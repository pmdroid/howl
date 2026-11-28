use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use howl::{
    enrollment::hosted::{Candidate, Network},
    identity::PeerCertificate,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::Transaction;

use crate::{
    ControlPlane, Error, Id, PendingSession, Result, bearer, id, proof, random, request_proof,
};

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/v1/network", get(read))
        .route("/v1/network/devices", post(register))
        .route("/v1/network/deny", post(deny))
        .route(
            "/v1/network/approve",
            post(approve).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
}

pub(crate) async fn reserve(
    tx: &Transaction<'_>,
    github: i64,
    device: &Id,
    signing: &Id,
) -> Result<()> {
    tx.execute(
        "INSERT INTO howl_control.networks (github_id,channel,founder,founder_signing)
         SELECT $1,$2,$3,$4 WHERE NOT EXISTS
             (SELECT FROM howl_control.enrollment_pins WHERE github_id = $1)
         ON CONFLICT (github_id) DO NOTHING",
        &[&github, &&random()?[..], &&device[..], &&signing[..]],
    )
    .await?;
    Ok(())
}

#[derive(Serialize)]
struct View {
    state: &'static str,
    network: Option<String>,
    founder: Option<String>,
    snapshot: Option<Network>,
    authority: Vec<String>,
    designation: Option<String>,
    pending: Vec<Candidate>,
}

struct Hosted {
    channel: Id,
    founder: Id,
    founder_signing: Id,
    snapshot: Option<Network>,
}

async fn hosted(tx: &Transaction<'_>, github: i64) -> Result<Option<Hosted>> {
    let row = tx
        .query_opt(
            "SELECT n.channel,n.founder,n.founder_signing,n.snapshot FROM howl_control.networks n
         LEFT JOIN howl_control.enrollment_pins p ON p.github_id = n.github_id
         WHERE n.github_id = $1 AND
            (p.account_id,p.authority_head,p.designation_digest) IS NOT DISTINCT FROM
            (n.account_id,n.authority_head,n.designation_digest)
         FOR UPDATE OF n",
            &[&github],
        )
        .await?;
    row.map(|row| {
        Ok(Hosted {
            channel: id(&row, 0)?,
            founder: id(&row, 1)?,
            founder_signing: id(&row, 2)?,
            snapshot: row
                .get::<_, Option<Value>>(3)
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Internal)?,
        })
    })
    .transpose()
}

impl Hosted {
    fn is_founder(&self, session: &PendingSession) -> Result<bool> {
        if proof::decode::<32>(&session.device_id)? != self.founder {
            return Ok(false);
        }
        if proof::decode::<32>(&session.signing_key)? != self.founder_signing {
            return Err(Error::Unauthorized);
        }
        Ok(true)
    }
}

fn matches(session: &PendingSession, peer: &PeerCertificate) -> Result<bool> {
    Ok(*peer.device_id() == proof::decode(&session.device_id)?
        && peer.signing_public() == proof::decode(&session.signing_key)?)
}

async fn signed_network(
    control: &ControlPlane,
    tx: &Transaction<'_>,
    headers: &HeaderMap,
    operation: &str,
    body: &[u8],
) -> Result<(PendingSession, Option<Hosted>)> {
    let session = control
        .authorize_in(
            tx,
            operation,
            bearer(headers)?,
            &request_proof(headers)?,
            body,
        )
        .await?;
    let network = hosted(tx, session.github_id).await?;
    Ok((session, network))
}

async fn read(State(control): State<Arc<ControlPlane>>, headers: HeaderMap) -> Result<Json<View>> {
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let (session, network) = signed_network(&control, &tx, &headers, "network-read", &[]).await?;
    let mut view = View {
        state: "legacy",
        network: None,
        founder: None,
        snapshot: None,
        authority: Vec::new(),
        designation: None,
        pending: Vec::new(),
    };
    if let Some(network) = network {
        let founder = network.is_founder(&session)?;
        view.state = if founder { "founder" } else { "pending" };
        view.network = Some(hex::encode(network.channel));
        view.founder = Some(hex::encode(network.founder));
        if let Some(snapshot) = network.snapshot {
            view.authority = snapshot.authority.clone();
            view.designation = Some(snapshot.designation.clone());
            for device in &snapshot.devices {
                let peer = device.identity().map_err(|_| Error::Internal)?;
                if !founder && matches(&session, &peer)? {
                    view.state = "approved";
                }
            }
            if founder || view.state == "approved" {
                view.snapshot = Some(snapshot);
            }
        }
        if founder {
            view.pending = tx
                .query(
                    "SELECT candidate FROM howl_control.network_requests
                WHERE github_id = $1 AND NOT denied AND expires_at > clock_timestamp() ORDER BY device_id",
                    &[&session.github_id],
                )
                .await?
                .into_iter()
                .map(|r| serde_json::from_value(r.get(0)).map_err(|_| Error::Internal))
                .collect::<Result<_>>()?;
        } else if view.state == "pending" {
            let device: Id = proof::decode(&session.device_id)?;
            if let Some(row) = tx.query_opt(
                "SELECT candidate FROM howl_control.network_requests WHERE github_id = $1 AND device_id = $2 AND denied",
                &[&session.github_id, &&device[..]],
            ).await? {
                let candidate: Candidate = serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
                if !matches(&session, &candidate.identity().map_err(|_| Error::Internal)?)? {
                    return Err(Error::Unauthorized);
                }
                view.state = "denied";
                view.authority.clear();
                view.designation = None;
            }
        }
    }
    tx.commit().await?;
    Ok(Json(view))
}

async fn register(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let candidate: Candidate = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let (session, network) =
        signed_network(&control, &tx, &headers, "network-register", &body).await?;
    let network = network.ok_or(Error::Unauthorized)?;
    if network.is_founder(&session)? {
        return Err(Error::Unauthorized);
    }
    let snapshot = network.snapshot.ok_or(Error::Unauthorized)?;
    let peer = candidate
        .verify(&snapshot.authority, &snapshot.designation)
        .map_err(|_| Error::Invalid)?;
    if !matches(&session, &peer)? {
        return Err(Error::Unauthorized);
    }
    for device in &snapshot.devices {
        let approved = device.identity().map_err(|_| Error::Internal)?;
        if approved.device_id() == peer.device_id() {
            if approved.as_bytes() != peer.as_bytes() {
                return Err(Error::Unauthorized);
            }
            tx.commit().await?;
            return Ok(StatusCode::NO_CONTENT);
        }
    }
    let candidate = serde_json::to_value(candidate).map_err(|_| Error::Internal)?;
    tx.execute("DELETE FROM howl_control.network_requests WHERE github_id = $1 AND NOT denied AND expires_at <= clock_timestamp()", &[&session.github_id]).await?;
    if tx.execute("INSERT INTO howl_control.network_requests (github_id,device_id,candidate,expires_at)
         SELECT $1,$2,$3,clock_timestamp()+interval '1 day'
         WHERE (SELECT count(*) FROM howl_control.network_requests WHERE github_id = $1 AND NOT denied) < 64
            OR EXISTS (SELECT FROM howl_control.network_requests WHERE github_id = $1 AND device_id = $2)
         ON CONFLICT (github_id,device_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
         WHERE NOT network_requests.denied AND network_requests.candidate = EXCLUDED.candidate", &[&session.github_id, &&peer.device_id()[..], &candidate]).await? != 1 {
        return Err(Error::Unauthorized);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn approve(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let next: Network = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let (session, network) =
        signed_network(&control, &tx, &headers, "network-approve", &body).await?;
    let network = network.ok_or(Error::Unauthorized)?;
    if !network.is_founder(&session)? {
        return Err(Error::Unauthorized);
    }
    let device = next.devices.last().ok_or(Error::Invalid)?;
    let peer = device.identity().map_err(|_| Error::Invalid)?;
    if let Some(current) = &network.snapshot {
        if current == &next {
            tx.commit().await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        let row = tx
            .query_opt(
                "SELECT candidate FROM howl_control.network_requests
             WHERE github_id = $1 AND device_id = $2 AND NOT denied AND expires_at > clock_timestamp()",
                &[&session.github_id, &&peer.device_id()[..]],
            )
            .await?
            .ok_or(Error::Unauthorized)?;
        let candidate: Candidate =
            serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
        current
            .verify_successor(network.channel, &next, &candidate)
            .map_err(|_| Error::Unauthorized)?;
    } else {
        if next.devices.len() != 1 || !matches(&session, &peer)? {
            return Err(Error::Unauthorized);
        }
        next.verify(network.channel)
            .map_err(|_| Error::Unauthorized)?;
    }
    let (account, head, designation) = next.pin().map_err(|_| Error::Invalid)?;
    let snapshot = serde_json::to_value(&next).map_err(|_| Error::Internal)?;
    tx.execute("UPDATE howl_control.networks SET snapshot=$2,account_id=$3,authority_head=$4,designation_digest=$5
         WHERE github_id=$1", &[&session.github_id,&snapshot,&&account[..],&&head[..],&&designation[..]]).await?;
    if network.snapshot.is_none()
        && !tx
            .query_one(
                "SELECT howl_control.pin_new_network($1)",
                &[&session.github_id],
            )
            .await?
            .get::<_, bool>(0)
    {
        return Err(Error::Unauthorized);
    }
    let material = crate::enrollment::DeviceMaterial {
        authority: next.authority.clone(),
        designation: next.designation.clone(),
        certificate: device.certificate.clone(),
    };
    let pin = crate::EnrollmentPin {
        github_id: session.github_id,
        account_id: account,
        authority_head: head,
        designation_digest: designation,
    };
    let certificate = material.verify(&pin)?;
    if !certificate.matches(&peer) {
        return Err(Error::Unauthorized);
    }
    crate::enrollment::store(&tx, &pin, &certificate, &material).await?;
    tx.execute(
        "DELETE FROM howl_control.network_requests WHERE github_id=$1 AND device_id=$2",
        &[&session.github_id, &&peer.device_id()[..]],
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deny {
    device: String,
    fingerprint: String,
}

async fn deny(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let request: Deny = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let device: Id = proof::decode(&request.device)?;
    let fingerprint: Id = proof::decode(&request.fingerprint)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let (session, network) = signed_network(&control, &tx, &headers, "network-deny", &body).await?;
    if !network.ok_or(Error::Unauthorized)?.is_founder(&session)? {
        return Err(Error::Unauthorized);
    }
    let row = tx
        .query_opt(
            "SELECT candidate FROM howl_control.network_requests
         WHERE github_id = $1 AND device_id = $2 AND (denied OR expires_at > clock_timestamp())",
            &[&session.github_id, &&device[..]],
        )
        .await?
        .ok_or(Error::Unauthorized)?;
    let candidate: Candidate = serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
    let peer = candidate.identity().map_err(|_| Error::Internal)?;
    if peer.device_id() != &device || peer.fingerprint() != fingerprint {
        return Err(Error::Unauthorized);
    }
    tx.execute(
        "UPDATE howl_control.network_requests SET denied = true WHERE github_id = $1 AND device_id = $2 AND NOT denied",
        &[&session.github_id, &&device[..]],
    ).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
