use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use howl::{
    discovery::{RouteHint, now},
    enrollment::hosted::Candidate,
    identity::PeerCertificate,
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Transaction;

use crate::{ControlPlane, Error, Id, Result, network, proof, web_login};

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/api/devices/{device}", get(read))
        .route("/api/devices/{device}/name", post(rename))
}

pub(crate) fn default_name(id: &Id) -> String {
    format!("Device {}", hex::encode(&id[..6]))
}

pub(crate) fn name(value: &str) -> Result<&str> {
    howl::control_client::device_name(value).map_err(|_| Error::Invalid)
}

pub(crate) async fn claimed(
    tx: &Transaction<'_>,
    github: i64,
    peer: &PeerCertificate,
    suggested: Option<&str>,
) -> Result<String> {
    let row = tx.query_opt(
        "INSERT INTO howl_control.device_details (github_id, device_id, fingerprint, name)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (github_id,device_id) DO UPDATE SET name=COALESCE(device_details.name,EXCLUDED.name)
         WHERE device_details.fingerprint=EXCLUDED.fingerprint RETURNING name",
        &[&github, &&peer.device_id()[..], &&peer.fingerprint()[..], &suggested],
    ).await?.ok_or(Error::Conflict)?;
    Ok(row
        .get::<_, Option<String>>(0)
        .unwrap_or_else(|| default_name(peer.device_id())))
}

pub(crate) async fn admitted(
    tx: &Transaction<'_>,
    github: i64,
    peer: &PeerCertificate,
) -> Result<()> {
    let changed = tx.execute(
        "INSERT INTO howl_control.device_details (github_id,device_id,fingerprint,requested_at,approved_at)
         SELECT $1,$2,$3,LEAST(n.requested_at,l.requested_at),COALESCE(l.approved_at,clock_timestamp())
         FROM (VALUES (1)) AS anchor(x)
         LEFT JOIN howl_control.network_requests n ON n.github_id=$1 AND n.device_id=$2
         LEFT JOIN howl_control.device_link_requests l ON l.github_id=$1 AND l.device_id=$2 AND l.peer=$4
         ON CONFLICT (github_id,device_id) DO UPDATE SET
            requested_at=COALESCE(device_details.requested_at,EXCLUDED.requested_at),
            approved_at=COALESCE(device_details.approved_at,EXCLUDED.approved_at)
         WHERE device_details.fingerprint=EXCLUDED.fingerprint",
        &[&github, &&peer.device_id()[..], &&peer.fingerprint()[..], &&peer.as_bytes()[..]],
    ).await?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Serialize)]
struct Details {
    id: String,
    fingerprint: String,
    name: String,
    state: &'static str,
    network_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_name: Option<String>,
    endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_route_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<Route>,
}

#[derive(Serialize)]
struct Route {
    ip: String,
    port: u16,
    expires_at: String,
}

async fn details(tx: &Transaction<'_>, github: i64, device: &Id) -> Result<Details> {
    let network = network::hosted(tx, github).await?.ok_or(Error::NotFound)?;
    let snapshot = network.snapshot.ok_or(Error::NotFound)?;
    let mut member = None;
    for entry in &snapshot.devices {
        let peer = entry.identity().map_err(|_| Error::Internal)?;
        if peer.device_id() == device {
            member = Some(peer);
            break;
        }
    }
    let admitted = member.is_some();
    let (peer, state) = if let Some(member) = member {
        (member, "approved")
    } else if let Some(row) = tx
        .query_opt(
            "SELECT peer,decision FROM howl_control.device_link_requests
         WHERE github_id=$1 AND device_id=$2 AND (decision='denied' OR expires_at>now())",
            &[&github, &&device[..]],
        )
        .await?
    {
        let bytes = row
            .try_get::<_, &[u8]>(0)?
            .try_into()
            .map_err(|_| Error::Internal)?;
        let peer = PeerCertificate::from_bytes(bytes).map_err(|_| Error::Internal)?;
        let state = match row.get::<_, Option<&str>>(1) {
            Some("denied") => "denied",
            Some("approved") => "approved",
            None => "pending",
            _ => return Err(Error::Internal),
        };
        (peer, state)
    } else {
        let row = tx
            .query_opt(
                "SELECT candidate,denied FROM howl_control.network_requests
             WHERE github_id=$1 AND device_id=$2 AND (denied OR expires_at>now())",
                &[&github, &&device[..]],
            )
            .await?
            .ok_or(Error::NotFound)?;
        let candidate: Candidate =
            serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
        let peer = candidate
            .verify(&snapshot.authority, &snapshot.designation)
            .map_err(|_| Error::Internal)?;
        let state = if row.get::<_, bool>(1) {
            "denied"
        } else {
            "pending"
        };
        (peer, state)
    };
    if peer.device_id() != device {
        return Err(Error::Conflict);
    }
    let (account, head, designation) = snapshot.pin().map_err(|_| Error::Internal)?;
    let row = tx.query_one(
        "SELECT d.name, d.fingerprint,
         to_char(COALESCE(d.requested_at,CASE WHEN NOT $8 THEN LEAST(l.requested_at,n.requested_at) END) AT TIME ZONE 'UTC',
                 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
         to_char(COALESCE(d.approved_at,CASE WHEN NOT $8 THEN l.approved_at END) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
         to_char(to_timestamp(h.issued_millis / 1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
         h.hint,
         to_char(to_timestamp(h.expires_millis / 1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
         FROM (VALUES (1)) AS anchor(x)
         LEFT JOIN howl_control.device_details d ON d.github_id=$1 AND d.device_id=$2
         LEFT JOIN howl_control.device_link_requests l ON l.github_id=$1 AND l.device_id=$2 AND l.peer=$3
         LEFT JOIN howl_control.network_requests n ON n.github_id=$1 AND n.device_id=$2
         LEFT JOIN howl_control.enrolled_devices e ON $8 AND e.account_id=$4 AND e.device_id=$2
             AND e.authority_head=$5 AND e.designation_digest=$6 AND e.signing_key=$7
         LEFT JOIN howl_control.route_hints h ON h.account_id=e.account_id AND h.device_id=e.device_id
             AND h.authority_head=e.authority_head AND h.designation_digest=e.designation_digest AND h.device_sequence=e.sequence",
        &[&github, &&device[..], &&peer.as_bytes()[..], &&account[..], &&head[..], &&designation[..], &&peer.signing_public()[..], &admitted],
    ).await?;
    if row
        .get::<_, Option<&[u8]>>(1)
        .is_some_and(|stored| stored != peer.fingerprint())
    {
        return Err(Error::Conflict);
    }
    let route = if let Some(bytes) = row.get::<_, Option<&[u8]>>(5) {
        let hint = RouteHint::from_bytes(bytes.try_into().map_err(|_| Error::Internal)?);
        hint.address(&peer, now().map_err(|_| Error::Internal)?)
            .map_err(|_| Error::Internal)?
            .map(|address| Route {
                ip: address.ip().to_string(),
                port: address.port(),
                expires_at: row.get(6),
            })
    } else {
        None
    };
    Ok(Details {
        id: hex::encode(device),
        fingerprint: hex::encode(peer.fingerprint()),
        name: row
            .get::<_, Option<String>>(0)
            .unwrap_or_else(|| default_name(device)),
        state,
        network_id: hex::encode(network.channel),
        network_name: network.github_login,
        endpoint_id: peer.endpoint().to_string(),
        requested_at: row.get(2),
        approved_at: row.get(3),
        last_route_at: row.get(4),
        route,
    })
}

async fn read(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Result<Json<Details>> {
    let github = web_login::owner(&control, &headers).await?;
    let device = proof::decode::<32>(&device)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let result = details(&tx, github, &device).await?;
    tx.commit().await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rename {
    fingerprint: String,
    name: String,
}

async fn rename(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(request): Json<Rename>,
) -> Result<Json<Details>> {
    web_login::same_origin(&control, &headers)?;
    let github = web_login::owner(&control, &headers).await?;
    let device = proof::decode::<32>(&device)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let mut result = details(&tx, github, &device).await?;
    let expected = proof::decode::<32>(&request.fingerprint)?;
    if hex::encode(expected) != result.fingerprint {
        return Err(Error::NotFound);
    }
    let label = name(&request.name)?;
    let count = tx.execute(
        "INSERT INTO howl_control.device_details(github_id,device_id,fingerprint,name) VALUES ($1,$2,$3,$4)
         ON CONFLICT(github_id,device_id) DO UPDATE SET name=EXCLUDED.name
         WHERE device_details.fingerprint=EXCLUDED.fingerprint",
        &[&github, &&device[..], &&expected[..], &label],
    ).await?;
    if count != 1 {
        return Err(Error::Conflict);
    }
    result.name = label.to_owned();
    tx.commit().await?;
    Ok(Json(result))
}
