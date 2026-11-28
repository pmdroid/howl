use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use ed25519_dalek::SigningKey;
use howl::{
    enrollment::hosted::{Candidate, Network},
    identity::PeerCertificate,
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Transaction;
use zeroize::Zeroizing;

use crate::{ControlPlane, Error, Id, Result, network, proof, random, web_login};

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/api/devices", get(devices))
        .route("/api/devices/approve", post(approve))
        .route("/api/devices/deny", post(deny))
        .route("/v1/network/transfer", post(transfer))
}

fn signer_context(github: i64, channel: &Id) -> Vec<u8> {
    [
        b"howl/account-network/signer/v1".as_slice(),
        &github.to_be_bytes(),
        channel,
    ]
    .concat()
}

fn fresh_signer() -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&Zeroizing::new(random()?)))
}

pub(crate) async fn ensure(
    control: &ControlPlane,
    tx: &Transaction<'_>,
    github: i64,
) -> Result<()> {
    if tx
        .query_opt(
            "SELECT 1 FROM howl_control.networks WHERE github_id=$1
         UNION ALL SELECT 1 FROM howl_control.enrollment_pins WHERE github_id=$1 LIMIT 1",
            &[&github],
        )
        .await?
        .is_some()
    {
        return Ok(());
    }
    let channel = random()?;
    let signer = fresh_signer()?;
    let snapshot = Network::account_owned(&fresh_signer()?, &fresh_signer()?, &signer)
        .map_err(|_| Error::Internal)?;
    let (account, head, designation) = snapshot.pin().map_err(|_| Error::Internal)?;
    let sealed = control.seal(&signer_context(github, &channel), signer.as_bytes())?;
    let inserted = tx.execute(
        "INSERT INTO howl_control.networks
          (github_id,channel,founder,founder_signing,snapshot,account_id,authority_head,designation_digest,account_signer)
         VALUES ($1,$2,$3,$4,$5,$3,$6,$7,$8)
         ON CONFLICT (github_id) DO NOTHING",
        &[&github, &&channel[..], &&account[..], &&signer.verifying_key().as_bytes()[..],
          &serde_json::to_value(snapshot).map_err(|_| Error::Internal)?, &&head[..], &&designation[..], &sealed],
    ).await?;
    if inserted == 1
        && !tx
            .query_one("SELECT howl_control.pin_new_network($1)", &[&github])
            .await?
            .get::<_, bool>(0)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Serialize)]
struct Device {
    id: String,
    fingerprint: String,
}

impl From<PeerCertificate> for Device {
    fn from(peer: PeerCertificate) -> Self {
        Self {
            id: hex::encode(peer.device_id()),
            fingerprint: hex::encode(peer.fingerprint()),
        }
    }
}

#[derive(Serialize, Default)]
struct Devices {
    network: Option<String>,
    account_managed: bool,
    pending: Vec<Device>,
    approved: Vec<Device>,
}

async fn devices(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Result<Json<Devices>> {
    let github = web_login::owner(&control, &headers).await?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let mut devices = Devices::default();
    if let Some(network) = network::hosted(&tx, github).await? {
        devices.network = Some(hex::encode(network.channel));
        devices.account_managed = network.signer.is_some();
        if let Some(snapshot) = network.snapshot {
            for candidate in network::pending(&tx, github).await? {
                let peer = candidate
                    .verify(&snapshot.authority, &snapshot.designation)
                    .map_err(|_| Error::Internal)?;
                devices.pending.push(peer.into());
            }
            for peer in crate::link::pending(&tx, github).await? {
                let linked = Device::from(peer);
                if !devices.pending.iter().any(|entry| entry.id == linked.id) {
                    devices.pending.push(linked);
                }
            }
            for member in snapshot.devices {
                devices
                    .approved
                    .push(member.identity().map_err(|_| Error::Internal)?.into());
            }
        }
    }
    tx.commit().await?;
    Ok(Json(devices))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    device: String,
    fingerprint: String,
}

async fn approve(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(request): Json<Decision>,
) -> Result<StatusCode> {
    web_login::same_origin(&control, &headers)?;
    let github = web_login::owner(&control, &headers).await?;
    let device = proof::decode::<32>(&request.device)?;
    let fingerprint = proof::decode::<32>(&request.fingerprint)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    approve_for(&control, &tx, github, device, fingerprint).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn approve_for(
    control: &ControlPlane,
    tx: &Transaction<'_>,
    github: i64,
    device: Id,
    fingerprint: Id,
) -> Result<()> {
    let network = network::hosted(tx, github).await?.ok_or(Error::Conflict)?;
    let sealed = network.signer.ok_or(Error::Conflict)?;
    let snapshot = network.snapshot.ok_or(Error::Internal)?;
    let linked = crate::link::queue_decision(tx, github, device, fingerprint, "approved").await?;
    for member in &snapshot.devices {
        let peer = member.identity().map_err(|_| Error::Internal)?;
        if peer.device_id() == &device {
            if peer.fingerprint() != fingerprint {
                return Err(Error::NotFound);
            }
            return Ok(());
        }
    }
    let row = tx.query_opt(
        "SELECT candidate FROM howl_control.network_requests WHERE github_id=$1 AND device_id=$2
         AND NOT denied AND expires_at > clock_timestamp()",
        &[&github, &&device[..]]
    ).await?;
    let Some(row) = row else {
        return if linked { Ok(()) } else { Err(Error::NotFound) };
    };
    let candidate: Candidate = serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
    let peer = candidate
        .verify(&snapshot.authority, &snapshot.designation)
        .map_err(|_| Error::Internal)?;
    if peer.device_id() != &device || peer.fingerprint() != fingerprint {
        return Err(Error::NotFound);
    }
    admit(
        control,
        tx,
        github,
        network.channel,
        &snapshot,
        &sealed,
        &candidate,
    )
    .await?;
    Ok(())
}

pub(crate) async fn admit(
    control: &ControlPlane,
    tx: &Transaction<'_>,
    github: i64,
    channel: Id,
    snapshot: &Network,
    sealed: &[u8],
    candidate: &Candidate,
) -> Result<()> {
    let secret = control.open_sealed(&signer_context(github, &channel), sealed)?;
    let signer = SigningKey::from_bytes(secret.as_slice().try_into().map_err(|_| Error::Internal)?);
    let next = snapshot
        .admit(channel, &signer, candidate)
        .map_err(|_| Error::Conflict)?;
    network::commit_member(tx, github, &next, false).await?;
    Ok(())
}

async fn deny(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(request): Json<Decision>,
) -> Result<StatusCode> {
    web_login::same_origin(&control, &headers)?;
    let github = web_login::owner(&control, &headers).await?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    deny_for(
        &tx,
        github,
        proof::decode(&request.device)?,
        proof::decode(&request.fingerprint)?,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn deny_for(
    tx: &Transaction<'_>,
    github: i64,
    device: Id,
    fingerprint: Id,
) -> Result<()> {
    if network::hosted(tx, github)
        .await?
        .and_then(|n| n.signer)
        .is_none()
    {
        return Err(Error::Conflict);
    }
    let linked = crate::link::queue_decision(tx, github, device, fingerprint, "denied").await?;
    match network::deny_device(tx, github, device, fingerprint).await {
        Err(Error::NotFound) if linked => Ok(()),
        result => result,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer<'a> {
    signer: &'a str,
}

async fn transfer(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    if control.web_origin.is_none() {
        return Err(Error::NotFound);
    }
    let request: Transfer<'_> = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let (session, network) =
        network::signed_network(&control, &tx, &headers, "network-transfer", &body).await?;
    let network = network.ok_or(Error::Unauthorized)?;
    if !network.founder_identity(&session)? {
        return Err(Error::Unauthorized);
    }
    let snapshot = network.snapshot.ok_or(Error::Conflict)?;
    let secret = Zeroizing::new(proof::decode(request.signer)?);
    let signer = SigningKey::from_bytes(&secret);
    if signer.verifying_key().to_bytes() != snapshot.signer().map_err(|_| Error::Internal)? {
        return Err(Error::Unauthorized);
    }
    if network.signer.is_none() {
        let (account, head, designation) = snapshot.pin().map_err(|_| Error::Internal)?;
        if tx
            .query_opt(
                "SELECT 1 FROM howl_control.enrolled_devices d
             WHERE d.account_id=$1 AND d.authority_head=$2 AND d.designation_digest=$3
             AND NOT EXISTS (SELECT FROM jsonb_array_elements($4::jsonb) m
                 WHERE m->>'certificate'=d.records->>'certificate') LIMIT 1",
                &[
                    &&account[..],
                    &&head[..],
                    &&designation[..],
                    &serde_json::to_value(&snapshot.devices).map_err(|_| Error::Internal)?,
                ],
            )
            .await?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let sealed = control.seal(
            &signer_context(session.github_id, &network.channel),
            &*secret,
        )?;
        tx.execute(
            "UPDATE howl_control.networks SET account_signer=$2 WHERE github_id=$1",
            &[&session.github_id, &sealed],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
