use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use ed25519_dalek::Signature;
use howl::{
    enrollment::hosted::{Candidate, Network},
    identity::PeerCertificate,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::{Row, Transaction};
use zeroize::Zeroizing;

use crate::{
    ControlPlane, Error, Id, Result, account_network, credential_digest, id, network, proof,
    random, sessions, web_login,
};

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/v1/device-links", post(start))
        .route("/v1/device-links/{id}/poll", post(poll))
        .route("/v1/device-links/{id}/challenge", get(challenge))
        .route("/api/device-links/view", post(view))
        .route("/api/device-links/decide", post(decide))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    peer: String,
}

async fn start(
    State(control): State<Arc<ControlPlane>>,
    Json(input): Json<Start>,
) -> Result<Json<Value>> {
    let peer =
        PeerCertificate::from_bytes(proof::decode(&input.peer)?).map_err(|_| Error::Invalid)?;
    if *peer.device_id() == [0; 32] {
        return Err(Error::Invalid);
    }
    let origin = control.web_origin.as_deref().ok_or(Error::NotFound)?;
    let link = random()?;
    let nonce = random()?;
    let secret = Zeroizing::new(random()?);
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(1893514700642126)", &[])
        .await?;
    tx.execute(
        "DELETE FROM howl_control.device_links WHERE expires_at <= now()",
        &[],
    )
    .await?;
    tx.execute("DELETE FROM howl_control.device_link_requests WHERE expires_at<=now() AND decision IS DISTINCT FROM 'denied'", &[]).await?;
    let inserted = tx.execute(
        "INSERT INTO howl_control.device_links(id,secret_digest,peer,nonce,expires_at)
         SELECT $1,$2,$3,$4,now()+interval '10 minutes' WHERE (SELECT count(*) FROM howl_control.device_links) < 4096",
        &[&&link[..],&&proof::hash(&secret[..])[..],&&peer.as_bytes()[..],&&nonce[..]],
    ).await?;
    if inserted != 1 {
        return Err(Error::Wait);
    }
    tx.commit().await?;
    let secret = hex::encode(&secret[..]);
    Ok(Json(json!({
        "id": hex::encode(link),
        "secret": secret,
        "nonce": hex::encode(nonce),
        "expires_in": 600,
        "url": format!("{origin}/link#{secret}")
    })))
}

async fn challenge(
    State(control): State<Arc<ControlPlane>>,
    Path(link): Path<String>,
) -> Result<Json<Value>> {
    let link = proof::decode::<32>(&link)?;
    let row = control
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT nonce FROM howl_control.device_links WHERE id=$1 AND expires_at>now()",
            &[&&link[..]],
        )
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(json!({"nonce":hex::encode(id(&row,0)?)})))
}

fn stored_peer(row: &Row) -> Result<PeerCertificate> {
    let bytes = row
        .try_get::<_, &[u8]>("peer")?
        .try_into()
        .map_err(|_| Error::Internal)?;
    PeerCertificate::from_bytes(bytes).map_err(|_| Error::Internal)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserLink {
    secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Approve,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserDecision {
    secret: String,
    device: String,
    fingerprint: String,
    decision: Decision,
}

async fn view(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(input): Json<BrowserLink>,
) -> Result<Json<Value>> {
    web_login::same_origin(&control, &headers)?;
    let github = web_login::owner(&control, &headers).await?;
    let digest = credential_digest(&input.secret)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx.query_opt(
        "SELECT peer,github_id,channel,designation FROM howl_control.device_links WHERE secret_digest=$1
         AND (github_id IS NULL OR github_id=$2) AND expires_at>now() FOR UPDATE",
        &[&&digest[..],&github],
    ).await?.ok_or(Error::NotFound)?;
    let network = network::hosted(&tx, github).await?.ok_or(Error::Conflict)?;
    let snapshot = network
        .snapshot
        .filter(|_| network.signer.is_some())
        .ok_or(Error::Conflict)?;
    let designation = snapshot.pin().map_err(|_| Error::Internal)?.2;
    let peer = stored_peer(&row)?;
    if row.get::<_, Option<i64>>("github_id").is_none() {
        let existing = tx
            .query_opt(
                "SELECT candidate,denied FROM howl_control.network_requests
                WHERE github_id=$1 AND device_id=$2 AND (denied OR expires_at>now())",
                &[&github, &&peer.device_id()[..]],
            )
            .await?;
        let mut decision: Option<&str> = None;
        if let Some(existing) = existing {
            let candidate: Candidate =
                serde_json::from_value(existing.get(0)).map_err(|_| Error::Internal)?;
            if candidate
                .identity()
                .map_err(|_| Error::Internal)?
                .as_bytes()
                != peer.as_bytes()
            {
                return Err(Error::Conflict);
            }
            if existing.get::<_, bool>(1) {
                decision = Some("denied");
            }
        }
        for member in &snapshot.devices {
            let approved = member.identity().map_err(|_| Error::Internal)?;
            if approved.device_id() == peer.device_id() && approved.as_bytes() != peer.as_bytes() {
                return Err(Error::Conflict);
            }
        }
        let changed = tx.execute(
            "INSERT INTO howl_control.device_link_requests(github_id,device_id,peer,decision,expires_at)
            SELECT $1,$2,$3,$4,expires_at FROM howl_control.device_links WHERE secret_digest=$5
            ON CONFLICT(github_id,device_id) DO UPDATE SET expires_at=GREATEST(device_link_requests.expires_at,EXCLUDED.expires_at),
              decision=COALESCE(EXCLUDED.decision,device_link_requests.decision)
            WHERE device_link_requests.peer=EXCLUDED.peer",
            &[&github, &&peer.device_id()[..], &&peer.as_bytes()[..], &decision, &&digest[..]],
        ).await?;
        if changed != 1 {
            return Err(Error::Conflict);
        }
        tx.execute("UPDATE howl_control.device_links SET github_id=$2,channel=$3,designation=$4 WHERE secret_digest=$1",
            &[&&digest[..],&github,&&network.channel[..],&&designation[..]]).await?;
    } else {
        check_target(&row, &network.channel, &designation)?;
    }
    let decision = decision(&tx, github, &peer).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "device": hex::encode(peer.device_id()),
        "fingerprint": hex::encode(peer.fingerprint()),
        "network": hex::encode(network.channel),
        "state": decision.as_deref().unwrap_or("pending")
    })))
}

fn check_target(row: &Row, channel: &Id, designation: &Id) -> Result<()> {
    if row.get::<_, &[u8]>("channel") != channel
        || row.get::<_, &[u8]>("designation") != designation
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

async fn decide(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(input): Json<BrowserDecision>,
) -> Result<StatusCode> {
    web_login::same_origin(&control, &headers)?;
    let github = web_login::owner(&control, &headers).await?;
    let digest = credential_digest(&input.secret)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT peer,channel,designation FROM howl_control.device_links
         WHERE secret_digest=$1 AND github_id=$2 AND expires_at>now() FOR UPDATE",
            &[&&digest[..], &github],
        )
        .await?
        .ok_or(Error::NotFound)?;
    let peer = stored_peer(&row)?;
    if peer.device_id() != &proof::decode(&input.device)?
        || peer.fingerprint() != proof::decode(&input.fingerprint)?
    {
        return Err(Error::NotFound);
    }
    let network = network::hosted(&tx, github).await?.ok_or(Error::Conflict)?;
    let snapshot = network
        .snapshot
        .filter(|_| network.signer.is_some())
        .ok_or(Error::Conflict)?;
    check_target(
        &row,
        &network.channel,
        &snapshot.pin().map_err(|_| Error::Internal)?.2,
    )?;
    match input.decision {
        Decision::Approve => {
            account_network::approve_for(
                &control,
                &tx,
                github,
                *peer.device_id(),
                peer.fingerprint(),
            )
            .await?
        }
        Decision::Deny => {
            account_network::deny_for(&tx, github, *peer.device_id(), peer.fingerprint()).await?
        }
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    nonce: String,
    signature: String,
    candidate: Option<Candidate>,
}

async fn poll(
    State(control): State<Arc<ControlPlane>>,
    Path(link): Path<String>,
    Json(input): Json<Poll>,
) -> Result<Json<Value>> {
    let link = proof::decode::<32>(&link)?;
    let nonce = proof::decode::<32>(&input.nonce)?;
    let mut conn = control.pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx.query_opt(
        "SELECT nonce,peer,github_id,channel,designation,sealed_credentials FROM howl_control.device_links
         WHERE id=$1 AND expires_at>now() FOR UPDATE",&[&&link[..]],
    ).await?.ok_or(Error::NotFound)?;
    let peer = stored_peer(&row)?;
    if nonce != id(&row, 0)? {
        return Err(Error::Unauthorized);
    }
    let body = input
        .candidate
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| Error::Invalid)?
        .unwrap_or_default();
    let signed = proof::signing_bytes(control.audience, link, "device-link", nonce, [0; 32], &body);
    proof::key(peer.signing_public())?
        .verify_strict(
            &signed,
            &Signature::from_bytes(&proof::decode(&input.signature)?),
        )
        .map_err(|_| Error::Unauthorized)?;
    let nonce = random()?;
    tx.execute(
        "UPDATE howl_control.device_links SET nonce=$2 WHERE id=$1",
        &[&&link[..], &&nonce[..]],
    )
    .await?;
    let mut response = json!({"state":"waiting","nonce":hex::encode(nonce)});
    if let Some(github) = row.get::<_, Option<i64>>("github_id") {
        let network = network::hosted(&tx, github).await?.ok_or(Error::Conflict)?;
        let snapshot = network.snapshot.ok_or(Error::Conflict)?;
        let signer = network.signer.ok_or(Error::Conflict)?;
        check_target(
            &row,
            &network.channel,
            &snapshot.pin().map_err(|_| Error::Internal)?.2,
        )?;
        let decision = decision(&tx, github, &peer).await?;
        if decision.as_deref() == Some("denied") {
            tx.commit().await?;
            return Ok(Json(json!({"state":"denied"})));
        }
        if let Some(candidate) = &input.candidate {
            let signed_peer = candidate
                .verify(&snapshot.authority, &snapshot.designation)
                .map_err(|_| Error::Unauthorized)?;
            if signed_peer.as_bytes() != peer.as_bytes() {
                return Err(Error::Unauthorized);
            }
        }
        response["network"] = json!(hex::encode(network.channel));
        response["authority"] = json!(snapshot.authority);
        response["designation"] = json!(snapshot.designation);
        let context = [b"howl/device-link/credentials/v1".as_slice(), &link].concat();
        if let Some(sealed) = row.get::<_, Option<&[u8]>>("sealed_credentials") {
            let plain = control.open_sealed(&context, sealed)?;
            let credentials: Value = serde_json::from_slice(&plain).map_err(|_| Error::Internal)?;
            response = json!({"state":"approved","credentials":credentials});
        } else if decision.as_deref() == Some("approved")
            && let Some(candidate) = input.candidate
        {
            if needs_admission(&tx, github, &snapshot, &peer).await? {
                account_network::admit(
                    &control,
                    &tx,
                    github,
                    network.channel,
                    &snapshot,
                    &signer,
                    &candidate,
                )
                .await?;
            }
            let credentials =
                sessions::begin(&tx, github, *peer.device_id(), peer.signing_public()).await?;
            let plain =
                Zeroizing::new(serde_json::to_vec(&credentials).map_err(|_| Error::Internal)?);
            let sealed = control.seal(&context, &plain)?;
            tx.execute(
                "UPDATE howl_control.device_links SET sealed_credentials=$2 WHERE id=$1",
                &[&&link[..], &sealed],
            )
            .await?;
            response = json!({"state":"approved","credentials":credentials});
        }
    }
    tx.commit().await?;
    Ok(Json(response))
}

async fn needs_admission(
    tx: &Transaction<'_>,
    github: i64,
    snapshot: &Network,
    peer: &PeerCertificate,
) -> Result<bool> {
    for member in &snapshot.devices {
        let existing = member.identity().map_err(|_| Error::Internal)?;
        if existing.device_id() == peer.device_id() {
            if existing.as_bytes() != peer.as_bytes() {
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
    }
    if tx.query_opt("SELECT 1 FROM howl_control.network_requests WHERE github_id=$1 AND device_id=$2 AND denied",
        &[&github,&&peer.device_id()[..]]).await?.is_some() {
        return Err(Error::Conflict);
    }
    Ok(true)
}

async fn decision(
    tx: &Transaction<'_>,
    github: i64,
    peer: &PeerCertificate,
) -> Result<Option<String>> {
    let row = tx
        .query_opt(
            "SELECT decision FROM howl_control.device_link_requests
        WHERE github_id=$1 AND device_id=$2 AND peer=$3",
            &[&github, &&peer.device_id()[..], &&peer.as_bytes()[..]],
        )
        .await?
        .ok_or(Error::NotFound)?;
    Ok(row.get(0))
}

pub(crate) async fn denied(
    tx: &Transaction<'_>,
    github: i64,
    device: &Id,
) -> Result<Option<PeerCertificate>> {
    tx.query_opt("SELECT peer FROM howl_control.device_link_requests WHERE github_id=$1 AND device_id=$2 AND decision='denied'",
        &[&github,&&device[..]]).await?.as_ref().map(stored_peer).transpose()
}

pub(crate) async fn pending(tx: &Transaction<'_>, github: i64) -> Result<Vec<PeerCertificate>> {
    tx.query("SELECT peer FROM howl_control.device_link_requests WHERE github_id=$1 AND decision IS NULL AND expires_at>now() ORDER BY device_id",
        &[&github]).await?.iter().map(stored_peer).collect()
}

pub(crate) async fn queue_decision(
    tx: &Transaction<'_>,
    github: i64,
    device: Id,
    fingerprint: Id,
    decision: &str,
) -> Result<bool> {
    let Some(row) = tx
        .query_opt(
            "SELECT decision,peer FROM howl_control.device_link_requests
        WHERE github_id=$1 AND device_id=$2 AND (decision='denied' OR expires_at>now())",
            &[&github, &&device[..]],
        )
        .await?
    else {
        return Ok(false);
    };
    if stored_peer(&row)?.fingerprint() != fingerprint {
        return Err(Error::NotFound);
    }
    match row.get::<_, Option<&str>>(0) {
        Some(previous) if previous != decision => return Err(Error::Conflict),
        None => {
            tx.execute("UPDATE howl_control.device_link_requests SET decision=$3 WHERE github_id=$1 AND device_id=$2",
          &[&github,&&device[..],&decision]).await?;
        }
        _ => {}
    }
    Ok(true)
}
