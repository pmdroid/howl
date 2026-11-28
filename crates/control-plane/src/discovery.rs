use std::{collections::BTreeSet, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use howl::{
    discovery::{HINT_LEN, RouteHint, now},
    discovery_client::{MESH_STATUS_OPERATION, MESH_STATUS_PATH},
    identity::{CERTIFICATE_LEN, PeerCertificate},
    transport::{MAX_REPORTED_PATHS, PeerPath},
};

use crate::{ControlPlane, Error, Result, bearer, enrollment, proof, request_proof};

const WRITE: &str = "discovery-write";
const READ: &str = "discovery-read";
const PUBLISH_LEN: usize = CERTIFICATE_LEN + HINT_LEN;

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route(
            "/v1/discovery/hints",
            post(publish).layer(DefaultBodyLimit::max(PUBLISH_LEN)),
        )
        .route("/v1/discovery/hints/{device}", get(lookup))
        .route(
            MESH_STATUS_PATH,
            post(report_status).layer(DefaultBodyLimit::max(8192)),
        )
}

async fn report_status(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let reports: Vec<PeerPath> = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    if reports.len() > MAX_REPORTED_PATHS {
        return Err(Error::Invalid);
    }
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let device = control
        .authorize_enrolled_in(
            &tx,
            MESH_STATUS_OPERATION,
            bearer(&headers)?,
            &request_proof(&headers)?,
            &body,
        )
        .await?;
    let mut paths = BTreeSet::new();
    for mut report in reports {
        let peer = proof::decode::<32>(&report.device)?;
        if peer == device.device_id() {
            return Err(Error::Invalid);
        }
        report.device = hex::encode(peer);
        paths.insert(report);
    }
    let value = serde_json::to_value(paths).map_err(|_| Error::Internal)?;
    let updated = tx.execute(
        "INSERT INTO howl_control.mesh_status
         (account_id, device_id, device_sequence, authority_head, designation_digest, seen_at, paths)
         SELECT e.account_id,e.device_id,e.sequence,e.authority_head,e.designation_digest,clock_timestamp(),$6
         FROM howl_control.enrolled_devices e JOIN howl_control.enrollment_pins p ON p.account_id=e.account_id
            AND p.authority_head=e.authority_head AND p.designation_digest=e.designation_digest
         WHERE e.account_id=$1 AND e.device_id=$2 AND e.authority_head=$3 AND e.designation_digest=$4 AND e.signing_key=$5
         ON CONFLICT (account_id,device_id) DO UPDATE SET
            device_sequence=EXCLUDED.device_sequence, authority_head=EXCLUDED.authority_head,
            designation_digest=EXCLUDED.designation_digest, seen_at=EXCLUDED.seen_at, paths=EXCLUDED.paths
         WHERE mesh_status.seen_at <= EXCLUDED.seen_at",
        &[&&device.account_id()[..], &&device.device_id()[..], &&device.authority_head()[..],
          &&device.designation_digest()[..], &&device.signing_key()[..], &value],
    ).await?;
    tx.commit().await?;
    if updated == 1 {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(Error::Conflict)
    }
}

async fn publish(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    if body.len() != PUBLISH_LEN {
        return Err(Error::Invalid);
    }
    let (certificate, hint) = body.split_at(CERTIFICATE_LEN);
    let peer = PeerCertificate::from_bytes(certificate.try_into().map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    let route = RouteHint::from_bytes(hint.try_into().map_err(|_| Error::Invalid)?);
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let device = control
        .authorize_enrolled_in(
            &tx,
            WRITE,
            bearer(&headers)?,
            &request_proof(&headers)?,
            &body,
        )
        .await?;
    let sequence = enrollment::verify_peer_certificate(&tx, &device, &peer).await?;
    if route
        .address(&peer, now().map_err(|_| Error::Internal)?)
        .map_err(|_| Error::Invalid)?
        .is_none()
    {
        return Err(Error::Invalid);
    }
    let issued = i64::try_from(u64::from_be_bytes(*route.issued())).map_err(|_| Error::Invalid)?;
    let expires =
        i64::try_from(u64::from_be_bytes(*route.expires())).map_err(|_| Error::Invalid)?;
    let changed = tx.execute(
        "INSERT INTO howl_control.route_hints
         (account_id, device_id, device_sequence, authority_head, designation_digest,
          issued_millis, expires_millis, hint)
         SELECT d.account_id, d.device_id, d.sequence, d.authority_head, d.designation_digest,
             $6, $7, $8 FROM howl_control.enrolled_devices d
         JOIN howl_control.enrollment_pins p ON p.account_id = d.account_id
            AND p.authority_head = d.authority_head AND p.designation_digest = d.designation_digest
         WHERE d.account_id = $1 AND d.device_id = $2 AND d.sequence = $3
             AND d.authority_head = $4 AND d.designation_digest = $5
             AND $7::bigint > floor(extract(epoch FROM clock_timestamp()) * 1000)
         ON CONFLICT (account_id, device_id) DO UPDATE SET device_sequence = EXCLUDED.device_sequence,
             authority_head = EXCLUDED.authority_head, designation_digest = EXCLUDED.designation_digest,
             issued_millis = EXCLUDED.issued_millis, expires_millis = EXCLUDED.expires_millis,
             hint = EXCLUDED.hint
         WHERE EXCLUDED.expires_millis > floor(extract(epoch FROM clock_timestamp()) * 1000)
             AND (route_hints.device_sequence < EXCLUDED.device_sequence
              OR (route_hints.device_sequence = EXCLUDED.device_sequence
                  AND (route_hints.issued_millis < EXCLUDED.issued_millis
                    OR route_hints.hint = EXCLUDED.hint)))",
        &[&&device.account_id()[..], &&device.device_id()[..], &&sequence[..],
            &&device.authority_head()[..], &&device.designation_digest()[..], &issued, &expires, &hint],
    ).await?;
    tx.commit().await?;
    if changed != 1 {
        return Err(Error::Unauthorized);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn lookup(
    State(control): State<Arc<ControlPlane>>,
    Path(target): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let target = proof::decode::<32>(&target)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let requester = control
        .authorize_enrolled_in(
            &tx,
            READ,
            bearer(&headers)?,
            &request_proof(&headers)?,
            &target,
        )
        .await?;
    let row = tx.query_opt(
        "SELECT h.hint FROM howl_control.route_hints h
         JOIN howl_control.enrolled_devices d ON d.account_id = h.account_id AND d.device_id = h.device_id
            AND d.sequence = h.device_sequence AND d.authority_head = h.authority_head
            AND d.designation_digest = h.designation_digest
         JOIN howl_control.enrollment_pins p ON p.account_id = d.account_id
            AND p.authority_head = d.authority_head AND p.designation_digest = d.designation_digest
         JOIN howl_control.enrolled_devices r ON r.account_id = p.account_id AND r.device_id = $3
            AND r.authority_head = p.authority_head AND r.designation_digest = p.designation_digest
         WHERE h.account_id = $1 AND h.device_id = $2 AND r.signing_key = $4
            AND p.authority_head = $5 AND p.designation_digest = $6
            AND h.expires_millis > floor(extract(epoch FROM clock_timestamp()) * 1000)",
        &[&&requester.account_id()[..], &&target[..], &&requester.device_id()[..],
          &&requester.signing_key()[..], &&requester.authority_head()[..], &&requester.designation_digest()[..]],
    ).await?;
    tx.commit().await?;
    let hint: Vec<u8> = row.ok_or(Error::Unauthorized)?.get(0);
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], hint).into_response())
}
