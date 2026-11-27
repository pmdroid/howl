use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use howl::{
    enrollment::{Authority, AuthorityRecord, Designation, DeviceCertificate},
    identity::PeerCertificate,
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Transaction;

use crate::{
    ControlPlane, Error, Id, PendingSession, Proof, Result, bearer, id, proof, request_proof,
};

const ENROLL: &str = "enrollment";
const READ: &str = "enrollment-read";

pub struct EnrollmentPin {
    pub github_id: i64,
    pub account_id: Id,
    pub authority_head: Id,
    pub designation_digest: Id,
}

pub struct TrustedDevice {
    account_id: Id,
    device_id: Id,
    signing_key: Id,
    authority_head: Id,
    designation_digest: Id,
}

impl TrustedDevice {
    pub fn account_id(&self) -> Id {
        self.account_id
    }

    pub fn device_id(&self) -> Id {
        self.device_id
    }

    pub fn signing_key(&self) -> Id {
        self.signing_key
    }

    pub fn authority_head(&self) -> Id {
        self.authority_head
    }

    pub fn designation_digest(&self) -> Id {
        self.designation_digest
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceMaterial {
    authority: Vec<String>,
    designation: String,
    certificate: String,
}

pub async fn pin_enrollment(pool: &Pool, pin: EnrollmentPin) -> Result<()> {
    if pin.github_id <= 0
        || [pin.account_id, pin.authority_head, pin.designation_digest].contains(&[0; 32])
    {
        return Err(Error::Invalid);
    }
    let result = pool
        .get()
        .await?
        .execute(
            "INSERT INTO howl_control.enrollment_pins VALUES ($1,$2,$3,$4)
         ON CONFLICT (github_id) DO UPDATE SET authority_head = EXCLUDED.authority_head,
             designation_digest = EXCLUDED.designation_digest
         WHERE enrollment_pins.account_id = EXCLUDED.account_id",
            &[
                &pin.github_id,
                &&pin.account_id[..],
                &&pin.authority_head[..],
                &&pin.designation_digest[..],
            ],
        )
        .await?;
    if result == 1 {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

impl ControlPlane {
    pub async fn authorize_enrolled(
        &self,
        operation: &str,
        credential: &str,
        proof: &Proof,
        body: &[u8],
    ) -> Result<TrustedDevice> {
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let device = self
            .authorize_enrolled_in(&tx, operation, credential, proof, body)
            .await?;
        tx.commit().await?;
        Ok(device)
    }

    pub async fn authorize_enrolled_in(
        &self,
        tx: &Transaction<'_>,
        operation: &str,
        credential: &str,
        proof: &Proof,
        body: &[u8],
    ) -> Result<TrustedDevice> {
        let session = self
            .authorize_in(tx, operation, credential, proof, body)
            .await?;
        enrolled(tx, &session).await
    }
}

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route(
            "/v1/enrollment/device",
            post(upload).layer(DefaultBodyLimit::max(512 * 1024)),
        )
        .route("/v1/enrollment/device/{device}", get(download))
}

async fn upload(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let mut material: DeviceMaterial = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let session = control
        .authorize_in(
            &tx,
            ENROLL,
            bearer(&headers)?,
            &request_proof(&headers)?,
            &body,
        )
        .await?;
    let pin = active_pin(&tx, session.github_id).await?;
    let certificate = material.verify(&pin)?;
    let device = proof::decode(&session.device_id)?;
    let signing = proof::decode(&session.signing_key)?;
    if certificate.device != device || certificate.signing != signing {
        return Err(Error::Unauthorized);
    }
    for record in &mut material.authority {
        record.make_ascii_lowercase();
    }
    material.designation.make_ascii_lowercase();
    material.certificate.make_ascii_lowercase();
    let material = serde_json::to_value(material).map_err(|_| Error::Internal)?;
    let sequence = certificate.sequence.to_be_bytes();
    let changed = tx.execute(
        "INSERT INTO howl_control.enrolled_devices
         (account_id, device_id, signing_key, authority_head, designation_digest, sequence, records)
         SELECT account_id, $2, $3, authority_head, designation_digest, $6, $7
         FROM howl_control.enrollment_pins WHERE github_id = $1 AND authority_head = $4
              AND designation_digest = $5
         ON CONFLICT (account_id, device_id) DO UPDATE SET signing_key = EXCLUDED.signing_key,
           authority_head = EXCLUDED.authority_head, designation_digest = EXCLUDED.designation_digest,
           sequence = EXCLUDED.sequence, records = EXCLUDED.records
         WHERE enrolled_devices.sequence < EXCLUDED.sequence
            OR (enrolled_devices.sequence = EXCLUDED.sequence AND enrolled_devices.records = EXCLUDED.records)",
        &[&pin.github_id, &&device[..], &&signing[..], &&pin.authority_head[..],
            &&pin.designation_digest[..], &&sequence[..], &material],
    ).await?;
    if changed != 1 {
        return Err(Error::Unauthorized);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn download(
    State(control): State<Arc<ControlPlane>>,
    Path(device): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let device = proof::decode::<32>(&device)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let session = control
        .authorize_in(
            &tx,
            READ,
            bearer(&headers)?,
            &request_proof(&headers)?,
            &device,
        )
        .await?;
    let source = enrolled(&tx, &session).await?;
    let row = tx
        .query_opt(
            "SELECT d.records FROM howl_control.enrolled_devices d
         JOIN howl_control.enrollment_pins p ON p.account_id = d.account_id
            AND p.authority_head = d.authority_head AND p.designation_digest = d.designation_digest
         WHERE d.account_id = $1 AND d.device_id = $2",
            &[&&source.account_id[..], &&device[..]],
        )
        .await?;
    tx.commit().await?;
    Ok(Json(row.ok_or(Error::Unauthorized)?.get(0)))
}

async fn active_pin(tx: &Transaction<'_>, github_id: i64) -> Result<EnrollmentPin> {
    let row = tx
        .query_opt(
            "SELECT account_id, authority_head, designation_digest
         FROM howl_control.enrollment_pins WHERE github_id = $1",
            &[&github_id],
        )
        .await?
        .ok_or(Error::Unauthorized)?;
    Ok(EnrollmentPin {
        github_id,
        account_id: id(&row, 0)?,
        authority_head: id(&row, 1)?,
        designation_digest: id(&row, 2)?,
    })
}

async fn enrolled(tx: &Transaction<'_>, session: &PendingSession) -> Result<TrustedDevice> {
    let device_id = proof::decode::<32>(&session.device_id)?;
    let signing_key = proof::decode::<32>(&session.signing_key)?;
    let row = tx
        .query_opt(
            "SELECT d.account_id, d.authority_head, d.designation_digest FROM howl_control.enrolled_devices d
         JOIN howl_control.enrollment_pins p ON p.account_id = d.account_id
            AND p.authority_head = d.authority_head AND p.designation_digest = d.designation_digest
         WHERE p.github_id = $1 AND d.device_id = $2 AND d.signing_key = $3",
            &[&session.github_id, &&device_id[..], &&signing_key[..]],
        )
        .await?
        .ok_or(Error::Unauthorized)?;
    Ok(TrustedDevice {
        account_id: id(&row, 0)?,
        device_id,
        signing_key,
        authority_head: id(&row, 1)?,
        designation_digest: id(&row, 2)?,
    })
}

impl DeviceMaterial {
    fn verify(&self, pin: &EnrollmentPin) -> Result<DeviceCertificate> {
        if self.authority.is_empty() || self.authority.len() > 4096 {
            return Err(Error::Invalid);
        }
        let records = self
            .authority
            .iter()
            .map(|record| {
                let bytes = hex::decode(record).map_err(|_| Error::Invalid)?;
                AuthorityRecord::from_bytes(&bytes).map_err(|_| Error::Invalid)
            })
            .collect::<Result<Vec<_>>>()?;
        let head = Authority::import(records, pin.account_id, pin.authority_head)
            .and_then(|authority| authority.head())
            .map_err(|_| Error::Unauthorized)?;
        let designation = Designation::verify(
            &hex::decode(&self.designation).map_err(|_| Error::Invalid)?,
            head,
        )
        .map_err(|_| Error::Unauthorized)?;
        if designation.digest() != pin.designation_digest {
            return Err(Error::Unauthorized);
        }
        DeviceCertificate::verify(
            &hex::decode(&self.certificate).map_err(|_| Error::Invalid)?,
            &designation,
        )
        .map_err(|_| Error::Unauthorized)
    }
}

pub(crate) async fn verify_peer_certificate(
    tx: &Transaction<'_>,
    device: &TrustedDevice,
    peer: &PeerCertificate,
) -> Result<[u8; 8]> {
    let row = tx
        .query_opt(
            "SELECT d.records, p.github_id FROM howl_control.enrolled_devices d
         JOIN howl_control.enrollment_pins p ON p.account_id = d.account_id
            AND p.authority_head = d.authority_head AND p.designation_digest = d.designation_digest
         WHERE d.account_id = $1 AND d.device_id = $2 AND d.signing_key = $3
            AND p.authority_head = $4 AND p.designation_digest = $5",
            &[
                &&device.account_id[..],
                &&device.device_id[..],
                &&device.signing_key[..],
                &&device.authority_head[..],
                &&device.designation_digest[..],
            ],
        )
        .await?
        .ok_or(Error::Unauthorized)?;
    let material: DeviceMaterial =
        serde_json::from_value(row.get(0)).map_err(|_| Error::Internal)?;
    let pin = EnrollmentPin {
        github_id: row.get(1),
        account_id: device.account_id,
        authority_head: device.authority_head,
        designation_digest: device.designation_digest,
    };
    let certificate = material.verify(&pin)?;
    if !certificate.matches(peer) {
        return Err(Error::Unauthorized);
    }
    Ok(certificate.sequence.to_be_bytes())
}
