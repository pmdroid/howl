use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

use crate::{Error, Result, random};

pub type Id = [u8; 32];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub nonce: String,
    pub signature: String,
}

pub fn signing_bytes(
    audience: Id,
    subject: Id,
    operation: &str,
    nonce: Id,
    token_digest: Id,
    body: &[u8],
) -> Vec<u8> {
    let mut bytes = b"howl/control-proof/v1\0".to_vec();
    bytes.extend(audience);
    bytes.extend(subject);
    bytes.extend(hash(operation.as_bytes()));
    bytes.extend(nonce);
    bytes.extend(token_digest);
    bytes.extend(hash(body));
    bytes
}

pub fn credential_digest(credential: &str) -> Result<Id> {
    Ok(hash(&decode::<32>(credential)?))
}

pub fn hash(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}

pub fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    let mut result = [0; N];
    hex::decode_to_slice(text, &mut result).map_err(|_| Error::Invalid)?;
    Ok(result)
}

pub fn key(key: Id) -> Result<VerifyingKey> {
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| Error::Invalid)?;
    if verifying.is_weak()
        || !CompressedEdwardsY(key)
            .decompress()
            .is_some_and(|point| point.compress().to_bytes() == key && point.is_torsion_free())
    {
        return Err(Error::Invalid);
    }
    Ok(verifying)
}

pub fn operation_name(operation: &str) -> Result<()> {
    if operation.is_empty()
        || operation.len() > 32
        || !operation
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c == b'-')
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub async fn issue(
    tx: &Transaction<'_>,
    subject: &Id,
    operation: &str,
    token_digest: &Id,
) -> Result<Id> {
    tx.execute(
        "DELETE FROM howl_control.proofs WHERE expires_at <= clock_timestamp()",
        &[],
    )
    .await?;
    let nonce = random()?;
    tx.execute(
        "INSERT INTO howl_control.proofs VALUES
         ($1, $2, $3, $4, clock_timestamp() + interval '60 seconds')",
        &[&&nonce[..], &&subject[..], &operation, &&token_digest[..]],
    )
    .await?;
    Ok(nonce)
}

pub struct Use<'a> {
    pub subject: Id,
    pub signing_key: Id,
    pub operation: &'a str,
    pub token_digest: Id,
    pub body: &'a [u8],
}

pub async fn consume(
    tx: &Transaction<'_>,
    audience: Id,
    proof: &Proof,
    action: Use<'_>,
) -> Result<()> {
    let nonce = decode(&proof.nonce)?;
    let signature = Signature::from_bytes(&decode(&proof.signature)?);
    let signed = signing_bytes(
        audience,
        action.subject,
        action.operation,
        nonce,
        action.token_digest,
        action.body,
    );
    key(action.signing_key)?
        .verify_strict(&signed, &signature)
        .map_err(|_| Error::Unauthorized)?;
    let consumed = tx
        .execute(
            "DELETE FROM howl_control.proofs WHERE nonce = $1 AND subject = $2
         AND operation = $3 AND token_digest = $4 AND expires_at > clock_timestamp()",
            &[
                &&nonce[..],
                &&action.subject[..],
                &action.operation,
                &&action.token_digest[..],
            ],
        )
        .await?;
    if consumed != 1 {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
