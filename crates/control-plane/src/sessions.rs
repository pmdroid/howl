use serde::Serialize;
use tokio_postgres::{Row, Transaction};
use zeroize::Zeroize;

use crate::{
    ControlPlane, Error, Result, id,
    proof::{self, Id, Proof},
    random,
};

#[derive(Serialize)]
pub struct PendingSession {
    pub id: String,
    pub github_id: i64,
    pub device_id: String,
    pub signing_key: String,
}

#[derive(Serialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u32,
    pub session: PendingSession,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

pub(crate) struct Session {
    id: Id,
    github_id: i64,
    device_id: Id,
    signing_key: Id,
}

impl Session {
    fn public(&self) -> PendingSession {
        PendingSession {
            id: hex::encode(self.id),
            github_id: self.github_id,
            device_id: hex::encode(self.device_id),
            signing_key: hex::encode(self.signing_key),
        }
    }
}

impl ControlPlane {
    pub async fn authorize(
        &self,
        operation: &str,
        credential: &str,
        proof: &Proof,
        body: &[u8],
    ) -> Result<PendingSession> {
        proof::operation_name(operation)?;
        if matches!(operation, "poll" | "refresh" | "revoke") {
            return Err(Error::Invalid);
        }
        let digest = proof::credential_digest(credential)?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let (session, _) = session(&tx, &digest, false).await?;
        self.prove(&tx, proof, &session, operation, digest, body)
            .await?;
        tx.commit().await?;
        Ok(session.public())
    }

    pub(crate) async fn session_challenge(&self, operation: &str, credential: &str) -> Result<Id> {
        proof::operation_name(operation)?;
        if operation == "poll" {
            return Err(Error::Invalid);
        }
        let digest = proof::credential_digest(credential)?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let refresh = matches!(operation, "refresh" | "revoke");
        let (session, _) = session(&tx, &digest, refresh).await?;
        let nonce = proof::issue(&tx, &session.id, operation, &digest).await?;
        tx.commit().await?;
        Ok(nonce)
    }

    pub(crate) async fn refresh(&self, token: &str, proof: &Proof) -> Result<Credentials> {
        let digest = proof::credential_digest(token)?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let (session, spent) = session(&tx, &digest, true).await?;
        self.prove(&tx, proof, &session, "refresh", digest, b"")
            .await?;
        if spent {
            revoke(&tx, &session).await?;
            tx.commit().await?;
            return Err(Error::Unauthorized);
        }
        tx.execute(
            "UPDATE howl_control.tokens SET spent = true WHERE digest = $1",
            &[&&digest[..]],
        )
        .await?;
        let tokens = issue(&tx, &session).await?;
        tx.commit().await?;
        Ok(tokens)
    }

    pub(crate) async fn revoke(&self, token: &str, proof: &Proof) -> Result<()> {
        let digest = proof::credential_digest(token)?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let (session, _) = session(&tx, &digest, true).await?;
        self.prove(&tx, proof, &session, "revoke", digest, b"")
            .await?;
        revoke(&tx, &session).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn prove(
        &self,
        tx: &Transaction<'_>,
        proof: &Proof,
        session: &Session,
        operation: &str,
        token_digest: Id,
        body: &[u8],
    ) -> Result<()> {
        proof::consume(
            tx,
            self.audience,
            proof,
            proof::Use {
                subject: session.id,
                signing_key: session.signing_key,
                operation,
                token_digest,
                body,
            },
        )
        .await
    }
}

pub(crate) async fn begin(
    tx: &Transaction<'_>,
    github_id: i64,
    device_id: Id,
    signing_key: Id,
) -> Result<Credentials> {
    tx.execute(
        "DELETE FROM howl_control.pending_sessions WHERE expires_at <= clock_timestamp()",
        &[],
    )
    .await?;
    let session = Session {
        id: random()?,
        github_id,
        device_id,
        signing_key,
    };
    tx.execute("INSERT INTO howl_control.pending_sessions (id, github_id, device_id, signing_key, expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp() + interval '30 days')",
        &[&&session.id[..], &github_id, &&device_id[..], &&signing_key[..]],
    ).await?;
    issue(tx, &session).await
}

async fn session(tx: &Transaction<'_>, digest: &Id, refresh: bool) -> Result<(Session, bool)> {
    let row = tx
        .query_opt(
            "SELECT s.id, s.github_id, s.device_id, s.signing_key, t.spent
         FROM howl_control.tokens t JOIN howl_control.pending_sessions s ON s.id = t.session_id
         WHERE t.digest = $1 AND t.refresh = $2 AND NOT s.revoked FOR UPDATE OF s, t",
            &[&&digest[..], &refresh],
        )
        .await?
        .ok_or(Error::Unauthorized)?;
    let active: bool = tx
        .query_one(
            "SELECT s.expires_at > clock_timestamp() AND t.expires_at > clock_timestamp()
         FROM howl_control.tokens t JOIN howl_control.pending_sessions s ON s.id = t.session_id
         WHERE t.digest = $1",
            &[&&digest[..]],
        )
        .await?
        .get(0);
    if !active {
        return Err(Error::Unauthorized);
    }
    Ok((read_session(&row)?, row.get(4)))
}

fn read_session(row: &Row) -> Result<Session> {
    Ok(Session {
        id: id(row, 0)?,
        github_id: row.get(1),
        device_id: id(row, 2)?,
        signing_key: id(row, 3)?,
    })
}

async fn issue(tx: &Transaction<'_>, session: &Session) -> Result<Credentials> {
    let access = zeroize::Zeroizing::new(random()?);
    let refresh = zeroize::Zeroizing::new(random()?);
    let access_digest = proof::hash(&access[..]);
    let refresh_digest = proof::hash(&refresh[..]);
    tx.execute(
        "INSERT INTO howl_control.tokens (digest, session_id, refresh, expires_at)
         SELECT $1::bytea, id, false, LEAST(expires_at, clock_timestamp() + interval '5 minutes')
         FROM howl_control.pending_sessions WHERE id = $3
         UNION ALL
         SELECT $2::bytea, id, true, expires_at FROM howl_control.pending_sessions WHERE id = $3",
        &[&&access_digest[..], &&refresh_digest[..], &&session.id[..]],
    )
    .await?;
    Ok(Credentials {
        access_token: hex::encode(&access[..]),
        refresh_token: hex::encode(&refresh[..]),
        expires_in: 300,
        session: session.public(),
    })
}

async fn revoke(tx: &Transaction<'_>, session: &Session) -> Result<()> {
    tx.execute(
        "UPDATE howl_control.pending_sessions SET revoked = true WHERE id = $1",
        &[&&session.id[..]],
    )
    .await?;
    Ok(())
}
