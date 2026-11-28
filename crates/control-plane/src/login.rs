use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    ControlPlane, Error, Result,
    github::Poll,
    id,
    proof::{self, Id, Proof},
    random,
    sessions::{self, Credentials},
};

const POLL: &str = "poll";
const NO_TOKEN: Id = [0; 32];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidate {
    device_id: String,
    signing_key: String,
}

#[derive(Serialize)]
pub(crate) struct Login {
    login: String,
    user_code: String,
    verification_uri: &'static str,
    interval: i32,
    expires_in: i32,
    nonce: String,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum LoginStatus {
    Pending { interval: i32, nonce: String },
    Verified { credentials: Credentials },
}

impl ControlPlane {
    pub(crate) async fn begin_login(
        &self,
        candidate: Candidate,
        join_network: bool,
    ) -> Result<Login> {
        let device = proof::decode(&candidate.device_id)?;
        let signing = proof::decode(&candidate.signing_key)?;
        proof::key(signing)?;
        if device == [0; 32] {
            return Err(Error::Invalid);
        }
        let mut upstream = self.github.begin().await?;
        let login = random()?;
        let code = upstream.take_code();
        let encrypted = self.seal(&login, code.as_bytes())?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        tx.execute(
            "DELETE FROM howl_control.pending_logins WHERE expires_at <= clock_timestamp()",
            &[],
        )
        .await?;
        tx.execute(
            "INSERT INTO howl_control.pending_logins
             (id, device_id, signing_key, provider_code, expires_at, next_poll, poll_interval, join_network)
             VALUES ($1, $2, $3, $4, clock_timestamp() + $5::integer * interval '1 second',
                     clock_timestamp() + $6::integer * interval '1 second', $6, $7)",
            &[
                &&login[..],
                &&device[..],
                &&signing[..],
                &encrypted,
                &upstream.expires_in,
                &upstream.interval,
                &join_network,
            ],
        )
        .await?;
        let nonce = proof::issue(&tx, &login, POLL, &NO_TOKEN).await?;
        tx.commit().await?;
        Ok(Login {
            login: hex::encode(login),
            user_code: upstream.user_code,
            verification_uri: "https://github.com/login/device",
            interval: upstream.interval,
            expires_in: upstream.expires_in,
            nonce: hex::encode(nonce),
        })
    }

    pub(crate) async fn login_challenge(&self, login: &str) -> Result<Id> {
        let login = proof::decode::<32>(login)?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        if tx
            .query_opt(
                "SELECT 1 FROM howl_control.pending_logins WHERE id = $1
            AND expires_at > clock_timestamp()",
                &[&&login[..]],
            )
            .await?
            .is_none()
        {
            return Err(Error::Unauthorized);
        }
        let nonce = proof::issue(&tx, &login, POLL, &NO_TOKEN).await?;
        tx.commit().await?;
        Ok(nonce)
    }

    pub(crate) async fn poll_login(&self, login: Id, signed: &Proof) -> Result<LoginStatus> {
        let attempt = random()?;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT device_id, signing_key, provider_code, poll_interval
            FROM howl_control.pending_logins WHERE id = $1 FOR UPDATE",
                &[&&login[..]],
            )
            .await?
            .ok_or(Error::Unauthorized)?;
        let device = id(&row, 0)?;
        let signing = id(&row, 1)?;
        let interval: i32 = row.get(3);
        proof::consume(
            &tx,
            self.audience,
            signed,
            proof::Use {
                subject: login,
                signing_key: signing,
                operation: POLL,
                token_digest: NO_TOKEN,
                body: b"",
            },
        )
        .await?;
        if tx
            .execute(
                "UPDATE howl_control.pending_logins SET
              next_poll = clock_timestamp() + poll_interval * interval '1 second',
              poll_lease = clock_timestamp() + interval '30 seconds', poll_attempt = $2
              WHERE id = $1 AND expires_at > clock_timestamp() AND next_poll <= clock_timestamp()
                AND (poll_lease IS NULL OR poll_lease <= clock_timestamp())",
                &[&&login[..], &&attempt[..]],
            )
            .await?
            != 1
        {
            return Err(Error::Wait);
        }
        let code = self.open_sealed(&login, row.get::<_, &[u8]>(2))?;
        tx.commit().await?;
        drop(connection);
        let upstream = self
            .github
            .poll(std::str::from_utf8(&code).map_err(|_| Error::Internal)?)
            .await;
        let mut connection = self.pool.get().await?;
        let tx = connection.transaction().await?;
        let status = match upstream {
            Ok(Poll::Verified(github_id)) => {
                let row = tx.query_opt(
                    "DELETE FROM howl_control.pending_logins WHERE id = $1 AND poll_attempt = $2
                     AND expires_at > clock_timestamp() RETURNING join_network",
                    &[&&login[..], &&attempt[..]],
                ).await?.ok_or(Error::Unauthorized)?;
                if row.get::<_, bool>(0) && self.web_origin.is_none() {
                    crate::network::reserve(&tx, github_id, &device, &signing).await?;
                }
                let credentials = sessions::begin(&tx, github_id, device, signing).await?;
                LoginStatus::Verified { credentials }
            }
            Ok(Poll::Denied) => {
                tx.execute(
                    "DELETE FROM howl_control.pending_logins WHERE id = $1 AND poll_attempt = $2",
                    &[&&login[..], &&attempt[..]],
                )
                .await?;
                tx.commit().await?;
                return Err(Error::Unauthorized);
            }
            outcome => {
                let interval = match outcome {
                    Ok(Poll::SlowDown(hint)) => hint.unwrap_or_default().max(interval + 5).min(900),
                    _ => interval,
                };
                if tx.execute("UPDATE howl_control.pending_logins SET poll_lease = NULL,
                     poll_attempt = NULL, poll_interval = $3,
                     next_poll = GREATEST(next_poll, clock_timestamp() + $3::integer * interval '1 second')
                     WHERE id = $1 AND poll_attempt = $2 AND expires_at > clock_timestamp()",
                    &[&&login[..], &&attempt[..], &interval],
                ).await? != 1 {
                    return Err(Error::Unauthorized);
                }
                if let Err(error) = outcome {
                    tx.commit().await?;
                    return Err(error);
                }
                let nonce = proof::issue(&tx, &login, POLL, &NO_TOKEN).await?;
                LoginStatus::Pending {
                    interval,
                    nonce: hex::encode(nonce),
                }
            }
        };
        tx.commit().await?;
        Ok(status)
    }

    pub(crate) fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| Error::Internal)?;
        let cipher = ChaCha20Poly1305::new((&*self.state_key).into());
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: context,
                },
            )
            .map_err(|_| Error::Internal)?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    pub(crate) fn open_sealed(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (nonce, body) = sealed.split_at_checked(12).ok_or(Error::Internal)?;
        let cipher = ChaCha20Poly1305::new((&*self.state_key).into());
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: context,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Internal)
    }
}
