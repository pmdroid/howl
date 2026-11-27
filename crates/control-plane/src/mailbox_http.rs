use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_postgres::{IsolationLevel, Transaction};

use crate::{
    ControlPlane, Error, TrustedDevice, bearer,
    mailbox::{
        Deposit, EnrolledDevice, EnrolledSubmission, Envelope, FRAME_LIMIT, Header, Limits,
        Mailbox, MailboxError, MailingAddress, Stream,
    },
    proof, request_proof,
};

const DEPOSIT: &str = "mailbox-deposit";
const FETCH: &str = "mailbox-fetch";
const RANGE: &str = "mailbox-range";
const ACK: &str = "mailbox-ack";
const BODY_LIMIT: usize = 2 * FRAME_LIMIT + 512;
const LIMITS: Limits = Limits {
    messages: 256,
    bytes: 16 * 1024 * 1024,
    retained_ids: 2048,
};

type Result<T> = std::result::Result<T, ApiError>;

enum ApiError {
    Control(Error),
    Storage(StatusCode),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Control(error) => error.into_response(),
            Self::Storage(status) => status.into_response(),
        }
    }
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Control(error)
    }
}

impl From<MailboxError> for ApiError {
    fn from(error: MailboxError) -> Self {
        let status = match error {
            MailboxError::Invalid => StatusCode::BAD_REQUEST,
            MailboxError::Unauthorized => StatusCode::UNAUTHORIZED,
            MailboxError::Expired => StatusCode::GONE,
            MailboxError::Conflict => StatusCode::CONFLICT,
            MailboxError::Quota => StatusCode::TOO_MANY_REQUESTS,
            MailboxError::Database => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::Storage(status)
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        Error::from(error).into()
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(error: tokio_postgres::Error) -> Self {
        Error::from(error).into()
    }
}

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route(
            "/v1/mailbox/deposit",
            post(deposit).layer(DefaultBodyLimit::max(BODY_LIMIT)),
        )
        .route("/v1/mailbox/fetch", post(fetch))
        .route("/v1/mailbox/range", post(range))
        .route("/v1/mailbox/ack", post(acknowledge))
}

impl ControlPlane {
    pub async fn run_mailbox_maintenance(&self) {
        let mailbox = self.mailbox();
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if mailbox.prune_expired(1024).await.is_err() {
                eprintln!("Mailbox retention cleanup failed.");
            }
        }
    }

    fn mailbox(&self) -> Mailbox {
        Mailbox::new(self.pool.clone(), LIMITS).expect("valid mailbox limits")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositRequest {
    recipient: String,
    ciphertext: String,
}

async fn deposit(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let request: DepositRequest = decode_body(&body)?;
    let recipient_device = proof::decode::<32>(&request.recipient)?;
    if request.ciphertext.is_empty() || request.ciphertext.len() > 2 * FRAME_LIMIT {
        return Err(Error::Invalid.into());
    }
    let ciphertext = hex::decode(request.ciphertext).map_err(|_| Error::Invalid)?;
    let metadata = howl_envelope::inspect_unverified(&ciphertext).map_err(|_| Error::Invalid)?;
    let routing = metadata.routing;
    let mut connection = control.pool.get().await?;
    let tx = connection
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let caller = authenticate(&control, &tx, DEPOSIT, &headers, &body).await?;
    let account = caller.account_id();
    if routing.sender.account != account
        || routing.sender.device != caller.device_id()
        || recipient_device == caller.device_id()
    {
        return Err(Error::Unauthorized.into());
    }
    let allowed = tx
        .query_opt(
            "SELECT 1 FROM howl_control.enrolled_devices d
             JOIN howl_control.enrollment_pins p USING (account_id, authority_head, designation_digest)
             WHERE d.account_id = $1 AND d.device_id = $2
               AND d.authority_head = $3 AND d.designation_digest = $4",
            &[
                &account.as_slice(),
                &recipient_device.as_slice(),
                &caller.authority_head().as_slice(),
                &caller.designation_digest().as_slice(),
            ],
        )
        .await?
        .is_some();
    if !allowed {
        return Err(Error::Unauthorized.into());
    }
    let sender = enrolled(&caller)?;
    let address = MailingAddress {
        account,
        device: recipient_device,
    };
    let recipient = EnrolledDevice::from_verified_enrollment(address)?;
    let submission = EnrolledSubmission::from_verified_request(
        &sender,
        &recipient,
        Header {
            stream: Stream {
                channel: routing.channel,
                epoch: routing.epoch,
                sender: MailingAddress {
                    account,
                    device: caller.device_id(),
                },
            },
            sequence: routing.sequence,
            message: metadata.message_id,
            sent_at: routing.created_at.try_into().map_err(|_| Error::Invalid)?,
        },
        &ciphertext,
    )?;
    let deposited = control.mailbox().deposit_in(&tx, submission).await?;
    tx.commit().await?;
    Ok(match deposited {
        Deposit::Stored => StatusCode::CREATED,
        Deposit::Duplicate => StatusCode::NO_CONTENT,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    after: i64,
    limit: usize,
}

#[derive(Serialize)]
struct Listing<Cursor> {
    envelopes: Vec<EnvelopeRecord>,
    next: Option<Cursor>,
}

#[derive(Serialize)]
struct EnvelopeRecord {
    cursor: i64,
    channel: String,
    epoch: u64,
    sender_account: String,
    sender_device: String,
    sequence: u64,
    message: String,
    sent_at: i64,
    digest: String,
    ciphertext: String,
}

impl From<Envelope> for EnvelopeRecord {
    fn from(envelope: Envelope) -> Self {
        let header = envelope.header;
        Self {
            cursor: envelope.cursor,
            channel: hex::encode(header.stream.channel),
            epoch: header.stream.epoch,
            sender_account: hex::encode(header.stream.sender.account),
            sender_device: hex::encode(header.stream.sender.device),
            sequence: header.sequence,
            message: hex::encode(header.message),
            sent_at: header.sent_at,
            digest: hex::encode(envelope.digest),
            ciphertext: hex::encode(envelope.ciphertext),
        }
    }
}

async fn fetch(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Listing<i64>>> {
    let request: FetchRequest = decode_body(&body)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let caller = authenticate(&control, &tx, FETCH, &headers, &body).await?;
    let page = control
        .mailbox()
        .fetch_in(&tx, &enrolled(&caller)?, request.after, request.limit)
        .await?;
    tx.commit().await?;
    Ok(Json(Listing {
        envelopes: page.envelopes.into_iter().map(Into::into).collect(),
        next: page.next,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeRequest {
    channel: String,
    epoch: u64,
    sender: String,
    first: u64,
    last: u64,
    limit: usize,
}

#[derive(Serialize)]
struct RangeListing {
    #[serde(flatten)]
    listing: Listing<u64>,
    missing: Vec<[u64; 2]>,
}

async fn range(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RangeListing>> {
    let request: RangeRequest = decode_body(&body)?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    let caller = authenticate(&control, &tx, RANGE, &headers, &body).await?;
    let stream = Stream {
        channel: proof::decode(&request.channel)?,
        epoch: request.epoch,
        sender: MailingAddress {
            account: caller.account_id(),
            device: proof::decode(&request.sender)?,
        },
    };
    let page = control
        .mailbox()
        .fetch_range_in(
            &tx,
            &enrolled(&caller)?,
            stream,
            request.first..=request.last,
            request.limit,
        )
        .await?;
    tx.commit().await?;
    Ok(Json(RangeListing {
        listing: Listing {
            envelopes: page.envelopes.into_iter().map(Into::into).collect(),
            next: page.next,
        },
        missing: page
            .missing
            .into_iter()
            .map(|range| [*range.start(), *range.end()])
            .collect(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    message: String,
    digest: String,
}

async fn acknowledge(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let request: AckRequest = decode_body(&body)?;
    let mut connection = control.pool.get().await?;
    let tx = connection
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let caller = authenticate(&control, &tx, ACK, &headers, &body).await?;
    let confirmed = control
        .mailbox()
        .acknowledge_in(
            &tx,
            &enrolled(&caller)?,
            proof::decode(&request.message)?,
            proof::decode(&request.digest)?,
        )
        .await?;
    tx.commit().await?;
    Ok(if confirmed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    })
}

fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Error::Invalid.into())
}

fn enrolled(caller: &TrustedDevice) -> Result<EnrolledDevice> {
    Ok(EnrolledDevice::from_verified_enrollment(MailingAddress {
        account: caller.account_id(),
        device: caller.device_id(),
    })?)
}

async fn authenticate(
    control: &ControlPlane,
    tx: &Transaction<'_>,
    operation: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<TrustedDevice> {
    Ok(control
        .authorize_enrolled_in(
            tx,
            operation,
            bearer(headers)?,
            &request_proof(headers)?,
            body,
        )
        .await?)
}
