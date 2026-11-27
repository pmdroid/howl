use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;

pub mod github;
pub mod proof;

pub use github::GitHub;
pub use proof::{Id, Proof, credential_digest, signing_bytes};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Configuration,
    Invalid,
    Unauthorized,
    Wait,
    Upstream,
    Internal,
}

impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Internal
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::Internal
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Configuration | Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Wait => (StatusCode::TOO_MANY_REQUESTS, "wait_for_poll_interval"),
            Self::Upstream => (StatusCode::BAD_GATEWAY, "github_unavailable"),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

pub async fn migrate(pool: &Pool) -> Result<()> {
    let mut connection = pool.get().await?;
    let tx = connection.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(4983033826038031201)", &[])
        .await?;
    tx.batch_execute(include_str!("../migrations/001_auth.sql"))
        .await?;
    tx.commit().await?;
    Ok(())
}

pub fn random() -> Result<Id> {
    let mut result = [0; 32];
    getrandom::fill(&mut result).map_err(|_| Error::Internal)?;
    Ok(result)
}
