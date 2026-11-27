use std::time::Duration;

use reqwest::{Client, RequestBuilder, StatusCode, redirect::Policy};
use serde::{Deserialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{Error, Result};

const VERIFICATION_URI: &str = "https://github.com/login/device";

pub struct GitHub {
    http: Client,
    login: String,
    api: String,
    client_id: String,
    client_secret: Zeroizing<String>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceCode {
    device_code: String,
    pub user_code: String,
    verification_uri: String,
    pub expires_in: i32,
    pub interval: i32,
}

impl DeviceCode {
    pub fn take_code(&mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.device_code))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    interval: Option<i32>,
}

#[derive(Deserialize)]
struct User {
    id: i64,
}

pub(crate) enum Poll {
    Pending,
    SlowDown(Option<i32>),
    Denied,
    Verified(i64),
}

impl GitHub {
    pub fn new(client_id: String, client_secret: Zeroizing<String>) -> Result<Self> {
        if !(1..=128).contains(&client_id.len())
            || !client_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || client_secret.is_empty()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            http: Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .timeout(Duration::from_secs(8))
                .user_agent("howl-control-plane")
                .build()
                .map_err(|_| Error::Configuration)?,
            login: "https://github.com/login".into(),
            api: "https://api.github.com".into(),
            client_id,
            client_secret,
        })
    }

    pub(crate) async fn begin(&self) -> Result<DeviceCode> {
        let mut result: DeviceCode = json(
            self.http
                .post(format!("{}/device/code", self.login))
                .header("accept", "application/json")
                .form(&[("client_id", &self.client_id)]),
        )
        .await?;
        if result.verification_uri != VERIFICATION_URI
            || !(1..=900).contains(&result.expires_in)
            || !(1..=900).contains(&result.interval)
            || result.user_code.len() != 9
            || !result
                .user_code
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || result.device_code.len() != 40
            || !result
                .device_code
                .bytes()
                .all(|c| c.is_ascii_alphanumeric())
        {
            let _ = result.take_code();
            return Err(Error::Upstream);
        }
        Ok(result)
    }

    pub(crate) async fn poll(&self, device_code: &str) -> Result<Poll> {
        let token: TokenResponse = json(
            self.http
                .post(format!("{}/oauth/access_token", self.login))
                .header("accept", "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("device_code", device_code),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ]),
        )
        .await?;
        match (
            token.access_token.map(Zeroizing::new),
            token.error.as_deref(),
        ) {
            (Some(token), None) => {
                let user: Result<User> = json(
                    self.http
                        .get(format!("{}/user", self.api))
                        .bearer_auth(&*token)
                        .header("accept", "application/vnd.github+json")
                        .header("x-github-api-version", "2026-03-10"),
                )
                .await;
                let revoked = self
                    .http
                    .delete(format!(
                        "{}/applications/{}/grant",
                        self.api, self.client_id
                    ))
                    .basic_auth(&self.client_id, Some(&*self.client_secret))
                    .header("accept", "application/vnd.github+json")
                    .header("x-github-api-version", "2026-03-10")
                    .json(&serde_json::json!({ "access_token": &*token }))
                    .send()
                    .await
                    .map_err(|_| Error::Upstream)?;
                if revoked.status() != StatusCode::NO_CONTENT {
                    return Err(Error::Upstream);
                }
                let id = user?.id;
                if id <= 0 {
                    return Err(Error::Upstream);
                }
                Ok(Poll::Verified(id))
            }
            (None, Some("authorization_pending")) => Ok(Poll::Pending),
            (None, Some("slow_down")) => Ok(Poll::SlowDown(token.interval)),
            (
                None,
                Some("expired_token" | "token_expired" | "access_denied" | "incorrect_device_code"),
            ) => Ok(Poll::Denied),
            _ => Err(Error::Upstream),
        }
    }
}

async fn json<T: DeserializeOwned>(request: RequestBuilder) -> Result<T> {
    let mut response = request.send().await.map_err(|_| Error::Upstream)?;
    if !response.status().is_success() {
        return Err(Error::Upstream);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Upstream)? {
        if bytes.len() + chunk.len() > 16_384 {
            return Err(Error::Upstream);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Upstream)
}
