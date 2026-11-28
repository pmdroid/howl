mod api;

use std::{
    io::{self, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::identity::LocalIdentity;

struct Web {
    directory: PathBuf,
    authority: String,
    origin: String,
    approvals_only: bool,
    secret: Zeroizing<[u8; 32]>,
}

pub async fn run(directory: &Path, port: u16) -> io::Result<()> {
    LocalIdentity::load_or_create(directory)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let external = std::env::var_os("HOWL_WEB_APPROVAL_ORIGIN");
    let approvals_only = external.is_some();
    let (origin, authority) = match external {
        Some(value) => approval_origin(value.to_str().unwrap_or_default())?,
        None => {
            let authority = listener.local_addr()?.to_string();
            (format!("http://{authority}"), authority)
        }
    };
    let path = if approvals_only { "/devices" } else { "/" };
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).map_err(io::Error::other)?;
    let fragment = Zeroizing::new(hex::encode(secret.as_ref()));
    writeln!(io::stdout(), "Open {origin}{path}#{}", fragment.as_str())?;
    let web = Arc::new(Web {
        directory: directory.to_owned(),
        authority,
        origin,
        approvals_only,
        secret,
    });
    let app = Router::new()
        .route(
            "/",
            get(move || async move {
                if approvals_only {
                    Redirect::temporary("/devices").into_response()
                } else {
                    asset("text/html; charset=utf-8", INDEX).into_response()
                }
            }),
        )
        .route(
            "/devices",
            get(|| async { asset("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/app.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
        .route(
            "/licenses",
            get(|| async { asset("text/plain; charset=utf-8", LICENSE) }),
        )
        .route("/api", post(api::command))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn_with_state(Arc::clone(&web), guard))
        .with_state(web);
    axum::serve(listener, app).await
}

fn approval_origin(value: &str) -> io::Result<(String, String)> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Expected an HTTPS approval origin",
        )
    };
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let origin = url.origin().ascii_serialization();
    let authority = origin
        .strip_prefix("https://")
        .ok_or_else(invalid)?
        .to_owned();
    Ok((origin, authority))
}

impl api::Command {
    fn is_device_action(&self) -> bool {
        matches!(
            self,
            Self::DeviceRequests | Self::ApproveDevice { .. } | Self::DenyDevice { .. }
        )
    }
}

const INDEX: &str = include_str!("../../web/src/index.html");
const SCRIPT: &str = include_str!("../../web/dist/app.js");
const STYLE: &str = include_str!("../../web/src/app.css");
const LICENSE: &str = include_str!("../../web/dist/REACT-LICENSE");

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, content_type)], body)
}

async fn guard(State(web): State<Arc<Web>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let is_api = request.uri().path() == "/api";
    let origin = single(headers, header::ORIGIN);
    let mut response = if single(headers, header::HOST) != Some(web.authority.as_bytes())
        || (headers.contains_key(header::ORIGIN) && origin != Some(web.origin.as_bytes()))
        || (is_api && request.method() != Method::POST)
        || (is_api && origin != Some(web.origin.as_bytes()))
    {
        StatusCode::FORBIDDEN.into_response()
    } else if is_api && !authenticated(headers, &web.secret) {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        next.run(request).await
    };

    response.headers_mut().extend([
        (header::CACHE_CONTROL, "no-store".parse().unwrap()),
        (header::REFERRER_POLICY, "no-referrer".parse().unwrap()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap()),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                .parse()
                .unwrap(),
        ),
    ]);
    response
}

fn single(headers: &HeaderMap, name: HeaderName) -> Option<&[u8]> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let first = values.next()?;
    values.next().is_none().then(|| first.as_bytes())
}

fn authenticated(headers: &HeaderMap, secret: &[u8; 32]) -> bool {
    let mut supplied = Zeroizing::new([0; 32]);
    single(headers, header::AUTHORIZATION)
        .and_then(|value| value.strip_prefix(b"Bearer "))
        .is_some_and(|value| {
            hex::decode_to_slice(value, supplied.as_mut()).is_ok()
                && bool::from(secret.ct_eq(supplied.as_ref()))
        })
}
