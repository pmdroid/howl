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
    response::{IntoResponse, Response},
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
    secret: Zeroizing<[u8; 32]>,
}

pub async fn run(directory: &Path, port: u16) -> io::Result<()> {
    LocalIdentity::load_or_create(directory)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let authority = listener.local_addr()?.to_string();
    let origin = format!("http://{authority}");
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).map_err(io::Error::other)?;
    let fragment = Zeroizing::new(hex::encode(secret.as_ref()));
    writeln!(io::stdout(), "Open {origin}/#{}", fragment.as_str())?;
    let web = Arc::new(Web {
        directory: directory.to_owned(),
        authority,
        origin,
        secret,
    });
    let app = Router::new()
        .route(
            "/",
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
