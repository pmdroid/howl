use std::sync::Arc;

use axum::{Router, http::header, response::IntoResponse, routing::get};

use crate::ControlPlane;

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/", get(page))
        .route("/devices", get(page))
        .route(
            "/assets/devices.css",
            get(|| async {
                asset(
                    "text/css; charset=utf-8",
                    include_str!("../web/devices.css"),
                )
            }),
        )
        .route(
            "/assets/devices.js",
            get(|| async {
                asset(
                    "text/javascript; charset=utf-8",
                    include_str!("../web/devices.js"),
                )
            }),
        )
}

async fn page() -> impl IntoResponse {
    asset(
        "text/html; charset=utf-8",
        include_str!("../web/devices.html"),
    )
}

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            ),
        ],
        body,
    )
}
