use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::server::AppState;

/// Bearer token auth middleware.
/// If config.admin_token is empty, all requests pass through (dev mode).
/// Otherwise requires: Authorization: Bearer <token>
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    if state.config.admin_token.is_empty() {
        return Ok(next.run(request).await);
    }

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization scheme"))?;

    if !state.sessions.is_valid(token) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or expired session"));
    }

    Ok(next.run(request).await)
}
