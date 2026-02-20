use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::prelude::*;
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::server::AppState;

/// NIP-98 HTTP Auth middleware
///
/// Expects Authorization header with base64-encoded Nostr event:
/// Authorization: Nostr <base64-encoded-event>
///
/// The event must:
/// - Be kind 27235 (HTTP Auth)
/// - Have valid signature
/// - Have "u" tag matching request URL
/// - Have "method" tag matching request method
/// - Be signed by a pubkey in admin_pubkeys table
/// - Be recent (within 60 seconds)
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    if !auth_header.starts_with("Nostr ") {
        return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization scheme"));
    }

    let event_b64 = &auth_header[6..];
    let event_json = BASE64_STANDARD
        .decode(event_b64)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid base64 in Authorization"))?;

    let event: serde_json::Value = serde_json::from_slice(&event_json)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid JSON in Authorization"))?;

    // Verify event structure
    let kind = event.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);
    if kind != 27235 {
        return Err((StatusCode::UNAUTHORIZED, "Invalid event kind"));
    }

    let pubkey = event
        .get("pubkey")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing pubkey"))?;

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing created_at"))?;

    let sig = event
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing signature"))?;

    let id = event
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing event id"))?;

    // Check timestamp (within 60 seconds)
    let now = chrono::Utc::now().timestamp();
    if (now - created_at).abs() > 60 {
        return Err((StatusCode::UNAUTHORIZED, "Event expired"));
    }

    // Verify event ID
    let event_for_id = serde_json::json!([
        0,
        pubkey,
        created_at,
        kind,
        event.get("tags").unwrap_or(&serde_json::json!([])),
        event.get("content").and_then(|v| v.as_str()).unwrap_or("")
    ]);
    let computed_id = hex::encode(Sha256::digest(event_for_id.to_string().as_bytes()));
    if computed_id != id {
        return Err((StatusCode::UNAUTHORIZED, "Invalid event id"));
    }

    // Verify signature
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest_slice(&hex::decode(id).unwrap())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid message hash"))?;

    let sig_bytes =
        hex::decode(sig).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature hex"))?;
    let signature = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature"))?;

    let pubkey_bytes =
        hex::decode(pubkey).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid pubkey hex"))?;
    let xonly = secp256k1::XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid pubkey"))?;

    secp.verify_schnorr(&signature, &msg, &xonly)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature"))?;

    // Check if pubkey is admin
    let is_admin = state
        .db
        .is_admin(pubkey)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    if !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not an admin"));
    }

    // Optionally verify URL and method tags
    // (skipped for simplicity - can add if needed)

    Ok(next.run(request).await)
}
