//! NIP-98 HTTP Auth verification (kind 27235).
//!
//! The browser admin UI signs each request with its NIP-07 key; the worker
//! verifies the signed event binds the exact **method + URL + body hash**
//! and is fresh, then the caller checks the pubkey against the admin set
//! and the event id against the replay-nonce store (both D1-backed).
//!
//! This module is pure (no `worker` deps) so it unit-tests on the host.

use sha2::{Digest, Sha256};

use crate::event::Event;

/// Default allowed clock skew for `created_at` (seconds).
pub const MAX_SKEW_SECS: u64 = 60;
const NIP98_KIND: u16 = 27235;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuthError {
    #[error("missing or malformed Authorization header")]
    BadHeader,
    #[error("auth event is not valid JSON")]
    BadJson,
    #[error("wrong kind {0} (expected 27235)")]
    WrongKind(u16),
    #[error("event id does not match content")]
    IdMismatch,
    #[error("signature verification failed")]
    BadSignature,
    #[error("timestamp outside allowed window")]
    StaleTimestamp,
    #[error("url tag mismatch")]
    UrlMismatch,
    #[error("method tag mismatch")]
    MethodMismatch,
    #[error("payload tag missing or mismatched")]
    PayloadMismatch,
}

/// Result of a successful NIP-98 verification. The caller still must
/// confirm `pubkey` ∈ admin set and `event_id` is unused (replay).
#[derive(Debug, Clone)]
pub struct Verified {
    pub pubkey: String,
    pub event_id: String,
}

/// Verify a NIP-98 `Authorization: Nostr <base64-event>` header.
///
/// `method`/`url` are the actual request's; `body` is the raw request body
/// (empty for GET). `now` is the current unix time (seconds).
pub fn verify(
    authorization: &str,
    method: &str,
    url: &str,
    body: &[u8],
    now: u64,
) -> Result<Verified, AuthError> {
    let b64 = authorization
        .strip_prefix("Nostr ")
        .or_else(|| authorization.strip_prefix("nostr "))
        .ok_or(AuthError::BadHeader)?
        .trim();

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let raw = B64.decode(b64.as_bytes()).map_err(|_| AuthError::BadHeader)?;
    let event: Event = serde_json::from_slice(&raw).map_err(|_| AuthError::BadJson)?;

    if event.kind != NIP98_KIND {
        return Err(AuthError::WrongKind(event.kind));
    }

    // id integrity + signature.
    if compute_id(&event) != event.id {
        return Err(AuthError::IdMismatch);
    }
    if !verify_signature(&event) {
        return Err(AuthError::BadSignature);
    }

    // freshness (symmetric window).
    let ts = event.created_at;
    let within = (ts <= now && now - ts <= MAX_SKEW_SECS) || (ts > now && ts - now <= MAX_SKEW_SECS);
    if !within {
        return Err(AuthError::StaleTimestamp);
    }

    // bound tags.
    let u = tag_value(&event, "u").ok_or(AuthError::UrlMismatch)?;
    if u != url {
        return Err(AuthError::UrlMismatch);
    }
    let m = tag_value(&event, "method").ok_or(AuthError::MethodMismatch)?;
    if !m.eq_ignore_ascii_case(method) {
        return Err(AuthError::MethodMismatch);
    }

    // payload hash is REQUIRED whenever there is a body; for empty bodies a
    // payload tag, if present, must still match the (empty) hash.
    if !body.is_empty() {
        let want = hex_sha256(body);
        match tag_value(&event, "payload") {
            Some(p) if p.eq_ignore_ascii_case(&want) => {}
            _ => return Err(AuthError::PayloadMismatch),
        }
    } else if let Some(p) = tag_value(&event, "payload") {
        if !p.eq_ignore_ascii_case(&hex_sha256(body)) {
            return Err(AuthError::PayloadMismatch);
        }
    }

    Ok(Verified {
        pubkey: event.pubkey,
        event_id: event.id,
    })
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|t| {
        if t.first().map(String::as_str) == Some(name) {
            t.get(1).map(String::as_str)
        } else {
            None
        }
    })
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Canonical NIP-01 id: sha256 of `[0,pubkey,created_at,kind,tags,content]`.
fn compute_id(event: &Event) -> String {
    let serialized = serde_json::to_string(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(serialized.as_bytes());
    hex::encode(h.finalize())
}

/// BIP-340 verify on the 32-byte id (mirrors `nostr-relay::nip01`).
fn verify_signature(event: &Event) -> bool {
    use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};

    let pk_bytes = match hex::decode(&event.pubkey) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(&event.sig) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let sig = match SchnorrSig::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let id_bytes = match hex::decode(&event.id) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    vk.verify_raw(&id_bytes, &sig).is_ok()
}
