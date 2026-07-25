//! Outbound delivery. Wraps a submission as a NIP-17 gift-wrap DM (via
//! `seal.rs`) and publishes it to the form's notify pubkey through the
//! relay's token-gated `/admin/publish` service binding.

use worker::*;

use crate::event::Event;
use crate::seal;

/// Gift-wrap `message` from the processor to `recipient_pubkey_hex` and
/// publish it. Used for both `full` (content) and `notify` (metadata-only)
/// delivery — the caller chooses the message.
pub async fn publish_dm(
    env: &Env,
    processor_sk_bytes: &[u8; 32],
    processor_pubkey_hex: &str,
    recipient_pubkey_hex: &str,
    message: &str,
    now: u64,
) -> Result<()> {
    let wrap = seal::gift_wrap(
        processor_sk_bytes,
        processor_pubkey_hex,
        recipient_pubkey_hex,
        message,
        now,
    )
    .map_err(|e| Error::RustError(format!("gift wrap: {e}")))?;
    publish_event(env, &wrap).await
}

async fn publish_event(env: &Env, event: &Event) -> Result<()> {
    let admin_token = env
        .secret("ADMIN_INTERNAL_TOKEN")
        .map(|s| s.to_string())
        .map_err(|_| Error::RustError("ADMIN_INTERNAL_TOKEN missing".into()))?;
    let body = serde_json::to_string(event)
        .map_err(|e| Error::RustError(format!("serialize: {e}")))?;

    let relay = env.service("RELAY")?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    headers.set("X-Admin-Token", &admin_token)?;
    let req = Request::new_with_init(
        "https://relay.internal/admin/publish",
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into())),
    )?;
    let resp = relay.fetch_request(req).await?;
    if resp.status_code() != 200 {
        return Err(Error::RustError(format!(
            "relay /admin/publish returned {}",
            resp.status_code()
        )));
    }
    Ok(())
}

/// Full-content DM body: a short header plus the decrypted submission.
pub fn full_message(form_slug: &str, plaintext: &str) -> String {
    format!("[form: {form_slug}] new submission\n\n{plaintext}")
}

/// Metadata-only DM body (delivery_mode=notify, and all retries).
pub fn notice_message(form_slug: &str, submitter_pubkey: &str) -> String {
    format!(
        "[form: {form_slug}] new submission from {} — open the admin dashboard to read it.",
        &submitter_pubkey[..submitter_pubkey.len().min(12)]
    )
}

/// Booking success DM: header, the decrypted submission, and the VEVENT —
/// the owner can save the trailing block as an .ics and drop it on a
/// calendar.
pub fn booking_message(form_slug: &str, plaintext: &str, starts_at: i64, ics: &str) -> String {
    format!(
        "[form: {form_slug}] new BOOKING — starts {} UTC\n\n{plaintext}\n\n--- calendar.ics ---\n{ics}",
        crate::booking::format_utc(starts_at)
    )
}

/// Slot was already taken when the claim ran (BOOKING-PLAN §guard).
pub fn booking_conflict_message(form_slug: &str, slot: &str, plaintext: &str) -> String {
    format!(
        "[form: {form_slug}] MISSED booking — slot {slot} already taken. \
         Visitor details below; reply to offer another time.\n\n{plaintext}"
    )
}

/// slot_id failed validation (outside rules/horizon, misaligned, or stale).
pub fn booking_invalid_message(form_slug: &str, slot: &str, plaintext: &str) -> String {
    format!(
        "[form: {form_slug}] REJECTED booking — slot {slot} is not offerable \
         (expired, blocked, or never valid). Visitor details below.\n\n{plaintext}"
    )
}

// ---------------------------------------------------------------------------
// Structured owner alerts -> the NOTIFY service binding (nostr-notify /alert).
//
// RECOVERED 2026-07-25. The edit that added this was pruned from the session
// transcripts, so it is reconstructed from the CONSUMER, which is authoritative:
// `../../nostr-notify/src/index.ts` (`/alert` handler) and `src/format.ts`
// (`AlertPayload`). Rendering — subject line, field ordering, timezone — lives
// in nostr-notify; the processor supplies domain data only.
//
// NOTE: `crate::alerts` is a SUPERSEDED earlier design that built email bodies
// here and published them as plaintext `["l","email"]` events via the relay.
// The shipped design POSTs JSON to NOTIFY instead. `alerts.rs` is kept for
// provenance but is not on this path.
// ---------------------------------------------------------------------------

/// `AlertPayload` per nostr-notify/src/format.ts. `fields` carries PII and is
/// emailed to the owner only — never persisted here.
pub fn alert_submission(form_name: &str, fields: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "type": "submission", "form": form_name, "fields": fields })
}

pub fn alert_booking(
    form_name: &str,
    starts_at: i64,
    status: &str,
    fields: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "type": "booking",
        "form": form_name,
        "starts_at": starts_at,
        "status": status,
        "fields": fields,
    })
}

/// Pull the `fields` object out of a decrypted submission payload.
/// Shape: `{"form_id":"…","slot_id":"…","fields":{…}}`.
pub fn fields_of(plaintext: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()
        .and_then(|v| v.get("fields").cloned())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// POST a structured alert to the NOTIFY Worker. Awaited deliberately: this
/// runs inside the cron invocation, and nostr-notify documents that a
/// backgrounded send gets cancelled when the invocation ends, which silently
/// dropped booking emails.
pub async fn send_alert(env: &Env, payload: &serde_json::Value) -> Result<()> {
    let notify = env.service("NOTIFY")?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let req = Request::new_with_init(
        "https://notify.internal/alert",
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.to_string().into())),
    )?;
    let resp = notify.fetch_request(req).await?;
    // The handler answers 202 Accepted on success.
    if resp.status_code() != 202 {
        return Err(Error::RustError(format!(
            "notify /alert returned {}",
            resp.status_code()
        )));
    }
    Ok(())
}
