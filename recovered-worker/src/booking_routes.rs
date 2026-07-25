//! Public booking HTTP surface (wasm): `GET /booking/<slug>/slots`.
//!
//! Unauthenticated by design — availability is not sensitive (BOOKING-PLAN
//! §Routes). Open slots are expanded from the form's rules at read time,
//! minus persisted booked rows. Rate-limited per client IP through the
//! existing per-form limiter (`submitter = "ip:<addr>"`), and CORS-open so
//! site pages (executiveaiguidance.com etc.) can fetch cross-origin.

use serde_json::json;
use worker::*;

use crate::booking;
use crate::storage;

pub async fn handle(req: Request, env: Env) -> Result<Response> {
    if req.method() != Method::Get {
        return Response::error("method not allowed", 405);
    }
    let path = req.path();
    let mut parts = path.trim_matches('/').split('/');
    let (Some("booking"), Some(slug), Some("slots"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Response::error("not found", 404);
    };

    let db = env.d1("FORMS")?;
    let form = match storage::get_form(&db, slug).await? {
        Some(f) if f.status == "active" => f,
        _ => return Response::error("not found", 404),
    };
    let cfg = match booking::parse_config(&form.options_json) {
        Ok(Some(c)) => c,
        Ok(None) => return Response::error("not a booking form", 404),
        Err(e) => {
            console_log!("booking: bad config for '{slug}': {e}");
            return Response::error("booking misconfigured", 500);
        }
    };

    let now = (Date::now().as_millis() / 1000) as i64;
    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".into());
    if !storage::rate_limit_check_and_inc(&db, &form.slug, &format!("ip:{ip}"), now, form.rate_limit_per_hour).await? {
        return Response::error("rate limited", 429);
    }

    let mut open = booking::expand_slots(&cfg, now);
    let booked = storage::booked_starts(&db, &form.slug, now).await?;
    open.retain(|s| !booked.contains(s));

    let slots: Vec<_> = open
        .iter()
        .map(|s| json!({ "id": booking::slot_id(&form.slug, *s), "starts_at": s }))
        .collect();
    let resp = Response::from_json(&json!({
        "tz": cfg.tz_name,
        "duration_min": cfg.duration_min,
        "slots": slots,
    }))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(resp.with_headers(headers))
}
