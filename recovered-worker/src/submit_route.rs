//! `POST /submit` (and its CORS preflight): the browser SDK's only write path.
//! Envelope checks live in `submit.rs` (host-tested); this is the HTTP and D1
//! glue around them and `process::process_event`.

use worker::*;

use crate::process::{self, Keys, Outcome};
use crate::storage;
use crate::submit::{self, Reject};

/// Submissions accepted per client IP per hour, across all forms. Each SDK
/// submission is signed by a fresh key, so the per-form, per-pubkey limit in
/// `process_event` cannot stop one client on its own.
const IP_LIMIT_PER_HOUR: i64 = 20;

/// `rate_limits.form_slug` value for the per-IP counter. Not a valid form
/// slug (slugs are 8 base62 chars), so it cannot collide with a form's rows.
const IP_LIMIT_SLUG: &str = "_submit_ip";

pub async fn handle(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    let origin = req.headers().get("Origin")?.unwrap_or_default();
    let allowed = allowed_origin(&env, &origin);

    if req.method() == Method::Options {
        return with_cors(Response::empty()?.with_status(204), allowed.as_deref());
    }
    if req.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }

    let ip = req.headers().get("CF-Connecting-IP")?.unwrap_or_default();
    let body = req.bytes().await?;
    let now_secs: i64 = (Date::now().as_millis() / 1000) as i64;

    let keys = Keys::from_env(&env)?;
    let resp = match submit::parse_and_check(&body, &keys.processor_pubkey, now_secs as u64) {
        Err(r) => reject(r.reason(), if r == Reject::TooLarge { 413 } else { 400 }),
        Ok(event) => {
            // No `ensure_schema` here: it is 8 DDL round trips, and the tables
            // exist (the admin routes still run it).
            let db = env.d1("FORMS")?;
            if !ip.is_empty()
                && !storage::rate_limit_check_and_inc(&db, IP_LIMIT_SLUG, &ip, now_secs, IP_LIMIT_PER_HOUR).await?
            {
                reject("rate-limited", 429)
            } else {
                match process::process_event(&db, &keys, &event, now_secs).await? {
                    Outcome::Duplicate => ok(&event.id, true),
                    Outcome::Stored(delivery) => {
                        // Answer the browser now; the DM (via the relay) and
                        // the owner email run after the response is sent.
                        let env = env.clone();
                        let keys = keys.clone();
                        ctx.wait_until(async move {
                            process::deliver(&env, &keys, delivery, now_secs).await;
                        });
                        ok(&event.id, false)
                    }
                    Outcome::Rejected("rate-limited") => reject("rate-limited", 429),
                    Outcome::Rejected(reason) => reject(reason, 422),
                }
            }
        }
    };
    with_cors(resp?, allowed.as_deref())
}

fn ok(id: &str, duplicate: bool) -> Result<Response> {
    Response::from_json(&serde_json::json!({ "ok": true, "id": id, "duplicate": duplicate }))
}

fn reject(reason: &str, status: u16) -> Result<Response> {
    Ok(Response::from_json(&serde_json::json!({ "ok": false, "reason": reason }))?.with_status(status))
}

/// The request's `Origin` if it is listed in `SUBMIT_ORIGINS` (comma-separated).
fn allowed_origin(env: &Env, origin: &str) -> Option<String> {
    if origin.is_empty() {
        return None;
    }
    let list = env.var("SUBMIT_ORIGINS").ok()?.to_string();
    list.split(',').map(str::trim).find(|o| *o == origin).map(str::to_string)
}

fn with_cors(resp: Response, origin: Option<&str>) -> Result<Response> {
    let Some(origin) = origin else { return Ok(resp) };
    let headers = resp.headers().clone();
    headers.set("Access-Control-Allow-Origin", origin)?;
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    headers.set("Access-Control-Max-Age", "86400")?;
    headers.set("Vary", "Origin")?;
    Ok(resp.with_headers(headers))
}
