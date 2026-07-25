//! Admin HTTP surface (wasm). Serves the dashboard UI and a NIP-98-gated
//! JSON API for forms CRUD, submission listing, and manual poll.
//!
//! Auth model (ADMIN-UI-PLAN §D2): every mutating/reading API call carries a
//! NIP-98 `Authorization: Nostr <event>` signed by the admin's NIP-07 key.
//! The worker verifies method+url+body-hash+freshness, that the pubkey is in
//! the admin set, and that the event id is unused (replay guard). The static
//! UI and the public `/admin/config` bootstrap are unauthenticated.

use serde::Deserialize;
use serde_json::json;
use worker::*;

use crate::nip98;
use crate::poll;
use crate::storage;

const ADMIN_UI: &str = include_str!("admin/index.html");

pub async fn handle(mut req: Request, env: Env) -> Result<Response> {
    let db = env.d1("FORMS")?;
    let method = req.method();
    let path = req.path();

    // ---- public routes ----
    if method == Method::Get && (path == "/admin" || path == "/admin/") {
        return Response::from_html(ADMIN_UI);
    }
    if method == Method::Get && path == "/admin/config" {
        let processor_pubkey = env
            .var("PROCESSOR_PUBKEY")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let admins = storage::list_admins(&db).await.unwrap_or_default();
        return Response::from_json(&json!({
            "processor_pubkey": processor_pubkey,
            "admins": admins,
        }));
    }

    // ---- NIP-98 gate (reads + writes) ----
    let url = req.url()?.to_string();
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    let body = req.text().await.unwrap_or_default();
    let now = (Date::now().as_millis() / 1000) as u64;

    let verified = match nip98::verify(&auth, method_str(&method), &url, body.as_bytes(), now) {
        Ok(v) => v,
        Err(e) => return Response::error(format!("unauthorized: {e}"), 401),
    };
    if !storage::is_admin(&db, &verified.pubkey).await? {
        return Response::error("forbidden: not an admin pubkey", 403);
    }
    if !storage::nonce_check_and_store(&db, &verified.event_id, now as i64).await? {
        return Response::error("unauthorized: replay", 401);
    }

    // ---- authenticated routes ----
    match (method.clone(), path.as_str()) {
        (Method::Post, "/admin/poll-now") => {
            poll::run_once(&env).await?;
            Response::ok("polled")
        }
        (Method::Get, "/admin/forms") => {
            let forms = storage::list_forms(&db).await?;
            Response::from_json(&forms)
        }
        (Method::Post, "/admin/forms") => upsert_form(&db, &body, now as i64).await,
        (Method::Get, "/admin/submissions") => {
            let (form, limit) = submissions_query(&req);
            let rows = storage::list_submissions(&db, form.as_deref(), limit).await?;
            Response::from_json(&rows)
        }
        (Method::Delete, p) if p.starts_with("/admin/forms/") => {
            let slug = p.trim_start_matches("/admin/forms/");
            if slug.is_empty() {
                return Response::error("missing slug", 400);
            }
            storage::delete_form(&db, slug).await?;
            Response::ok("deleted")
        }
        // Booking (BOOKING-PLAN §Admin): list booked slots, cancel one.
        // Rules live in forms.options_json and are edited via the existing
        // POST /admin/forms upsert.
        (Method::Get, "/admin/slots") => {
            let (form, limit) = submissions_query(&req);
            let slots = storage::list_slots(&db, form.as_deref(), limit).await?;
            Response::from_json(&slots)
        }
        (Method::Delete, p) if p.starts_with("/admin/slots/") => {
            let slot_id = p.trim_start_matches("/admin/slots/");
            if slot_id.is_empty() {
                return Response::error("missing slot id", 400);
            }
            // Frees the slot (it becomes offerable again). Visitor
            // notification is manual per decision D3.
            if storage::delete_slot(&db, slot_id).await? {
                Response::ok("freed")
            } else {
                Response::error("unknown slot", 404)
            }
        }
        _ => Response::error("not found", 404),
    }
}

#[derive(Deserialize)]
struct FormInput {
    slug: String,
    #[serde(default)]
    name: String,
    notify_pubkey: String,
    #[serde(default = "default_pow")]
    pow_difficulty: i64,
    #[serde(default = "default_rate")]
    rate_limit_per_hour: i64,
    #[serde(default = "default_mode")]
    delivery_mode: String,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default = "default_options")]
    options_json: String,
}
fn default_pow() -> i64 { 16 }
fn default_rate() -> i64 { 100 }
fn default_mode() -> String { "full".into() }
fn default_status() -> String { "active".into() }
fn default_options() -> String { "{}".into() }

async fn upsert_form(db: &D1Database, body: &str, now: i64) -> Result<Response> {
    let f: FormInput = match serde_json::from_str(body) {
        Ok(f) => f,
        Err(e) => return Response::error(format!("bad form json: {e}"), 400),
    };
    if f.slug.is_empty() {
        return Response::error("slug required", 400);
    }
    if !is_hex64(&f.notify_pubkey) {
        return Response::error("notify_pubkey must be 64-char hex", 400);
    }
    if f.delivery_mode != "full" && f.delivery_mode != "notify" {
        return Response::error("delivery_mode must be 'full' or 'notify'", 400);
    }
    if f.status != "active" && f.status != "disabled" {
        return Response::error("status must be 'active' or 'disabled'", 400);
    }
    storage::upsert_form(
        db,
        &f.slug,
        &f.name,
        &f.notify_pubkey,
        f.pow_difficulty,
        f.rate_limit_per_hour,
        &f.delivery_mode,
        &f.status,
        &f.options_json,
        now,
    )
    .await?;
    Response::ok("saved")
}

fn submissions_query(req: &Request) -> (Option<String>, i64) {
    let mut form = None;
    let mut limit = 100i64;
    if let Ok(url) = req.url() {
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "form" if !v.is_empty() => form = Some(v.to_string()),
                "limit" => limit = v.parse().unwrap_or(100),
                _ => {}
            }
        }
    }
    (form, limit)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn method_str(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Patch => "PATCH",
        Method::Head => "HEAD",
        Method::Options => "OPTIONS",
        Method::Connect => "CONNECT",
        Method::Trace => "TRACE",
        Method::Report => "REPORT",
    }
}
