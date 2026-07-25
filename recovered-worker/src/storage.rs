//! D1 helpers (Phase 3.5). Schema bootstrap, cursor, dedupe, forms
//! registry, sealed-submission insert, per-form rate limiting, NIP-98
//! admin set + replay nonces, and admin-API read/write queries.
//!
//! D1 binds integers as JS numbers (`f64`); binding `i64` directly yields a
//! `BigInt` which D1 rejects, so every integer bind goes through `as f64`.

use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::*;

use crate::event::Event;
use crate::schema;

const CURSOR_NAME: &str = "envelope_since";
/// Rate-limit window length (seconds). Per-form cap is `rate_limit_per_hour`.
const RATE_WINDOW_SECS: i64 = 3600;
/// NIP-98 replay nonces older than this are pruned / rejected.
const NONCE_TTL_SECS: i64 = 300;

pub async fn ensure_schema(db: &D1Database) -> Result<()> {
    for stmt in schema::DDL_STATEMENTS {
        db.prepare(*stmt).run().await?;
    }
    Ok(())
}

// ---------- cursor ----------

#[derive(Debug, Deserialize)]
struct CursorRow {
    value: i64,
}

pub async fn get_cursor(db: &D1Database) -> Result<i64> {
    let stmt = db
        .prepare("SELECT value FROM cursors WHERE name = ?1")
        .bind(&[CURSOR_NAME.into()])?;
    let row: Option<CursorRow> = stmt.first(None).await?;
    Ok(row.map(|r| r.value).unwrap_or(0))
}

pub async fn set_cursor(db: &D1Database, value: i64, now_secs: i64) -> Result<()> {
    db.prepare(
        "INSERT INTO cursors(name, value, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(&[CURSOR_NAME.into(), (value as f64).into(), (now_secs as f64).into()])?
    .run()
    .await?;
    Ok(())
}

// ---------- forms registry ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
    pub slug: String,
    pub name: String,
    pub notify_pubkey: String,
    pub pow_difficulty: i64,
    pub rate_limit_per_hour: i64,
    pub delivery_mode: String,
    pub status: String,
    pub options_json: String,
    pub created_at: i64,
    pub updated_at: i64,
}

const FORM_COLS: &str = "slug, name, notify_pubkey, pow_difficulty, rate_limit_per_hour, \
                         delivery_mode, status, options_json, created_at, updated_at";

pub async fn get_form(db: &D1Database, slug: &str) -> Result<Option<Form>> {
    let stmt = db
        .prepare(&format!("SELECT {FORM_COLS} FROM forms WHERE slug = ?1"))
        .bind(&[slug.into()])?;
    stmt.first(None).await
}

pub async fn list_forms(db: &D1Database) -> Result<Vec<Form>> {
    let res = db
        .prepare(&format!("SELECT {FORM_COLS} FROM forms ORDER BY created_at DESC"))
        .all()
        .await?;
    res.results::<Form>()
}

/// Create or update a form (upsert by slug). `created_at` is preserved on
/// update; `updated_at` always set to `now`.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_form(
    db: &D1Database,
    slug: &str,
    name: &str,
    notify_pubkey: &str,
    pow_difficulty: i64,
    rate_limit_per_hour: i64,
    delivery_mode: &str,
    status: &str,
    options_json: &str,
    now: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO forms(slug,name,notify_pubkey,pow_difficulty,rate_limit_per_hour,delivery_mode,status,options_json,created_at,updated_at) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9) \
         ON CONFLICT(slug) DO UPDATE SET \
           name=excluded.name, notify_pubkey=excluded.notify_pubkey, \
           pow_difficulty=excluded.pow_difficulty, rate_limit_per_hour=excluded.rate_limit_per_hour, \
           delivery_mode=excluded.delivery_mode, status=excluded.status, \
           options_json=excluded.options_json, updated_at=excluded.updated_at",
    )
    .bind(&[
        slug.into(),
        name.into(),
        notify_pubkey.into(),
        (pow_difficulty as f64).into(),
        (rate_limit_per_hour as f64).into(),
        delivery_mode.into(),
        status.into(),
        options_json.into(),
        (now as f64).into(),
    ])?
    .run()
    .await?;
    Ok(())
}

pub async fn delete_form(db: &D1Database, slug: &str) -> Result<()> {
    db.prepare("DELETE FROM forms WHERE slug = ?1")
        .bind(&[slug.into()])?
        .run()
        .await?;
    Ok(())
}

// ---------- submissions ----------

pub async fn has_submission(db: &D1Database, event_id: &str) -> Result<bool> {
    let stmt = db
        .prepare("SELECT 1 AS one FROM submissions WHERE event_id = ?1 LIMIT 1")
        .bind(&[event_id.into()])?;
    let row: Option<serde_json::Value> = stmt.first(None).await?;
    Ok(row.is_some())
}

/// Insert a submission with its at-rest **sealed** payload (NIP-44 to the
/// admin). `delivery_status` starts `pending`.
pub async fn insert_submission(
    db: &D1Database,
    event: &Event,
    form_slug: &str,
    sealed_json: &str,
    received_at: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO submissions \
            (event_id, form_slug, submitter_pubkey, sealed_json, created_at, received_at, admin_notified, delivery_status) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'pending')",
    )
    .bind(&[
        event.id.clone().into(),
        form_slug.into(),
        event.pubkey.clone().into(),
        sealed_json.into(),
        (event.created_at as f64).into(),
        (received_at as f64).into(),
    ])?
    .run()
    .await?;
    Ok(())
}

pub async fn set_delivery(
    db: &D1Database,
    event_id: &str,
    status: &str,
    notified: bool,
) -> Result<()> {
    db.prepare("UPDATE submissions SET delivery_status = ?2, admin_notified = ?3 WHERE event_id = ?1")
        .bind(&[event_id.into(), status.into(), (notified as i64 as f64).into()])?
        .run()
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionRow {
    pub event_id: String,
    pub form_slug: String,
    pub submitter_pubkey: String,
    pub sealed_json: String,
    pub created_at: i64,
    pub received_at: i64,
    pub admin_notified: i64,
    pub delivery_status: String,
}

const SUB_COLS: &str = "event_id, form_slug, submitter_pubkey, sealed_json, created_at, \
                        received_at, admin_notified, delivery_status";

/// Admin list: newest first, optional form filter, capped limit.
pub async fn list_submissions(
    db: &D1Database,
    form_slug: Option<&str>,
    limit: i64,
) -> Result<Vec<SubmissionRow>> {
    let limit = limit.clamp(1, 500);
    let res = match form_slug {
        Some(slug) => {
            db.prepare(&format!(
                "SELECT {SUB_COLS} FROM submissions WHERE form_slug = ?1 ORDER BY received_at DESC LIMIT ?2"
            ))
            .bind(&[slug.into(), (limit as f64).into()])?
            .all()
            .await?
        }
        None => {
            db.prepare(&format!(
                "SELECT {SUB_COLS} FROM submissions ORDER BY received_at DESC LIMIT ?1"
            ))
            .bind(&[(limit as f64).into()])?
            .all()
            .await?
        }
    };
    res.results::<SubmissionRow>()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingRow {
    pub event_id: String,
    pub form_slug: String,
    pub submitter_pubkey: String,
}

/// Submissions whose delivery is still pending — for metadata-only retry.
pub async fn pending_submissions(db: &D1Database, limit: i64) -> Result<Vec<PendingRow>> {
    let res = db
        .prepare(
            "SELECT event_id, form_slug, submitter_pubkey FROM submissions \
             WHERE delivery_status = 'pending' ORDER BY received_at ASC LIMIT ?1",
        )
        .bind(&[(limit.clamp(1, 100) as f64).into()])?
        .all()
        .await?;
    res.results::<PendingRow>()
}

// ---------- rate limiting (per form + submitter, hourly) ----------

#[derive(Debug, Deserialize)]
struct RateRow {
    count: i64,
}

/// Returns true if the submission is **under** the form's hourly cap (and
/// increments the counter); false if rate-limited.
pub async fn rate_limit_check_and_inc(
    db: &D1Database,
    form_slug: &str,
    submitter_pubkey: &str,
    now_secs: i64,
    max_per_hour: i64,
) -> Result<bool> {
    let window_start = now_secs - (now_secs % RATE_WINDOW_SECS);
    let stmt = db
        .prepare(
            "SELECT count FROM rate_limits \
             WHERE form_slug = ?1 AND submitter_pubkey = ?2 AND window_start = ?3",
        )
        .bind(&[form_slug.into(), submitter_pubkey.into(), (window_start as f64).into()])?;
    let row: Option<RateRow> = stmt.first(None).await?;
    let current = row.map(|r| r.count).unwrap_or(0);
    if current >= max_per_hour {
        return Ok(false);
    }
    db.prepare(
        "INSERT INTO rate_limits(form_slug, submitter_pubkey, window_start, count) VALUES (?1, ?2, ?3, 1) \
         ON CONFLICT(form_slug, submitter_pubkey, window_start) DO UPDATE SET count = count + 1",
    )
    .bind(&[form_slug.into(), submitter_pubkey.into(), (window_start as f64).into()])?
    .run()
    .await?;
    Ok(true)
}

// ---------- booking slots ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotRow {
    pub slot_id: String,
    pub form_slug: String,
    pub starts_at: i64,
    pub duration_min: i64,
    pub status: String,
    pub booked_event_id: Option<String>,
    pub created_at: i64,
}

const SLOT_COLS: &str = "slot_id, form_slug, starts_at, duration_min, status, booked_event_id, created_at";

/// Atomically claim a slot for `event_id`. `INSERT OR IGNORE` on the PK is
/// the double-booking guard (D1 is single-writer); the read-back confirms
/// who won, so a lost race reports `false` instead of silently succeeding.
/// Re-claiming with the same event id is idempotent (poll retries).
pub async fn claim_slot(
    db: &D1Database,
    slot_id: &str,
    form_slug: &str,
    starts_at: i64,
    duration_min: i64,
    event_id: &str,
    now: i64,
) -> Result<bool> {
    db.prepare(
        "INSERT OR IGNORE INTO slots (slot_id, form_slug, starts_at, duration_min, status, booked_event_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, 'booked', ?5, ?6)",
    )
    .bind(&[
        slot_id.into(),
        form_slug.into(),
        (starts_at as f64).into(),
        (duration_min as f64).into(),
        event_id.into(),
        (now as f64).into(),
    ])?
    .run()
    .await?;
    #[derive(Deserialize)]
    struct Winner {
        booked_event_id: Option<String>,
    }
    let row: Option<Winner> = db
        .prepare("SELECT booked_event_id FROM slots WHERE slot_id = ?1")
        .bind(&[slot_id.into()])?
        .first(None)
        .await?;
    Ok(matches!(row, Some(Winner { booked_event_id: Some(id) }) if id == event_id))
}

/// Start times of persisted (booked) slots for a form at/after `from` —
/// what the public route subtracts from the rule expansion.
pub async fn booked_starts(db: &D1Database, form_slug: &str, from: i64) -> Result<Vec<i64>> {
    #[derive(Deserialize)]
    struct Row {
        starts_at: i64,
    }
    let res = db
        .prepare("SELECT starts_at FROM slots WHERE form_slug = ?1 AND starts_at >= ?2")
        .bind(&[form_slug.into(), (from as f64).into()])?
        .all()
        .await?;
    Ok(res.results::<Row>()?.into_iter().map(|r| r.starts_at).collect())
}

/// Admin list: upcoming first, optional form filter.
pub async fn list_slots(db: &D1Database, form_slug: Option<&str>, limit: i64) -> Result<Vec<SlotRow>> {
    let limit = limit.clamp(1, 500);
    let res = match form_slug {
        Some(slug) => {
            db.prepare(&format!(
                "SELECT {SLOT_COLS} FROM slots WHERE form_slug = ?1 ORDER BY starts_at ASC LIMIT ?2"
            ))
            .bind(&[slug.into(), (limit as f64).into()])?
            .all()
            .await?
        }
        None => {
            db.prepare(&format!("SELECT {SLOT_COLS} FROM slots ORDER BY starts_at ASC LIMIT ?1"))
                .bind(&[(limit as f64).into()])?
                .all()
                .await?
        }
    };
    res.results::<SlotRow>()
}

/// Cancel a booking (frees the slot — it becomes virtual/open again).
/// Returns false if the slot id did not exist.
pub async fn delete_slot(db: &D1Database, slot_id: &str) -> Result<bool> {
    let existed: Option<serde_json::Value> = db
        .prepare("SELECT 1 AS one FROM slots WHERE slot_id = ?1")
        .bind(&[slot_id.into()])?
        .first(None)
        .await?;
    db.prepare("DELETE FROM slots WHERE slot_id = ?1")
        .bind(&[slot_id.into()])?
        .run()
        .await?;
    Ok(existed.is_some())
}

// ---------- admin set (NIP-98) ----------

pub async fn is_admin(db: &D1Database, pubkey: &str) -> Result<bool> {
    let row: Option<serde_json::Value> = db
        .prepare("SELECT 1 AS one FROM admin_pubkeys WHERE pubkey = ?1 LIMIT 1")
        .bind(&[pubkey.into()])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

#[derive(Debug, Deserialize)]
struct AdminRow {
    pubkey: String,
}

pub async fn list_admins(db: &D1Database) -> Result<Vec<String>> {
    let res = db
        .prepare("SELECT pubkey FROM admin_pubkeys ORDER BY added_at ASC")
        .all()
        .await?;
    Ok(res.results::<AdminRow>()?.into_iter().map(|r| r.pubkey).collect())
}

pub async fn add_admin(db: &D1Database, pubkey: &str, now: i64) -> Result<()> {
    db.prepare("INSERT OR IGNORE INTO admin_pubkeys(pubkey, added_at) VALUES (?1, ?2)")
        .bind(&[pubkey.into(), (now as f64).into()])?
        .run()
        .await?;
    Ok(())
}

// ---------- NIP-98 replay nonces ----------

/// Records the auth event id; returns true if it was **fresh** (accept),
/// false if it was already seen within the window (replay → reject). Prunes
/// expired nonces opportunistically.
pub async fn nonce_check_and_store(db: &D1Database, event_id: &str, now: i64) -> Result<bool> {
    db.prepare("DELETE FROM auth_nonces WHERE created_at < ?1")
        .bind(&[((now - NONCE_TTL_SECS) as f64).into()])?
        .run()
        .await?;
    let seen: Option<serde_json::Value> = db
        .prepare("SELECT 1 AS one FROM auth_nonces WHERE event_id = ?1 LIMIT 1")
        .bind(&[event_id.into()])?
        .first(None)
        .await?;
    if seen.is_some() {
        return Ok(false);
    }
    db.prepare("INSERT OR IGNORE INTO auth_nonces(event_id, created_at) VALUES (?1, ?2)")
        .bind(&[event_id.into(), (now as f64).into()])?
        .run()
        .await?;
    Ok(true)
}

// ---------- relay poll filter ----------

/// The filter the poll handler sends to the relay: NIP-44 envelopes
/// (kinds 4 / 1059) addressed to the processor since the cursor.
pub fn build_poll_filter(processor_pubkey: &str, since: i64) -> serde_json::Value {
    json!({
        "kinds": [4, 1059],
        "#p": [processor_pubkey],
        "since": since,
        "limit": 500
    })
}
