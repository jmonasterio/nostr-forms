//! D1 schema (Phase 3.5). Sensitivity-split per ADMIN-UI-PLAN.md:
//! - `forms` — routing config, cleartext (not sensitive).
//! - `submissions` — cleartext index columns + `sealed_json`
//!   (NIP-44-encrypted-to-admin payload; never plaintext at rest).
//! - `rate_limits` — per-form, per-submitter sliding window.
//! - `cursors` — relay poll high-water mark.
//! - `admin_pubkeys` — NIP-98 admin set.
//! - `auth_nonces` — NIP-98 replay guard (seen event ids).
//!
//! `ensure_schema` runs these `IF NOT EXISTS` on every poll/request; the
//! one-time `migrate.sql` reshapes any pre-Phase-3.5 tables.

pub const DDL_STATEMENTS: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS forms (
        slug                 TEXT PRIMARY KEY,
        name                 TEXT NOT NULL DEFAULT '',
        notify_pubkey        TEXT NOT NULL,
        pow_difficulty       INTEGER NOT NULL DEFAULT 16,
        rate_limit_per_hour  INTEGER NOT NULL DEFAULT 100,
        delivery_mode        TEXT NOT NULL DEFAULT 'full',
        status               TEXT NOT NULL DEFAULT 'active',
        options_json         TEXT NOT NULL DEFAULT '{}',
        created_at           INTEGER NOT NULL,
        updated_at           INTEGER NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS submissions (
        event_id         TEXT PRIMARY KEY,
        form_slug        TEXT NOT NULL,
        submitter_pubkey TEXT NOT NULL,
        sealed_json      TEXT NOT NULL,
        created_at       INTEGER NOT NULL,
        received_at      INTEGER NOT NULL,
        admin_notified   INTEGER NOT NULL DEFAULT 0,
        delivery_status  TEXT NOT NULL DEFAULT 'pending'
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_submissions_slug      ON submissions(form_slug)",
    "CREATE INDEX IF NOT EXISTS idx_submissions_submitter ON submissions(submitter_pubkey)",
    "CREATE INDEX IF NOT EXISTS idx_submissions_received  ON submissions(received_at)",
    r#"CREATE TABLE IF NOT EXISTS rate_limits (
        form_slug        TEXT NOT NULL,
        submitter_pubkey TEXT NOT NULL,
        window_start     INTEGER NOT NULL,
        count            INTEGER NOT NULL,
        PRIMARY KEY (form_slug, submitter_pubkey, window_start)
    )"#,
    r#"CREATE TABLE IF NOT EXISTS cursors (
        name       TEXT PRIMARY KEY,
        value      INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS admin_pubkeys (
        pubkey   TEXT PRIMARY KEY,
        added_at INTEGER NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS auth_nonces (
        event_id   TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
    )"#,
    // Booking mode (BOOKING-PLAN.md): only *booked* slots are persisted;
    // open slots are virtual (expanded from forms.options_json rules at
    // read time). slot_id is deterministic: `<form_slug>:<starts_at_unix>`.
    // The PK is the double-booking guard (INSERT OR IGNORE claim).
    r#"CREATE TABLE IF NOT EXISTS slots (
        slot_id         TEXT PRIMARY KEY,
        form_slug       TEXT NOT NULL,
        starts_at       INTEGER NOT NULL,
        duration_min    INTEGER NOT NULL,
        status          TEXT NOT NULL DEFAULT 'booked',
        booked_event_id TEXT,
        created_at      INTEGER NOT NULL
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_slots_form_start ON slots(form_slug, starts_at)",
];
