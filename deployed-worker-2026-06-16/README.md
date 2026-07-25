# The live `forms.argw.com` Worker — recovered bundle + reconstructed spec

Pulled 2026-07-25 from `GET /accounts/{id}/workers/scripts/nostr-form-rs`.
Cloudflare metadata: created 2026-06-02, **modified 2026-06-16**,
`has_modules: true`, handlers `fetch` + `scheduled`.

## Status: WORKING. Do not rebuild, do not redeploy over it.

Verified 2026-07-25 against the live D1 (`FORMS`, `f4dc3389-…`):

- Cron last ran **8 seconds** before the check (`cursors.envelope_since`
  `updated_at`), so the every-minute tick is healthy.
- **15 submissions, all `admin_notified=1`, all `delivery_status='delivered'`.**
  Zero pending, zero failed. Most recent real submission 2026-07-23, delivered.
- All three `executiveaiguidance.com` forms are `status='active'` and their slugs
  are wired into the live pages: `contact.html` carries all three,
  `index.html` / `about.html` carry the newsletter.
- `/admin/config` → 200 with the real admin + processor pubkeys; every other
  `/admin/*` route → 401 `unauthorized: missing or malformed Authorization header`.

## Why this directory exists

The source crate that produced this bundle is **not on this machine**, and is not
`..` (the parent tree). That tree is the retired droplet binary — axum + tokio +
rusqlite, no `wrangler.toml`.

Evidence from panic-location strings inside `index_bg.wasm`:

- Built on this box: `C:\Users\jorge.000\.cargo\registry\...`, MSVC stable toolchain.
- Crate name `nostr-form-rs`; framework `worker-0.8.3` / `worker-sys-0.8.3` /
  `wasm-bindgen-0.2.121`; crypto `k256-0.13.4`, `chacha20-0.9.1`, `sha2-0.10.9`.
- **Worker modules:** `src/admin.rs`, `src/booking_routes.rs`, `src/decrypt.rs`,
  `src/notify.rs`, `src/poll.rs`, `src/sign.rs`, `src/storage.rs`.

The parent tree has none of those; its modules are `api/ config.rs crypto/
forwarder/ processor/ registry/`. Searched and not found: all of `C:\github`,
`C:\gitlab`, `C:\src`, and every branch of `github.com/jmonasterio/nostr-forms`
(one branch, `main`, head `d88ac69`).

**`wrangler deploy` from the parent directory would destroy the live service.**

## Contents

| File | What |
|---|---|
| `shim.js` | 48 KB ESM entry emitted by `worker-build` |
| `de07d22…-index_bg.wasm` | 800 KB; validates — 152 imports, 51 exports |

Rollback: re-upload both as a `multipart/form-data` script PUT with
`shim.js` as the main module.

---

# Reconstructed deployment contract

Everything below is read from the live account, not guessed. It is enough to
rebuild `wrangler.toml` and the storage layer exactly.

## Bindings

```toml
name = "nostr-form-rs"
main = "build/worker/shim.mjs"      # worker-build output
compatibility_date = "2025-01-01"

[[d1_databases]]
binding = "FORMS"
database_id = "f4dc3389-d2e4-4119-a196-510c97ebe585"

[[services]]
binding = "RELAY"
service  = "nostr-relay"
environment = "production"

[[services]]
binding = "NOTIFY"
service  = "nostr-notify"
environment = "production"

[triggers]
crons = ["* * * * *"]

[vars]
ADMIN_PUBKEY     = "777d0ead9065a316d57773164ac4d013708f30f1235f089e12c22c4bbe4b625a"
PROCESSOR_PUBKEY = "43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6"
DEFAULT_POW_BITS = "16"

# secrets (wrangler secret put):
#   PROCESSOR_NSEC         -- the processor identity's private key
#   ADMIN_INTERNAL_TOKEN   -- shared with nostr-relay-rs for /admin/poll
```

Custom domain: `forms.argw.com` (zone `argw.com`, cert `8b5ac743-…`).

## D1 schema (live, verbatim)

```sql
CREATE TABLE forms (
    slug                TEXT PRIMARY KEY,
    name                TEXT NOT NULL DEFAULT '',
    notify_pubkey       TEXT NOT NULL,
    pow_difficulty      INTEGER NOT NULL DEFAULT 16,
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 100,
    delivery_mode       TEXT NOT NULL DEFAULT 'full',
    status              TEXT NOT NULL DEFAULT 'active',
    options_json        TEXT NOT NULL DEFAULT '{}',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE submissions (
    event_id         TEXT PRIMARY KEY,
    form_slug        TEXT NOT NULL,
    submitter_pubkey TEXT NOT NULL,
    sealed_json      TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    received_at      INTEGER NOT NULL,
    admin_notified   INTEGER NOT NULL DEFAULT 0,
    delivery_status  TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE slots (
    slot_id         TEXT PRIMARY KEY,
    form_slug       TEXT NOT NULL,
    starts_at       INTEGER NOT NULL,
    duration_min    INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'booked',
    booked_event_id TEXT,
    created_at      INTEGER NOT NULL
);

CREATE TABLE rate_limits (
    form_slug        TEXT NOT NULL,
    submitter_pubkey TEXT NOT NULL,
    window_start     INTEGER NOT NULL,
    count            INTEGER NOT NULL,
    PRIMARY KEY (form_slug, submitter_pubkey, window_start)
);

CREATE TABLE admin_pubkeys (pubkey TEXT PRIMARY KEY, added_at INTEGER NOT NULL);
CREATE TABLE auth_nonces  (event_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE cursors      (name TEXT PRIMARY KEY, value INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE INDEX idx_slots_form_start       ON slots(form_slug, starts_at);
CREATE INDEX idx_submissions_received   ON submissions(received_at);
CREATE INDEX idx_submissions_slug       ON submissions(form_slug);
CREATE INDEX idx_submissions_submitter  ON submissions(submitter_pubkey);
```

`cursors` holds one row, `envelope_since` — the relay poll watermark.
(`_cf_KV` is Cloudflare's own table; not application state.)

## Routes (from the WASM string table)

| Route | Auth |
|---|---|
| `GET /` | open — returns `nostr-form-rs ok` |
| `/forms`, `/forms/<slug>` | open |
| `/slots`, `/slots/<id>`, `/booking/…` | open |
| `GET /admin/config` | **open** — returns `{admins:[…], processor_pubkey:…}` |
| `/admin/forms` | NIP-98, admin pubkey |
| `/admin/submissions` | NIP-98, admin pubkey |
| `/admin/slots` | NIP-98, admin pubkey |
| `/admin/publish`, `/admin/booking` | NIP-98, admin pubkey |
| `/admin/poll`, `/admin/poll-now` | NIP-98 or `ADMIN_INTERNAL_TOKEN` |
| `/admin/nostr-universal` | admin UI asset |

Observed error strings: `unauthorized: missing or malformed Authorization
header`, `rate limited`, `not found`, `PoW for …`, `slot_conflict`,
`slot_invalid`, nonce `missing or older than 24 h`.

## Behaviour

- **Ingest** is pull, not push: the every-minute cron reads `cursors.envelope_since`,
  polls the `RELAY` service binding for NIP-59 gift-wrapped envelopes addressed to
  `PROCESSOR_PUBKEY`, unwraps with `PROCESSOR_NSEC`, and writes `submissions`.
- **Delivery** re-seals to `forms.notify_pubkey` and hands off to the `NOTIFY`
  service binding, flipping `admin_notified` / `delivery_status`.
- **Anti-abuse:** `DEFAULT_POW_BITS = 16` NIP-13 PoW per submission,
  `rate_limits` per (form, submitter, hour), `auth_nonces` replay protection
  with a 24 h window.

## If it ever must be rebuilt

Start here, not from the parent tree. The parent already did the hard
prerequisite — crypto moved to the wasm-clean `nostr-crypto` crate
(`../nostr-crypto-rs`), so NIP-44/59/98 can be reused as-is. What must be
replaced is everything the droplet assumed: `axum` → `worker::Router`,
`rusqlite` → `worker::D1Database`, `tokio` tasks → the `scheduled` handler,
`tokio-tungstenite` → the `RELAY` service binding.

Deploy the rebuild to a **throwaway Worker name first** and diff it against the
live one. Never test against `forms.argw.com`.
