# nostr-form-rs — Admin UI + encrypted delivery (Phase 3.5)

Status: **in progress**. Builds on the live Cloudflare deployment of
`nostr-form-rs` (worker `nostr-form-rs`, D1 `nostr-form-rs`
`f4dc3389-d2e4-4119-a196-510c97ebe585`, service binding → `nostr-relay`,
cron `* * * * *`). This document is the contract; every decision below was
agreed before implementation.

## Goal

Restore the form-owner experience the droplet had, done properly on CF:

1. **See submissions two ways**, both decrypting with one key (the owner's
   Nostr key, held only in a NIP-07 extension):
   - **Push:** each submission delivered as an **encrypted Nostr DM**.
   - **Pull:** a browsable/searchable **`/admin` dashboard**.
2. **Forms-aware routing** (per-form notify pubkey, PoW, rate limit,
   active/disabled) — full parity with the droplet, replacing today's
   catch-all single-`ADMIN_PUBKEY` behavior.
3. **No plaintext secrets in the browser; no readable submission content at
   rest.**

## Background: how the droplet worked (so intent is clear)

- Browser SDK (`forms.js`) NIP-44-encrypts the form payload to the
  **processor pubkey**, mines NIP-13 PoW, publishes to the relay tagging
  the processor via `#p`.
- Processor decrypts, stores the submission, and **delivers it to the
  form's `notify_pubkey` as a Nostr DM** (the primary inbox).
- An admin UI (`web/admin/`) browsed the stored copy.

The current CF port diverges: it only sends a **200-char plaintext kind-4
summary** to a single `ADMIN_PUBKEY`, has **no UI**, and **ignores the
forms registry** (catch-all slug). This phase fixes all three.

## Decisions

### Architecture
- **D1.1** Admin UI is **served by the worker at `/admin`** (static
  HTML/JS embedded via `include_str!` — single deploy artifact, no asset
  binding). Same-origin ⇒ no CORS. Reachable from any device; it is a
  public URL, gated by auth (D2.x).
- **D1.2** UI is minimal vanilla JS. It uses only the **NIP-07** browser
  API (`window.nostr`): `signEvent` (for NIP-98 auth) and `nip44.decrypt`
  (to read submissions). No heavyweight bundled libraries.
- **D1.3** The worker stays a single Rust→wasm worker. New modules:
  `nip98.rs` (HTTP auth verify), `nip44.rs` gains **encrypt** (currently
  decrypt-only), `admin.rs` (API + UI routing), `seal.rs` (NIP-17 wrap).

### Authentication (the security boundary)
- **D2.1** Every admin endpoint (reads included) is gated by **NIP-98**
  (`Authorization: Nostr <base64 kind-27235 event>`). The worker verifies:
  BIP-340 Schnorr signature (via `k256`, reused from decrypt/sign), the
  `u` tag == exact request URL, the `method` tag == HTTP method, the
  `payload` tag == hex SHA-256 of the request body (for writes),
  `created_at` within **±60 s**, and **pubkey ∈ admin set**.
- **D2.2** **Replay protection:** the NIP-98 event `id` is recorded in an
  `auth_nonces` D1 table; a repeat within the window is rejected. Old rows
  pruned opportunistically.
- **D2.3** **Admin set** is multiple pubkeys (table `admin_pubkeys`,
  cleartext). Seeded with `777d0ead…`. Multiple keys = no lockout if one
  is lost.
- **D2.4** The **processor private key** (`PROCESSOR_NSEC`) stays a worker
  secret and is **never** sent to the browser. The **admin key** lives
  only in the NIP-07 extension; the worker only ever sees its pubkey.
- **D2.5** `POST /admin/poll-now` is moved **behind** the NIP-98 gate
  (currently open). `GET /healthz` stays open. `GET /admin/config`
  (returns processor pubkey + admin set, all public data) stays open so
  the UI can bootstrap before the user signs in.
- **D2.6** **Cloudflare Access** in front of `/admin*` is documented as
  optional defense-in-depth; not configured by code (dashboard-only).

### Data model
- **D3.1** `forms` (routing config, **cleartext** — not sensitive):
  `slug PK, name, notify_pubkey, pow_difficulty, rate_limit_per_hour,
  delivery_mode, status, options_json, created_at, updated_at`.
- **D3.2** `submissions` columns **split by sensitivity**:
  - Cleartext index: `event_id PK, form_slug, submitter_pubkey,
    created_at, received_at, admin_notified, delivery_status`.
  - **Encrypted payload:** `sealed_json` — the submission plaintext
    **NIP-44-encrypted from the processor key to the dashboard admin
    pubkey**. No cleartext content column.
- **D3.3** `rate_limits` and `cursors` unchanged. New `auth_nonces`
  (`event_id PK, created_at`) and `admin_pubkeys` (`pubkey PK, added_at`).
- **D3.4** **At-rest encryption recipient = the dashboard admin pubkey**
  (configurable; defaults to `ADMIN_PUBKEY` / first `admin_pubkeys` row).
  The dashboard decrypts via NIP-07 `nip44.decrypt(processorPubkey,
  sealed_json)`. The worker encrypts with the processor secret (ECDH with
  the admin pubkey) — same conversation key, opposite direction.
- **D3.5 Consequence (accepted):** submission **content is not queryable
  server-side** (it's ciphertext). The index columns support
  list/filter/dedupe by form, sender, time. Content search happens
  in-browser after decryption.

### Routing (forms-aware poll)
- **D4.1** Poll reads the slug from the decrypted payload field
  **`form_id`** (the real client field, per captured submissions), falling
  back to `_form`, then `"default"`.
- **D4.2** Look up the form in `forms`. If missing or `status !=
  'active'` → reject (counted), no store, no DM. (A row with
  `slug='default'` can be created to keep a catch-all.)
- **D4.3** Enforce **per-form** `pow_difficulty` and
  `rate_limit_per_hour`; PoW is recomputed against the form's threshold
  (defense-in-depth even though the relay also gates).
- **D4.4** Routing only ever reads **cleartext** `forms` + metadata; the
  encrypted payload is the *output* of routing (written last), never an
  input.

### Delivery
- **D5.1** Default delivery is **NIP-17 private DM (kind 1059 gift-wrap)**
  carrying the **full** submission, sent to the form's `notify_pubkey`.
  This is the standard, client-renderable private DM; the relay's poll
  filter already anticipates kind 1059. Implemented in `seal.rs`
  (kind-14 chat → kind-13 seal → kind-1059 gift wrap, ephemeral key,
  timestamp fuzzing per NIP-17).
- **D5.2** Per-form `delivery_mode`:
  - `full` (default): NIP-17 DM with full content.
  - `notify`: metadata-only NIP-04 DM ("new submission for <form> from
    <sender> — open the dashboard"). Used for low-trust recipients or to
    keep full content only in the dashboard.
- **D5.3** **Notification retry** (failed delivery) uses **metadata only**
  — never rebuilds content from D1 (it's admin-sealed, not
  recipient-decryptable by the worker). Full content remains available in
  the dashboard.
- **D5.4** Outbound events are published through the existing relay
  service binding `POST /admin/publish` (token-gated, already wired).

### Migration (from `backups/argw/extracted/nostr-form-rs/forms.db`)
- **D6.1** Migrate the **7 forms** (config) → D1 `forms`
  (`form_id`→`slug`, `notify_pubkey`, `pow_difficulty`,
  `rate_limit_per_hour`, `status`; `delivery_mode='full'`,
  `options_json='{}'`). Required for routing parity.
- **D6.2** Migrate `admin_pubkeys` (`777d0ead…`) → D1 `admin_pubkeys`.
- **D6.3** Migrate the **5 historical submissions** into the archive:
  re-encrypt each `decrypted_content` to the admin pubkey → `sealed_json`,
  preserve original timestamps, set `admin_notified=1`,
  `delivery_status='migrated'` so **no DMs are re-sent**. Lower priority;
  archive completeness only.

### Hosting / ops
- **D7.1** Keep `workers_dev = true` for now (`/admin` reachable at the
  workers.dev URL). Optional later: bind `forms.argw.com` as a Worker
  Custom Domain (same API-side procedure used for `relay.argw.com`, since
  the token can't edit zone routes).
- **D7.2** `ADMIN_INTERNAL_TOKEN` (shared with the relay) and
  `PROCESSOR_NSEC` remain worker secrets. `ADMIN_PUBKEY` var becomes the
  default at-rest recipient + bootstrap admin.

### Crypto reuse / additions
- **D8.1** Schnorr **verify** for NIP-98: add to a small `nip98.rs` using
  `k256::schnorr::VerifyingKey` (already a dependency).
- **D8.2** Add **`nip44_v2_encrypt`** to the worker (promote from the
  test-only encrypt) for at-rest sealing and DM content.
- **D8.3** All new crypto is covered by unit tests (vectors +
  round-trips), run natively (no wasm) like the existing suite.

## Residual risks (documented, accepted)
- **CF account compromise** can delete data / change config even with
  at-rest encryption (confidentiality ≠ integrity/availability).
  Mitigation: account 2FA, least-privilege API tokens, optional CF Access.
- **Admin key loss** = lockout. Mitigation: register multiple admin
  pubkeys (D2.3); keep a backup.
- **NIP-07 extension compromise** = admin access (inherent to key-based
  auth).
- **Replay inside the ±60 s window** mitigated by the nonce store (D2.2).

## Implementation phases (verify each before next)
- **A. Crypto foundations** — `nip44_v2_encrypt`, `nip98` verify +
  Schnorr verify, `seal.rs` (NIP-17). Unit tests green.
- **B. Schema + migration** — new/extended tables; migrate forms +
  admin_pubkeys (+ historical submissions). Verify row counts.
- **C. Routing rewrite** — forms-aware poll, `form_id` field, per-form
  gates, at-rest sealing, NIP-17 delivery. Re-verify the real-envelope
  decrypt + a routed test submission.
- **D. Admin API** — NIP-98-gated CRUD (`/admin/forms`,
  `/admin/submissions`, `/admin/poll-now`, public `/admin/config`).
- **E. Admin UI** — static `/admin` page: NIP-07 sign-in, forms CRUD,
  submissions list + in-browser decrypt.
- **F. Deploy + verify** — deploy, NIP-98 happy/again-rejected paths,
  end-to-end submission → DM + dashboard view.
