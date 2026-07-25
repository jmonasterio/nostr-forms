# nostr-form-rs (Cloudflare Worker)

Nostr form processor + booking ("Calendly clone") + admin dashboard.
Successor to the Rust daemon that ran on argw. Browsers encrypt form
submissions to a processor pubkey and publish them to the relay; this
Worker polls, decrypts, stores them **encrypted at rest** in D1, and
delivers each as an encrypted Nostr DM. The owner reads/manages everything
from a NIP-98-gated web dashboard.

## Status

**Live.** Worker `nostr-form-rs`, D1 `nostr-form-rs`
(`f4dc3389-d2e4-4119-a196-510c97ebe585`), service binding → `nostr-relay`,
cron `* * * * *`. Admin dashboard at **https://forms.argw.com/admin**
(Custom Domain) and the `*.workers.dev` URL.

Design contracts: `ADMIN-UI-PLAN.md` (auth, encrypt-at-rest, delivery) and
`BOOKING-PLAN.md` (slot math).

## Flows

```
Inbound (cron, every minute):
  browser ──NIP-44 encrypt to PROCESSOR_PUBKEY──▶ relay (kind 4/1059, #p=processor, PoW)
     this worker:  /admin/poll (service binding) → decrypt → resolve form (form_id)
                   → PoW + per-form rate limit → SEAL to ADMIN_PUBKEY → INSERT (D1)
                   → deliver: NIP-17 gift wrap → notify_pubkey  via /admin/publish

Admin (HTTP, NIP-98-gated):
  browser (nostr-universal login) ──Authorization: Nostr <kind-27235>──▶ /admin/*
                   forms CRUD · submissions (decrypted server-side) · poll-now
```

## Security model (see ADMIN-UI-PLAN.md)

- **Auth:** every `/admin/*` call (except the static UI + public
  `/admin/config`) is verified with **NIP-98** — signature, exact
  method+URL, body hash, freshness, pubkey ∈ `admin_pubkeys`, and a
  replay-nonce check (`auth_nonces`).
- **Encrypt at rest:** submission payloads are stored only as
  `sealed_json` — NIP-44 from the processor key to `ADMIN_PUBKEY`. D1 holds
  no plaintext (a DB-only leak is useless). Cleartext index columns
  (`form_slug`, `submitter_pubkey`, timestamps) support listing/filtering.
- **Reading submissions:** decrypted **server-side** with the processor key
  (the seal's conversation key is symmetric) and returned over the
  authenticated `/admin/submissions` call — so it works with any signer,
  not just NIP-44-capable ones. (The browser `nip44Decrypt` path also
  exists in the vendored `nostr-universal` and can be re-enabled.)
- **Delivery:** `delivery_mode=full` → NIP-17 gift wrap with the full
  submission to the form's `notify_pubkey`; `notify` → metadata-only DM.
  Failed deliveries retry metadata-only.

## D1 schema (`schema.rs` / `migrate.sql`)

`forms` (routing config: slug, notify_pubkey, pow_difficulty,
rate_limit_per_hour, delivery_mode, status, options_json) ·
`submissions` (index cols + `sealed_json`) · `rate_limits` (per form+sender,
hourly) · `cursors` (relay poll high-water mark) · `admin_pubkeys`
(NIP-98 admin set) · `auth_nonces` (replay guard).

`ensure_schema` runs the `IF NOT EXISTS` DDL on every request; `migrate.sql`
reshapes pre-3.5 tables and seeds forms + admin pubkey.

## Config

`wrangler.toml` `[vars]`: `PROCESSOR_PUBKEY`, `ADMIN_PUBKEY` (at-rest
recipient + bootstrap admin), `DEFAULT_POW_BITS`. Bindings: D1 `FORMS`,
service `RELAY` → `nostr-relay`.

Secrets (`wrangler secret put`):

```bash
wrangler secret put PROCESSOR_NSEC          # processor private key (hex)
wrangler secret put ADMIN_INTERNAL_TOKEN    # MUST match the relay's value
```

## Build / test

```bash
cd src/nostr-form-rs
worker-build --release         # wasm build (wrangler runs this on deploy)
cargo test                     # nip44 round-trip + spec vectors, nip98 auth, nip17 gift wrap
```

`examples/admin_tool.rs` is a dev helper (keypair / nip98 header / nip42
auth event / nip44 encrypt-decrypt / mined submission) used for
end-to-end verification.

## Deploy

Same account as `nostr-relay`; the `RELAY` service binding needs both
Workers deployed.

```bash
cd src/nostr-form-rs
NODE_OPTIONS=--dns-result-order=ipv4first wrangler deploy
```

- IPv6 black-holes on this LAN — wrangler may fail the first 1–4 calls;
  the `ipv4first` flag + a retry clears it.
- First-time D1: `wrangler d1 create nostr-form-rs`, paste the id into
  `wrangler.toml`, then `wrangler d1 execute nostr-form-rs --remote
  --file=migrate.sql`.
- `forms.argw.com` is a Workers Custom Domain attached via the account API
  (the deploy token can't edit zone routes; `wrangler deploy` logs a
  harmless route-auth error after uploading).

## Admin

Open **https://forms.argw.com/admin**, sign in with a NIP-07 extension,
remote signer (NIP-46), or key via the bundled `nostr-universal` login.
The signing pubkey must be in `admin_pubkeys`. Manage forms and read
decrypted submissions.
