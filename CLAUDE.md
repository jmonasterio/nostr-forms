# nostr-form-rs — Project Context for AI Agents

## Deployment

**Status (verified live 2026-07-24): the form pipeline IS deployed and
running, entirely on Cloudflare.** Do not "restore" it, do not stand up a
VPS, and do not deploy this working tree over it — see the warning at the
end of this section.

### Live topology (probed, not assumed)

| Piece | Where | Evidence |
|---|---|---|
| Marketing site + forms | `executiveaiguidance.com` — CF Pages project `executiveaiguidance-com`, deployed from `../executive-ai-training` (`deploy.sh` → `wrangler pages deploy html/`) | Serves the real site; `/forms.js`, `/main.js`, `/booking.js` all 200 |
| Form SDK config | `html/main.js` → `NostrForms.init({ relayUrl: 'wss://relay.argw.com', processorPubkey: '43100984…' })` | Read from the live JS |
| Live forms | `MpAETNds` (contact), `vgFZPC9h` (booking, `data-pow="16"`), `bGFqnzYT` (newsletter) | `data-nostr-form` attrs on the live `/contact` page |
| Relay | `wss://relay.argw.com` — CF Worker + Durable Object (`../nostr-relay-rs`) | NIP-11 doc responds |
| **Form processor + admin API** | **`forms.argw.com` — a live CF Worker** | `/admin/config` → 200 JSON with the real admin + processor pubkeys; `/admin/forms`, `/admin/submissions`, `/admin/slots`, `/admin/poll-now` → 401 `unauthorized: missing or malformed Authorization header` |
| Booking widget backend | `forms.argw.com` | `booking.js` fetches it directly |

Submission path: browser NIP-44-encrypts to the processor pubkey, mines
NIP-13 PoW, publishes to `wss://relay.argw.com` tagged `#p=43100984…`; the
`forms.argw.com` Worker holds the processor key, ingests, and exposes
everything through its NIP-98-authenticated `/admin/*` API and dashboard at
`forms.argw.com/admin`.

### The deployed code is NOT this working tree

This repo's git remote *is* `github.com/jmonasterio/nostr-forms`, but what
is running on `forms.argw.com` is a different, newer implementation:

- **API shape differs.** Live: `/admin/*` with a NIP-98 `Authorization`
  header. This repo (`src/api/`): `/api/*` with a `Bearer <session token>`
  issued by an unauthenticated localhost `login` handler.
- **Live has booking.** `/admin/slots`, a Booking tab, and slot tables. This
  repo has no slots table in `src/registry/` and no booking code at all.
- **Assets differ.** Live `forms.js` is 8940 B vs this repo's 9266 B; live
  admin page is 13752 B vs this repo's `web/admin/index.html` at 30810 B.
- **Not in history.** `origin` has exactly one branch (`main`, = local
  HEAD); no commit anywhere in this repo's history contains `poll-now` or
  `admin/slots`, and no source with those routes exists anywhere under
  `C:\github`.

[INFERENCE] This Rust tree is a superseded earlier implementation. The
source that actually builds `forms.argw.com` is not on this machine — find
it before changing anything user-facing, and treat this repo as legacy
until that's resolved.

> **Do not `wrangler deploy` this repo to `forms.argw.com`.** It would
> replace a working NIP-98 + booking backend with an older Bearer-token API
> that has no slots support, breaking the live contact, booking, and
> newsletter forms on `executiveaiguidance.com`.

### The retired droplet (true, but it did not break forms)

The `argw.com` DigitalOcean droplet that once ran this Rust binary under
systemd has been closed. The old flow — `../nostr-form-rs.deploy`,
`cargo zigbuild` → `scp` → `ssh`-install → restart systemd — targets
`jm@argw.com` and is dead; `nostr-form-rs.deploy/deploy.bat` now refuses to
run. Closing it cost nothing, because forms had already been migrated to
the Cloudflare Worker above. `deploy/install.sh` here is a generic
Debian/Ubuntu installer (not argw-specific) and still works for self-hosting
this legacy tree, but it is not what runs in production.

Note: `../cf-infra/docs/nostr-stack-migration.md` still lists Phase 3
(nostr-form-rs → Worker) as unbuilt. That plan is **stale** — reality
overtook it. Trust the probes above over that document.

## Known pubkeys

| Role | Hex pubkey |
|------|-----------|
| Admin (Jorge) | `777d0ead9065a316d57773164ac4d013708f30f1235f089e12c22c4bbe4b625a` — corrected 2026-07-24 against live `forms.argw.com/admin/config`. This file previously said `…164ae4d013708…` (`ae` for `ac` at offset 24); that value is wrong and appears in other docs too. |
| Processor | `43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6` — confirmed live in `forms.argw.com/admin/config` and in the SDK config on `executiveaiguidance.com` |

## Crypto

This project implements **NIP-44 v2** exactly. As of 2026-07-24 the actual
encrypt/decrypt (and the schnorr/keypair helpers in `src/crypto/keys.rs`)
are no longer implemented in this repo — they delegate to the shared
`../nostr-crypto-rs` crate (`nostr-crypto = { path = "../nostr-crypto-rs" }`
in `Cargo.toml`), which is pure-Rust (`k256`, no `secp256k1` C bindings) and
therefore `wasm32`-clean. This is the same crate `nostr-relay` already
depends on in production on Cloudflare — one implementation, not two
drifting copies. `src/crypto/nip44.rs` and `src/crypto/keys.rs` here are now
thin wrappers kept only so call sites (`crate::crypto::{nip44, keys}::…`)
didn't have to change. **Do not re-add a parallel NIP-44/keypair
implementation in this repo** — extend `nostr-crypto-rs` instead.

Spec, for reference (implemented in `nostr-crypto-rs/src/nip44.rs`):

- `derive_conversation_key`: **HKDF-Extract only** (salt=`"nip44-v2"`, IKM=shared_x). The 32-byte PRK is the conversation key. Do NOT run Expand afterwards.
- `derive_message_keys`: **HKDF-Expand only** (PRK=conversation_key, info=nonce, L=76). Do NOT run Extract first. The nonce is `info`, not `salt`.
- Cipher: **ChaCha20** (RFC 8439, 12-byte nonce from HKDF bytes 32..44). Not XChaCha20, not AEAD.
- MAC: **HMAC-SHA256**(key=hmac_key, data=nonce‖ciphertext). Not Poly1305.
- Nonce: **32 bytes** random per message.
- Payload: `base64(version[1] | nonce[32] | ciphertext | mac[32])`.

The JS side (`web/`) uses `nostr-tools` which follows the spec. Any drift between Rust and nostr-tools means the browser encrypts messages the server can never decrypt.

The drift-gate pin against the official NIP-44 v2 test vector now lives in
`nostr-crypto-rs` (`nip44::tests::official_vector_conversation_key` /
`official_vector_full_payload`) — it must always pass **there**. This repo's
own `src/crypto/nip44.rs` tests only check the wrapper wiring (roundtrip,
garbage-input rejection), since the byte-level internals it used to test are
no longer visible outside `nostr-crypto-rs`.

This crypto swap is also step one of the Phase 3 Cloudflare Worker port
(see Deployment, above): it removes the one dependency (`secp256k1`) that
could never compile to `wasm32-unknown-unknown` in the first place. It does
**not** by itself make this binary a Worker — `tokio`, `rusqlite`, `axum`,
and `tokio-tungstenite` are all still native-only and still need the actual
`workers-rs` rewrite.

## Project structure

```
src/
├── main.rs           # Entry point, config loading
├── config.rs         # Config struct
├── crypto/
│   ├── nip44.rs      # NIP-44 v2 encrypt/decrypt
│   └── keys.rs       # Keypair generation and hex helpers
├── registry/         # Form CRUD (SQLite via rusqlite)
├── processor/        # Event ingestion, PoW verification, decryption
├── forwarder/        # DM delivery to notify_pubkey via relay
└── api/              # Axum HTTP handlers (admin API + UI)

web/
├── forms.js          # Browser SDK — NOTE: the copy embedded on the live
│                     #   site is NOT this file (see Deployment)
└── admin/            # Admin UI — likewise superseded by the live one

../nostr-form-rs.deploy/   # Sibling repo — retired argw.com deploy scripts
```

## Related repos (all siblings under C:\github\)

| Repo | Purpose |
|------|---------|
| `executive-ai-training` | **Live customer site** `executiveaiguidance.com` (CF Pages, `deploy.sh`). `html/main.js` holds the live `NostrForms.init` config; `html/contact.html` carries the three live `data-nostr-form` ids. This is the thing that breaks if the forms backend changes. |
| `nostr-form-rs.deploy` | **Retired.** SSH/scp deploy scripts + config for the closed argw.com droplet. |
| `nostr-relay` | Companion Nostr relay source (pre-migration Rust/systemd copy) |
| `nostr-relay.deploy` | **Retired.** SSH deploy scripts for the same closed droplet; the relay now deploys via `wrangler` from `nostr-relay-rs`. |
| `cf-infra` | Cloudflare migration plan + shared CF credentials/tooling; the live relay Worker moved out to `nostr-relay-rs`. Its `cf-infra/docs/nostr-stack-migration.md` Phase 3 ("nostr-form-rs → Worker") is **stale** — it describes the port as unbuilt, but a forms Worker is already live at `forms.argw.com`. |
| `nostr-crypto-rs` | Shared pure-Rust NIP-44/59/98/26 crate this repo now depends on (see Crypto). |
