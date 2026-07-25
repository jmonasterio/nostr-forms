# Recovered deployed Worker — forms.argw.com

Pulled 2026-07-25 from `GET /accounts/{id}/workers/scripts/nostr-form-rs`.
Cloudflare metadata: created 2026-06-02, **modified 2026-06-16**, `has_modules: true`,
handlers `fetch`+`scheduled`.

## Why this exists

The source crate that produced this bundle is **not on this machine**. This tree
(`C:\\github\\nostr-form-rs`) is the droplet binary — axum + tokio + rusqlite, no
`wrangler.toml` — and its module layout does not match.

Evidence from panic-location strings embedded in `index_bg.wasm`:

- Built on this box: `C:\\Users\\jorge.000\\.cargo\\registry\\...`, MSVC stable toolchain.
- Crate name: `nostr-form-rs`.
- Framework: `worker-0.8.3` / `worker-sys-0.8.3` / `wasm-bindgen-0.2.121` (workers-rs).
- Crypto: `k256-0.13.4` (schnorr), `chacha20-0.9.1`, `sha2-0.10.9`, `base64-0.22.1`.
- **Worker crate modules:** `src/admin.rs`, `src/booking_routes.rs`, `src/decrypt.rs`,
  `src/notify.rs`, `src/poll.rs`, `src/sign.rs`, `src/storage.rs`.

This tree has none of those files. Its modules are `src/api/`, `src/crypto/`,
`src/forwarder/`, `src/processor/`, `src/registry/`. Searched and NOT found:
`C:\\github` (all repos), `C:\\gitlab`, `C:\\src`, and every branch of
`github.com/jmonasterio/nostr-forms` (single branch `main`, head `d88ac69`).

## What this bundle is good for

1. **Rollback.** If someone `wrangler deploy`s over forms.argw.com, this is the
   only copy of what was there.
2. **Rebuild reference.** The module list above is the API surface to recreate.
3. `shim.js` names every exported binding and class.

Do NOT treat this as source. `index_bg.wasm` is compiled output.
