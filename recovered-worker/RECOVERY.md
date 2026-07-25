# Recovered Worker source — `forms.argw.com`

**Status: recovered, compiles to wasm32, 40/40 tests pass, deployed to staging
and diffed against live. NOT deployed to production.**

Recovered 2026-07-25 from omp agent session transcripts.

## Verified against live

Staging Worker `nostr-form-rs-v2` (workers.dev only, scratch D1, **no cron**)
was deployed from this source and compared with `forms.argw.com`:

| Route | Live | Recovered | |
|---|---|---|---|
| `/`, `/healthz` | 200 `nostr-form-rs ok` | 200 `nostr-form-rs ok` | match |
| `/admin/config` | 200 JSON | 200 JSON | match (data differs — scratch DB) |
| `/admin/forms`, `/admin/submissions`, `/admin/slots`, `/admin/poll-now` | 401 | 401 | match, identical body |
| `/booking/<unknown>/slots` | 404 | 404 | match |
| `/nonexistent` | 404 | 404 | match |

**The decisive one:** seeding the scratch D1 with the live discovery-call form's
actual `options_json` (`America/Los_Angeles`, 30 min, Mon–Fri 08:00–17:00,
2-week horizon, 1440 min notice) and hitting `/booking/vgFZPC9h/slots` on both:

```
live      180 slots   tz America/Los_Angeles
recovered 180 slots   tz America/Los_Angeles
identical slot set: true   (0 only-live, 0 only-recovered)
```

Same slot ids, same `starts_at` values. That single call exercises rule
expansion, DST offsets, horizon bounds, min-notice filtering and slot-id
generation — i.e. all of `booking.rs`, the largest recovered module.

## What happened

The Worker crate lived at `C:\github\cf-migration\src\nostr-form-rs\` — a
sibling of `src/nostr-relay`. When the relay was extracted to
`C:\github\nostr-relay-rs` on 2026-07-25, this sibling was not carried along and
the directory was lost. `cf-migration` was never a git repo, so there was no
history to recover from.

It is **not** the same crate as its parent directory (`C:\github\nostr-form-rs`),
which is the retired axum/tokio/rusqlite droplet binary and cannot compile to
wasm at all (`mio` fails immediately on `wasm32-unknown-unknown`).

## How it was recovered

`~/.omp/agent/sessions/**/*.jsonl` retain every `write` and `edit` tool call
with full file bodies. Across 5 sessions (2026-05-19 → 2026-06-14) there were
**42 writes and 21 edits** against 31 files. Replaying them chronologically —
last full write per file, then applying subsequent edit hunks — reconstructed
the crate.

## Fidelity — read this before trusting any file

| Category | Files | Confidence |
|---|---|---|
| **Verbatim** (final state was a full `write`, no later edits) | 19 | Exact |
| **Replayed** (edit hunks applied after last write) | 10 | High, compiler-verified |
| **Repaired by hand** | `lib.rs`, `admin.rs`, `examples/admin_tool.rs` | Hunks landed at drifted line numbers; splices moved back to correct scope |
| **Reimplemented** | `decrypt.rs::encrypt_bytes`, `EncryptError`, `calc_padded_len` | The edit that added them was pruned. Written as the exact inverse of `decrypt_bytes` — **validated byte-for-byte against the official NIP-44 v2 spec vectors** |
| **Refetched** | `tests/nip44_spec_vectors.json` | Data file, never in transcripts. Rebuilt from `github.com/paulmillr/nip44` |

Transcripts carry `prunedAt` markers, so some intermediate edits are simply
gone. Two consequences were found and fixed by the compiler; one remains open
(below).

### Independent corroboration

- `schema.rs` DDL matches the **live D1 schema exactly** — same 7 tables, same
  4 indexes, same column names and defaults.
- Module set matches the panic strings in the deployed WASM exactly:
  `admin booking_routes decrypt notify poll sign storage`.
- Resolved dependency versions match the deployed build: `worker 0.8.3`,
  `k256 0.13.4`, and `worker-build 0.8.3` is the installed toolchain.

## The owner-alert gap — CLOSED

`src/alerts.rs` (written 2026-06-14, the last session) was orphaned: its doc
comment referenced `notify::publish_email_alert`, which the pruned edits took
with them.

Rather than guess, the contract was read off the **consumer**, which is
authoritative and present on disk: `../../nostr-notify/src/index.ts` (`/alert`
handler) and `src/format.ts` (`AlertPayload`). That revealed `alerts.rs` is a
**superseded design** — it built email bodies here and published them as
plaintext `["l","email"]` events through the relay. The shipped design instead
POSTs structured JSON straight to the `NOTIFY` service binding, with all
rendering (subject, field order, timezone) living in nostr-notify:

```json
{ "type": "booking"|"submission", "form": "...",
  "starts_at": 1234567890, "status": "booked"|"conflict"|"invalid",
  "fields": { ... } }        // -> 202 Accepted
```

Added to `notify.rs`: `send_alert`, `alert_submission`, `alert_booking`,
`fields_of`. Wired into `poll.rs` immediately after a successful DM delivery,
awaited (nostr-notify documents that a backgrounded send is cancelled when the
cron invocation ends — that bug silently dropped booking emails once already),
and failure-isolated so a dead alert never un-delivers a submission. Conflict
and invalid outcomes recover `starts_at` from the `<slug>:<unix>` slot id so
the email still says *when*.

`alerts.rs` is kept for provenance, marked superseded, and is not on this path.

**Not end-to-end verified:** exercising it for real would send actual email to
the owner's verified inbox. The payload shape is typechecked against
`AlertPayload` by inspection, not by a live send.

## Remaining delta vs the deployed build

```
rebuilt  index_bg.wasm  621,191 bytes  (53 exports)
deployed index_bg.wasm  800,126 bytes  (51 exports)   -22.4%
```

Export-name diffs are internal `wasm-bindgen` closure indices and abort
handlers, not API surface. **The reconstruction is ~2 days behind the live
deploy** (last transcript activity 2026-06-14; live `modified_on` 2026-06-16).
Every route that could be compared behaves identically (see top), so whatever
differs is not in the HTTP surface or the booking engine.

## Fixes applied during recovery

1. `Cargo.toml` is the 2026-05-20 original and was never rewritten in the
   transcripts, so it had drifted. Removing the stale `"http"` feature from
   `worker` fixed 10 of 16 compile errors at once (`fetch_request` returns
   `worker::Response`, which has `status_code()`/`text()`; the `http` feature
   swaps it for `http::Response`, which does not). Also pinned `=0.8.3` and
   added `rlib` so integration tests can link.
2. `sign.rs` — `sign_raw` takes `(msg, aux_rand)` in k256 0.13.4; recovered
   call passed one arg. Uses zero aux_rand (deterministic, BIP-340 valid).
3. `admin.rs` — `Method::Report` arm added (exists in worker 0.8.3).

## Build and test

```bash
cargo test                                   # 40 pass
cargo check --target wasm32-unknown-unknown  # clean
worker-build --release                       # -> build/
```

## Deploying — do NOT overwrite live

`forms.argw.com` is **healthy**: cron ticking every minute, 15/15 submissions
`delivered`, three active forms serving `executiveaiguidance.com`. There is no
outage to fix.

Safe procedure when a change is actually needed:

1. Copy `wrangler.toml` to a staging name (`nostr-form-rs-v2`), **remove the
   custom domain**, point `FORMS` at a scratch D1, keep workers.dev only.
2. `wrangler secret put PROCESSOR_NSEC` / `ADMIN_INTERNAL_TOKEN` with test values.
3. Deploy, then diff every route against live: `/`, `/admin/config`,
   `/booking/<slug>/slots`, and the NIP-98-gated `/admin/*` set.
4. Close the `alerts.rs` gap first — otherwise cutting over silently drops the
   owner email-alert path that the live Worker has.
5. Only then re-point `forms.argw.com`.

`../deployed-worker-2026-06-16/` holds the live bundle as a rollback.
