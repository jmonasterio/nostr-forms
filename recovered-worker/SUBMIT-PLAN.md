# Plan: direct form submission, no relay polling (2026-11-17)

## Outcome (2026-11-17): done

| Check | Result |
|---|---|
| `cargo test` | 47 pass (7 new in `submit.rs`: valid envelope, wrong `#p`, wrong kind, `created_at` ±10 min both ways, tampered content, foreign signature, oversized/malformed body) |
| `web` vitest | 5 pass |
| Staging, real `forms.js` in Chromium from `localhost:8766` | `OPTIONS` 204, `POST /submit` 200, row in scratch D1. DM step 403: staging's `ADMIN_INTERNAL_TOKEN` differs from the relay's |
| CORS from another origin | no `Access-Control-Allow-Origin` |
| Production Worker deploy (cron still on), site deploy, contact form on executiveaiguidance.com | 200, success message shown, live row `MpAETNds` `delivered`, `admin_notified=1` |
| Production deploy without the poll, cron removed | `schedules` API returns `[]`; newsletter form on the live site → 200, row `bGFqnzYT` `delivered` |

Differences from the plan below:

- The relay `RELAY` binding stays: NIP-17 DMs to each form's `notify_pubkey`
  are published through relay `/admin/publish`. Only `/admin/poll` lost its
  caller; removing it from `nostr-relay-rs` is a separate relay change, not
  done here.
- The owner email is now sent whether or not the DM succeeded (before, a DM
  failure suppressed it). Failed DMs stay `pending`; `/admin/poll-now` became
  `POST /admin/retry-pending` ("Retry pending DMs" in the dashboard).
- `/submit` answers once the row is stored; the DM and owner email run after
  the response under `ctx.wait_until` (`process::deliver`). It also skips
  `ensure_schema` (8 DDL round trips). Staging: ~0.3 s from POST to response.
- PoW stays at 16 bits. The SDK miner hashes candidates in batches of 1024
  with WebCrypto in parallel (0.5–2.6 s in 4 desktop runs, against 1–3 s and
  more before), and the site shows "sent" on click (`optimistic: true`) and
  rolls back to the form with the error message if the POST fails.
- Per-IP cap: 20/hour across forms (`rate_limits` rows with slug `_submit_ip`).
- `wrangler deploy` with no `[triggers]` left the old cron in place; it was
  removed with `PUT …/workers/scripts/nostr-form-rs/schedules []`, and
  `wrangler.toml` now pins `crons = []`.
- The uncommitted adaptive poll gate was parked in branch `poll-gate-wip`
  (also `git stash`), never deployed.
- cf-jobs `AGENTS.md` and `wrangler.toml` record the freed slot (4 of 5 used).

## Why this plan exists

The forms on executiveaiguidance.com have not delivered a submission since
2026-07-25. Checked 2026-11-17:

- Live D1 `nostr-form-rs`: 16 submissions; the newest has `received_at` 1785006049
  (2026-07-25 19:00 UTC). `cursors.envelope_since` is still 1785005994, and its
  `updated_at` is current, so the cron is running and finding nothing.
- `nostr-relay-rs` commit `52e1acc` (2026-07-26) deleted the anonymous deposit
  path: "auth-required is the honest refusal; retire PoW".
  `ingest::local_gate` accepts a write only from a NIP-42 local socket or an
  event signed by a local key.
- `web/forms.js` (and the site copy `executive-ai-training/html/forms.js`)
  signs each submission with a throwaway key and publishes it to
  `wss://relay.argw.com` over an anonymous socket.
- A probe on 2026-11-17 (throwaway key, kind 4, anonymous socket) got
  `["OK", …, false, "auth-required: authenticate as a relay pubkey to publish"]`.

So every submission since 2026-07-26 has been refused by the relay. Whether
`forms.js` shows the visitor an error was not checked; `publishEvent` rejects on
`OK false`, so `onError` should fire.

That same polling design is also the cost question that started this: the cron
`* * * * *` is ~1,440 of the Worker's 1,477–1,957 requests/day, and each poll
costs `nostr-relay` one Worker request and one DO request.

## Decision: submit straight to this Worker

The browser POSTs the signed, PoW-mined event to `https://forms.argw.com/submit`.
This Worker validates it and runs the same per-event processing the poll runs
today (decrypt, store in D1, alert through `NOTIFY`). The relay is no longer in
the submission path.

| | Relay exception (muthr's msg 202743) | Direct POST (this plan) |
|---|---|---|
| Relay write policy | New unauthenticated write rule on the relay | Unchanged |
| Cron | Stays (`*/10` at best, bound by the relay's 15-min lookback) | Removed; frees 1 of the 5 account cron slots |
| Requests/day | ~144 cron + ~144 relay poll pairs | One request per real submission |
| Latency | Up to the poll interval | Synchronous; the visitor's request is the delivery |
| Failure the visitor sees | None (relay `OK true`, processing later) | The POST response (200 or error) |
| Code touched | `nostr-relay-rs` ingest, `nostr-form-rs` unchanged | `nostr-form-rs` route + `forms.js` publish step |

The relay push hook from the earlier discussion is dropped: with no relay in the
path there is nothing to push.

muthr's msg 202743 was a paste-ready prompt for a relay change; the desk
intake rated it `stop` and nothing in it was run. Its diagnosis matched what the
PC checks above found.

## Work

### 1. Reconcile the uncommitted source (blocker for any deploy)

`recovered-worker` has uncommitted changes in `admin.rs`, `lib.rs`, `poll.rs`,
`storage.rs` and the untracked `poll_schedule.rs` (adaptive poll gate). The live
script was last modified 2026-06-16; its wasm contains none of `poll_gate`,
`idle_streak` or `poll_schedule`.

- Delete `poll_schedule.rs` and the gate code it needs in `poll.rs` /
  `storage.rs`: the cron it throttles is removed in step 4.
- Keep the wall-clock cursor change (committed 2026-07-28) only while the poll
  still exists; it goes in step 4 with the poll.
- `cargo test` (host) and `worker-build --release` must pass before step 2.

### 2. `POST /submit` in the Worker

- Route in `lib.rs` next to `/healthz`. CORS: `Access-Control-Allow-Origin` for
  the site origins that host forms (`https://executiveaiguidance.com`, plus
  `www.` if served), `OPTIONS` preflight.
- Body: one Nostr event JSON, max 64 KB.
- Checks, in order, each a 4xx with a short reason:
  1. Parses as an event; `id` recomputes; BIP-340 signature verifies.
  2. `kind` and `#p` match what the poll accepts today (processor pubkey from `[vars]`).
  3. PoW: leading zero bits of `id` ≥ `powDifficulty` (16, matching `forms.js`).
     `pow.rs` already exists in the crate.
  4. `created_at` within ±10 min of now.
  5. Per-IP rate limit using the existing `rate_limits` table
     (`CF-Connecting-IP`), e.g. 5/hour.
  6. Duplicate `event_id`: return 200 with `duplicate: true` and do nothing else.
- Then call the per-event function the poll uses (extract it from `poll.rs` so
  poll and submit share one code path), and return 200 once the row is stored.
  Alert delivery runs under `ctx.wait_until` so a slow `nostr-notify` does not
  hold the visitor's request.

### 3. `forms.js` publish step

- `publishEvent(event, relayUrl)` becomes `fetch(submitUrl, {method: 'POST', body})`.
  New option `submitUrl` (default `https://forms.argw.com/submit`); `relayUrl`
  is removed.
- Update `web/forms.test.js`, then copy the file to
  `executive-ai-training/html/forms.js` and drop `relayUrl` from that site's
  `main.js`. The site deploys through its existing Pages flow.

### 4. Remove the poll

After step 3 is live and a real submission has gone through `/submit`:

- Delete `[triggers] crons`, the `scheduled` handler, `poll.rs`,
  `/admin/poll-now`, the `RELAY` service binding and `cursors.envelope_since`.
- In `nostr-relay-rs`, `handle_poll` (`relay.rs:3787`) and `/admin/poll` lose
  their only caller; delete them in a separate relay change.
- Update `cf-jobs/AGENTS.md`'s cron table (4 of 5 slots used).

## Testing

| Step | Check | Pass |
|---|---|---|
| 1 | `cargo test` in `recovered-worker` | all pass |
| 2 | Unit tests for the `/submit` validator: bad sig, wrong `#p`, PoW 15 bits, `created_at` −11 min, 6th request in an hour, duplicate id | each gives its 4xx (duplicate: 200, `duplicate: true`) |
| 2 | Deploy to staging `nostr-form-rs-v2` (`wrangler.staging.toml`, scratch D1, no cron, `NOTIFY` bound). Run `forms.js` in Node against it with a real form slug seeded in scratch D1 | 200; row in scratch D1 `submissions` with `delivery_status='delivered'`; one owner email |
| 2 | `curl -X OPTIONS` with `Origin: https://executiveaiguidance.com` | CORS headers present; other origins get none |
| 3 | `web/forms.test.js` | pass |
| 3 | Local copy of the site (`python -m http.server` in `html/`) with `submitUrl` pointing at staging; submit the contact form in a browser | success message shown; staging row + email |
| deploy | Production deploy of the Worker (keeps the cron and poll for now, so nothing is lost if `/submit` misbehaves), then deploy the site | `/healthz` 200; one real test submission on executiveaiguidance.com lands in live D1 within seconds and emails the owner |
| 4 | Deploy without the cron | `GET …/workers/scripts/nostr-form-rs/schedules` returns no crons; Workers requests for `nostr-form-rs` in the next cf-status digest drop from ~1,500/day to page hits + submissions |

Rollback: the 2026-06-16 bundle is in `deployed-worker-2026-06-16/`; re-upload it
with the same bindings. The site rollback is the previous Pages deployment.

## Out of scope

- The relay write exception (msg 202743): not needed once the relay is out of
  the path.
- Moving any of this onto jorge-mint: the box holds no Cloudflare repos or
  credentials, and this Worker deploys with the account token.
