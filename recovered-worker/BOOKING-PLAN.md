# nostr-form-rs — Booking mode (Calendly replacement, Phase 3.6)

Status: **phases A–D deployed and E2E-verified** (2026-06-11). Phases E/F
blocked on recovering the live executiveaiguidance.com source. This
document is the contract; D1–D3 were confirmed in-session.

## Goal

Replace Calendly for `executiveaiguidance.com` "Schedule Session" with a
booking flow built entirely on the existing CF nostr stack — forms
registry, NIP-44 submission pipeline, NIP-17 DM delivery, NIP-98-gated
admin dashboard. No third-party scheduler, no new worker.

```
visitor → executiveaiguidance.com/contact.html
   ├─ GET  forms.argw.com/booking/<slug>/slots   (public, cleartext)
   ├─ POST submission via existing forms.js path  (slot id + name/email/topic, NIP-44 encrypted)
   └─ worker poll: decrypt → atomically claim slot in D1 → NIP-17 DM to owner (+ ICS attached in DM)
```

## Decisions

### Scope (pilot)
- **D1 Visitor confirmation = on-page + downloadable `.ics` only. No
  outbound email.** No email infra exists on CF (MailChannels free tier is
  dead since 2024); adding paid email is scope creep for a pilot. Owner
  confirms manually by replying to the visitor's email from the DM.
- **D2 Availability = recurring weekly rules** stored in
  `forms.options_json` (e.g. `{"booking":{"tz":"America/Los_Angeles",
  "duration_min":45,"rules":[{"dow":[2,3,4],"start":"09:00","end":"12:00"}],
  "horizon_weeks":4,"min_notice_min":1440,"blocks":["2026-07-04"]}}`).
  `min_notice_min` (default 0) drops slots starting sooner than now +
  notice — the "no same-hour bookings" requirement. Slots are materialized
  lazily at read time — no hand-entered slot rows for open time; only
  *booked/held* slots are persisted.
- **D3 Cancel/reschedule = deferred.** Pilot is book-only; changes happen
  over email. Revisit after real usage.

### Data model
- New D1 table `slots`:
  `slot_id TEXT PK` (deterministic: `<form_slug>:<starts_at_unix>`),
  `form_slug TEXT NOT NULL`, `starts_at INTEGER NOT NULL`,
  `duration_min INTEGER NOT NULL`, `status TEXT NOT NULL` (`booked` —
  open slots are virtual, see D2), `booked_event_id TEXT`,
  `created_at INTEGER NOT NULL`.
  Index on `(form_slug, starts_at)`.
- **Double-booking guard:** claim = `INSERT … ON CONFLICT(slot_id) DO
  NOTHING`; rows-affected = 0 ⇒ slot taken ⇒ submission stored with
  `delivery_status='slot_conflict'` and the DM says "missed booking —
  slot already taken". D1 is single-writer, so this is race-free.
- Booking submissions reuse the existing `submissions` table (sealed
  payload, same at-rest encryption). `slots` carries only non-sensitive
  scheduling metadata; the *who/why* stays encrypted.

### Routes
- **`GET /booking/<slug>/slots`** — public (like `/admin/config`).
  Expands the form's rules over the horizon, subtracts persisted
  `booked` rows and `blocks`, returns future open slots as JSON
  `{tz, duration_min, slots:[{id, starts_at}]}`. No auth: availability
  is not sensitive; rate-limited per IP via the existing limiter shape.
- **Poll routing** — payload field `slot_id` present ⇒ booking path:
  validate slot is inside the rule set + horizon, claim, then normal
  store + NIP-17 delivery. The DM body includes a rendered `.ics`
  (VEVENT, UTC, UID = slot_id) so the owner can drop it on a calendar.
- **Admin** (NIP-98-gated, existing dashboard): booking tab on `/admin` —
  edit rules JSON per form, list booked slots, cancel a booking
  (DELETE `/admin/slots/<id>` → frees the slot; visitor notification is
  manual per D3).

### Client (contact page)
- Slot picker on `contact.html`: fetch `/booking/<slug>/slots`, render
  grouped by day in the visitor's local timezone (convert from `tz`),
  selected slot id goes into the form payload alongside name/email/topic.
  Falls back to the plain message form when zero slots are returned.
- Success state: "Booked <local time>" + a client-generated `.ics`
  download (same VEVENT the worker builds — duplicated ~15 LOC, keeps
  the public endpoint write-free).
- **Blocker: the live site's source is not in this workspace.**
  `src/executiveaiguidance-com/index.html` is a stale placeholder; the
  deployed site (Tailwind, `forms.js`, `main.js`) lives elsewhere.
  Locate it before Phase E below.

### New form registry row
- One new form, e.g. `name='ExecutiveAiGuidance Booking'`, fresh slug,
  `notify_pubkey=777d0ead…`, `delivery_mode='full'`, booking config in
  `options_json`. Existing contact (`MpAETNds`) and newsletter
  (`bGFqnzYT`) forms untouched.

## Residual risks (documented, accepted)
- **Slot squatting:** anyone can book all slots (no payment/captcha).
  Mitigated by per-form PoW + rate limit (already enforced) and small
  horizon. Acceptable for pilot traffic.
- **Timezone bugs** are the classic failure mode: all storage/compare in
  unix UTC; `tz` used only for rule expansion (DST-correct via offset
  lookup at each slot date) and display.
- **No visitor reminder/confirmation email** (D1) — relies on the owner
  replying. Revisit if no-shows happen.

## Implementation phases (verify each before next)
- **A. Schema + slot math** — DONE. `slots` DDL in `schema.rs`; pure
  `booking.rs` (config parse, US-DST tz table, rule expansion, slot ids,
  ICS) with 12 native unit tests (DST both directions, horizon,
  min-notice, blocks, window fit, validation).
- **B. Public slots route** — DONE. `booking_routes.rs`; verified live:
  `GET forms.argw.com/booking/<slug>/slots` → 200, DST-correct 9:00 EDT
  first slot, CORS `*`, per-IP rate limit via existing limiter.
- **C. Booking poll path** — DONE. E2E-verified against production:
  two PoW-mined submissions for the same slot via `admin_tool` +
  wss publish → one `delivered` (DM with ICS), one `slot_conflict`;
  exactly one `slots` row; booked slot vanished from the public route.
  Invalid slot ids → `slot_invalid` status + owner DM.
- **D. Admin tab** — DONE. `GET /admin/slots`, `DELETE /admin/slots/<id>`
  (NIP-98-gated); dashboard Booking tab (list + cancel) and an
  options_json editor on the form card (which also fixes the prior UI
  hazard of wiping options_json on save).
- **E. Contact page picker** — needs live-site source (see blocker);
  deploy, book a real slot from a browser.
- **F. Cutover** — remove Calendly link/embed from the live site (if
  any remains), update DOMAINS.md note.

## Related deferred work (not this phase)
- D6.3 historical-submission import (5 rows from
  `backups/argw/extracted/nostr-form-rs/forms.db`) — still open.
- `src/executive-redirect/` has `wrangler.toml` but no `src/index.js`
  on disk — recover or recreate the deployed worker's source.
- Self-certifying form ids (NIP-101-style addressable coordinates) —
  **worker side DONE** (2026-06-11): `src/form_id.rs::resolve_slug`
  accepts `30168:<ADMIN_PUBKEY>:<slug>` alongside bare slugs (8 native
  unit tests; wrong owner/kind resolves to the raw string → rejected as
  unknown form, never silently truncated). Client embed snippets still
  send bare slugs — switch them to the coordinate form when the
  live-site source is recovered (Phase E) or when formstr interop
  appears. No schema migration needed.
