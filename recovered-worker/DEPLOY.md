# nostr-form-rs deploy + verify runbook

Operational runbook for the live Worker (overview is in `README.md`).
The processor is **deployed and live**; this covers re-deploys, disaster
recovery, and migration.

## Local smoke

`form_smoke` in `../nostr-relay-harness` exercises the pipeline against a
local relay:

```bash
cd src/nostr-relay && cmd /c "start /B _run-dev.bat"   # or `wrangler dev`
cd ../nostr-relay-harness && cargo run --release --bin form_smoke
# ✓ AUTH → EVENT publish → /admin/poll → NIP-44 v2 decrypt → plaintext match
```

Crypto is also covered natively: `cd src/nostr-form-rs && cargo test`
(nip44 round-trip + spec vectors, nip98 auth, nip17 gift wrap).

## First-time setup

1. **D1** (one-time):
   ```bash
   cd src/nostr-form-rs
   wrangler d1 create nostr-form-rs
   # paste database_id into wrangler.toml [[d1_databases]]  (live id: f4dc3389-…)
   ```

2. **Vars** in `wrangler.toml` `[vars]`:
   ```toml
   PROCESSOR_PUBKEY = "<x-only hex matching PROCESSOR_NSEC>"   # 43100984…
   ADMIN_PUBKEY     = "<owner x-only hex>"                      # at-rest recipient + bootstrap admin
   ```

3. **Secrets** (one-time):
   ```bash
   wrangler secret put PROCESSOR_NSEC          # processor private key (hex)
   wrangler secret put ADMIN_INTERNAL_TOKEN    # MUST match the relay's value
   ```

4. **Schema + seed** — apply `migrate.sql` (creates all tables and seeds the
   forms registry + `admin_pubkeys`; it is the source of truth, generated
   from a `forms.db` snapshot and committed):
   ```bash
   wrangler d1 execute nostr-form-rs --remote --file=migrate.sql
   ```
   `ensure_schema` also runs the `IF NOT EXISTS` DDL (`schema.rs`) on every
   request, so tables self-heal; `migrate.sql` is what makes them appear
   immediately and carries the seed data.

## Deploy

The relay must already be deployed (the `RELAY` service binding resolves at
deploy time).

```bash
cd src/nostr-form-rs
NODE_OPTIONS=--dns-result-order=ipv4first wrangler deploy
wrangler tail            # watch the first cron tick (cron: every minute)
```

- IPv6 black-holes on this LAN — wrangler may fail the first 1–4 calls;
  the `ipv4first` flag + a retry clears it.
- `forms.argw.com` is a Workers **Custom Domain** attached via the account
  API (the deploy token can't edit zone routes). `wrangler deploy` will log
  a route-auth error after `Uploaded` — harmless; judge success by the
  `Uploaded` line. (Re-attach if ever needed: `PUT
  /accounts/<acct>/workers/domains` with `service=nostr-form-rs`,
  `hostname=forms.argw.com`, the argw.com `zone_id`.)

## Migrating from an argw `forms.db` snapshot

The droplet is retired; snapshots live in `../../backups/argw/` (e.g.
`nostr-state.zip` → `nostr-form-rs/forms.db`).

- **Forms + admin pubkeys**: already folded into `migrate.sql` (regenerate
  it from a fresh `forms.db` if the registry changes).
- **Historical submissions**: **not** auto-migrated. The at-rest column is
  `sealed_json` (NIP-44 to `ADMIN_PUBKEY`), so a snapshot's plaintext
  `decrypted_content` would have to be **re-encrypted to the admin pubkey**
  before insert — `migrate.py`'s plaintext output is *not* compatible with
  the encrypt-at-rest schema. Deferred by design (ADMIN-UI-PLAN §D6.3); the
  archive starts at cutover. If you ever want them, re-encrypt each row with
  `examples/admin_tool encrypt "<plaintext>" <PROCESSOR_NSEC> <ADMIN_PUBKEY>`
  and insert into `submissions(... , sealed_json, ...)`.

## Post-deploy verification

1. **Auth + read path** (NIP-98) — needs an admin key in `admin_pubkeys`:
   ```bash
   B=https://forms.argw.com
   HDR=$(cargo run -q --example admin_tool -- nip98 <admin_sk> GET "$B/admin/forms")
   curl -s -H "Authorization: $HDR" "$B/admin/forms"      # → forms JSON (401 without/with bad token)
   ```
2. **Full round-trip** — mine + publish a submission, then confirm it lands
   decrypted:
   ```bash
   cargo run -q --example admin_tool -- submission <PROCESSOR_PUBKEY> <form_slug> "hello" 16 > sub.json
   curl -s --resolve relay.argw.com:443:<cf-edge-ip> -X POST https://relay.argw.com/admin/publish \
     -H "X-Admin-Token: <ADMIN_INTERNAL_TOKEN>" -H "Content-Type: application/json" --data @sub.json
   # next cron tick (or POST /admin/poll-now with a NIP-98 header) processes it
   wrangler d1 execute nostr-form-rs --remote --command \
     "SELECT event_id, form_slug, delivery_status, received_at FROM submissions ORDER BY received_at DESC LIMIT 5"
   ```
3. **Dashboard** — open https://forms.argw.com/admin, sign in (extension /
   NIP-46 / key via `nostr-universal`), confirm forms list + decrypted
   submissions render. Remember to clean up any test rows afterward.

## Notes

- `ADMIN_INTERNAL_TOKEN` is shared with the relay; rotating it requires
  `wrangler secret put` on **both** workers.
- The relay gates writes (free-tier `rows_written`) — if the relay DO is in
  a write-blocked window, published submissions won't be stored until it
  resets (see `../nostr-relay/DIVERGENCES.md §v3`).
