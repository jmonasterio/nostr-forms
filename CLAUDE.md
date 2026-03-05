# nostr-form-rs — Project Context for AI Agents

## Deployment

The deploy scripts live in the **sibling directory** `../nostr-form-rs.deploy` (i.e., `C:\github\nostr-form-rs.deploy`). That repo is not part of this source tree.

### To deploy to argw.com

Prerequisites (one-time setup):
```
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu
```

Then from anywhere on Windows:
```
cd C:\github\nostr-form-rs.deploy
deploy.bat
```

What the script does:
1. Runs `cargo zigbuild --target x86_64-unknown-linux-gnu --release` inside `../nostr-form-rs`
2. SCPs the binary, `config.json`, `nostr-form-rs.service`, and web assets to `jm@argw.com`
3. SSH-installs everything, restarts the systemd service, and prints the processor pubkey

### Server details

| Item | Value |
|------|-------|
| Host | `argw.com` |
| SSH user | `jm` |
| Binary | `/usr/local/bin/nostr-form-rs` |
| Config | `/etc/nostr-form-rs/config.json` |
| Database | `/var/lib/nostr-form-rs/forms.db` |
| Web assets | `/var/lib/nostr-form-rs/web/` |
| Service | `nostr-form-rs` (systemd) |
| API | `127.0.0.1:8081` (internal only) |
| Relay | `wss://relay.argw.com` |

### Smoke test (end-to-end verification)

After any deploy, run the full pipeline test from the deploy repo:

```
cd C:\github\nostr-form-rs.deploy
npm install        # one-time
npm run smoke
```

What it verifies:
- API is reachable (via SSH to 127.0.0.1:8081)
- A test form can be found or created
- An NIP-44 v2 encrypted event can be published to `wss://relay.argw.com`
- The processor picks it up, **decrypts it successfully**, and delivers the DM

The decryption check is the critical gate. If `decrypted: NO` appears, the Rust
NIP-44 implementation has drifted from nostr-tools and no real submissions will work.

### After deploying

If the processor pubkey changed (first deploy on a fresh DB), add it to `nostr-relay.deploy/config.json` under `local_pubkeys` and redeploy the relay. The script reminds you of this.

### Accessing the admin UI

The API/admin is bound to `127.0.0.1:8081` and is not exposed publicly. Use an SSH tunnel:

```
ssh -L 8081:127.0.0.1:8081 jm@argw.com -N
```

Then open `http://localhost:8081/admin` in a browser and sign in with your Nostr extension.

### Checking service health

```bash
ssh jm@argw.com "sudo systemctl status nostr-form-rs"
ssh jm@argw.com "sudo journalctl -u nostr-form-rs -f"
ssh jm@argw.com "curl -s http://127.0.0.1:8081/api/config"
```

## Known pubkeys

| Role | Hex pubkey |
|------|-----------|
| Admin (Jorge) | `777d0ead9065a316d57773164ae4d013708f30f1235f089e12c22c4bbe4b625a` |
| Processor | `43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6` (auto-generated on first run, stored in DB) |

## Crypto

This project implements **NIP-44 v2** exactly. Key implementation notes for anyone touching `src/crypto/nip44.rs`:

- `derive_conversation_key`: **HKDF-Extract only** (salt=`"nip44-v2"`, IKM=shared_x). The 32-byte PRK is the conversation key. Do NOT run Expand afterwards.
- `derive_message_keys`: **HKDF-Expand only** (PRK=conversation_key, info=nonce, L=76). Do NOT run Extract first. The nonce is `info`, not `salt`.
- Cipher: **ChaCha20** (RFC 8439, 12-byte nonce from HKDF bytes 32..44). Not XChaCha20, not AEAD.
- MAC: **HMAC-SHA256**(key=hmac_key, data=nonce‖ciphertext). Not Poly1305.
- Nonce: **32 bytes** random per message.
- Payload: `base64(version[1] | nonce[32] | ciphertext | mac[32])`.

The JS side (`web/`) uses `nostr-tools` which follows the spec. Any drift between Rust and nostr-tools means the browser encrypts messages the server can never decrypt.

The `test_known_vector_full_encrypt` unit test in `src/crypto/nip44.rs` pins the implementation against the official NIP-44 v2 published test vector. It must always pass.

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
├── forms.js          # Browser SDK (embedded on client sites)
└── admin/            # Admin UI (served from the processor)

../nostr-form-rs.deploy/   # Sibling repo — deploy scripts, live config
```

## Related repos (all siblings under C:\github\)

| Repo | Purpose |
|------|---------|
| `nostr-form-rs.deploy` | Deploy scripts and live config for argw.com |
| `nostr-relay` | Companion Nostr relay source |
| `nostr-relay.deploy` | Deploy scripts for relay.argw.com |
