# nostr-form-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Encrypted contact forms for any website, powered by Nostr.

## What It Does

Replace Google Forms, Typeform, or custom backends with a Nostr-native form system:

1. **Embed** a JavaScript snippet on your website
2. **Visitors submit** - data is encrypted to your processor's public key
3. **Any Nostr relay** receives the encrypted event (knows nothing about forms)
4. **Processor decrypts** and sends as Nostr DM to your configured pubkey

No backend to maintain. No database to secure. No accounts for visitors.

## Key Design

**The relay stays dumb.** All form logic lives in the processor.

- Relay just accepts events (zero form-specific code)
- Processor owns everything: form registry, submissions, rate limits, keys
- Works with any NIP-01 compatible relay
- Single processor keypair decrypts all forms
- **Processor doesn't need public internet** - only outbound to relay

## Features

- **End-to-end encryption** - Only the processor can read submissions (NIP-44)
- **Spam resistant** - Proof-of-work required (NIP-13)
- **Anonymous or authenticated** - Works without accounts, or with Nostr identity (NIP-07)
- **Relay compatible** - Works with nostr-relay (two-tier auth) or any open Nostr relay
- **Self-hosted** - Run the processor on your local network

## Quick Start

### 1. Install

```bash
cargo install nostr-form-rs
```

Or build from source:

```bash
git clone https://github.com/YOUR_USERNAME/nostr-form-rs
cd nostr-form-rs
cargo build --release
```

### 2. Configure

Create `config.json`:

```json
{
  "relay_url": "ws://127.0.0.1:8080",
  "database_path": "./forms.db",
  "api_bind_addr": "127.0.0.1:8081"
}
```

### 3. Add Processor to Relay Whitelist

In your relay's config (e.g., nostr-inbox-rs `config.json`):

```json
{
  "local_pubkeys": ["<processor_pubkey_hex>"],
  "external_pow_bits": 16
}
```
_This allows the processor (local tier) full access, and allows browser form submissions (ephemeral keys tagging the processor via `#p` with 16-bit PoW) through automatically._

The processor prints its pubkey on startup.

### 4. Run

```bash
./target/release/nostr-form-rs
```

### 5. Create a Form

Open the admin UI at `http://127.0.0.1:8081/admin`

1. Click "New Form"
2. Enter a name and your Nostr pubkey (where you want to receive submissions)
3. Copy the embed code

### 6. Embed on Your Website

```html
<form data-nostr-form="YOUR_FORM_ID">
  <input name="name" placeholder="Your name" required />
  <input name="email" type="email" placeholder="Email" required />
  <textarea name="message" placeholder="Message" required></textarea>
  <button type="submit">Send</button>
</form>

<script src="https://raw.githubusercontent.com/YOUR_USERNAME/nostr-form-rs/main/web/forms.js"></script>
```

Done. Submissions are encrypted and forwarded to you as Nostr DMs.

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Your Website  │────▶│   Any Relay     │◀────│    Processor    │
│                 │     │                 │     │   (private)     │
│  • Collect form │     │  • Accept event │     │                 │
│                 │     │  • Two-tier auth│     │                 │
│  • Encrypt to   │     │  • Store        │     │  • Subscribe    │
│    processor    │     │  • Forward      │     │  • Verify PoW   │
│  • Mine PoW     │     │                 │     │  • Decrypt      │
│  • Publish      │     │  (no form       │     │  • Send DM to   │
│                 │     │   logic here)   │     │    recipient    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  Your Nostr     │
                                               │  Client         │
                                               │  (DM inbox)     │
                                               └─────────────────┘
```

### Security Model

| Component | Can Read Submissions? |
|-----------|----------------------|
| Visitor's browser | Yes (before encryption) |
| Network | No (encrypted) |
| Nostr relay | No (encrypted) |
| Processor | Yes (has private key) |
| You | Yes (receive as DM) |

The relay only sees encrypted blobs. Even if compromised, submissions remain private.

### Spam Prevention

Every submission requires proof-of-work (NIP-13):

- Browser must compute ~65,000 SHA-256 hashes (at difficulty 16)
- Takes ~100ms for legitimate users
- Makes bulk spam expensive
- Difficulty adjustable per-form

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `relay_url` | string | required | Nostr relay WebSocket URL |
| `database_path` | string | `"./forms.db"` | SQLite database location |
| `api_bind_addr` | string | `"127.0.0.1:8081"` | Admin API/UI address |
| `processor_privkey` | string | auto-generated | Hex privkey or path to keyfile |
| `default_pow_difficulty` | number | `16` | Minimum PoW bits required |

## Admin API

```
GET    /api/config                 Get processor pubkey
POST   /api/forms                  Create a new form
GET    /api/forms                  List all forms
GET    /api/forms/:id              Get form details
PATCH  /api/forms/:id              Update form settings
DELETE /api/forms/:id              Delete form
GET    /api/forms/:id/embed        Get embed code snippet
GET    /api/forms/:id/submissions  List submissions
POST   /api/submissions/:id/retry  Retry failed delivery
```

## Browser SDK

The embedded JavaScript handles:

1. **Form interception** - Captures submit events
2. **Serialization** - Converts form to JSON
3. **Key generation** - Creates ephemeral keypair (or uses NIP-07)
4. **Encryption** - NIP-44 encrypts to processor pubkey
5. **PoW mining** - Computes NIP-13 proof-of-work
6. **Publishing** - Sends event to relay

### Options

```html
<script>
NostrForms.init({
  relayUrl: 'wss://relay.example.com',   // Override relay
  processorPubkey: 'hex...',             // Processor pubkey
  powDifficulty: 18,                      // Override PoW
  onSuccess: (eventId) => {
    console.log('Submitted:', eventId);
  },
  onError: (error) => {
    console.error('Failed:', error);
  }
});
</script>
```

### NIP-07 Support

If the visitor has a Nostr extension (Alby, nos2x, etc.), they can optionally sign with their real identity:

```html
<form data-nostr-form="YOUR_FORM_ID" data-allow-auth="true">
  ...
</form>
```

## Relay Compatibility

Works with **nostr-relay** (two-tier auth model) or any open Nostr relay.

For nostr-relay (nostr-inbox-rs):
```json
{
  "local_pubkeys": ["<processor_pubkey_hex>"],
  "external_pow_bits": 16
}
```
_This allows the processor (local tier) full access, and allows browser form submissions (ephemeral keys tagging the processor via `#p` with 16-bit PoW) through automatically._

## Development

### Prerequisites

- Rust 1.70+
- Any Nostr relay

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Project Structure

```
src/
├── main.rs           # Entry point
├── config.rs         # Configuration
├── registry/         # Form management (SQLite)
├── processor/        # Event processing, PoW, decryption
├── forwarder/        # DM delivery
├── api/              # HTTP endpoints
└── crypto/           # NIP-44, key management

web/
├── forms.js          # Browser SDK
└── admin/            # Admin UI
```

## Roadmap

- [x] Core architecture design
- [ ] Processor keypair management
- [ ] Relay subscription by #p tag
- [ ] PoW verification in processor
- [ ] Form registry
- [ ] DM forwarding to notify_pubkey
- [ ] Browser SDK with real crypto
- [ ] Admin UI

## Related Projects

- [nostr-inbox-rs](https://github.com/YOUR_USERNAME/nostr-inbox-rs) - Companion Nostr relay
- [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) - Encryption spec
- [NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md) - Proof-of-work spec
- [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) - Browser extension signing

## License

MIT License - see [LICENSE](LICENSE)
