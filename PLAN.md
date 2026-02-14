# nostr-form-rs

## Overview

A Nostr-native encrypted web form submission system. Public websites embed a JavaScript widget that encrypts form data to a form processor's pubkey, applies NIP-13 proof-of-work, and submits to any Nostr relay. The processor subscribes to its own pubkey, decrypts submissions, and forwards as Nostr DMs to configured recipients.

**Key principle:** The relay stays dumb. All form logic lives in the processor.

**Companion to**: [nostr-inbox-rs](../nostr-relay) - works with this relay (or any NIP-01 relay).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PUBLIC WEBSITE                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  <form data-nostr-form="FORM_ID">                        │   │
│  │    <input name="email" />                                │   │
│  │    <textarea name="message"></textarea>                  │   │
│  │    <button>Submit</button>                               │   │
│  │  </form>                                                 │   │
│  │  <script src="https://processor.example/forms.js">      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Browser:                                                        │
│    1. Collect form data                                          │
│    2. Generate ephemeral keypair (or use NIP-07)                 │
│    3. NIP-44 encrypt to PROCESSOR pubkey                         │
│    4. Mine NIP-13 PoW (16+ bits)                                 │
│    5. Publish event to relay                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     NOSTR RELAY (any relay)                      │
│                                                                  │
│  Relay knows NOTHING about forms. It just:                       │
│    - Accepts events (processor pubkey in whitelist)              │
│    - Stores events                                               │
│    - Forwards to subscribers                                     │
│                                                                  │
│  Zero form-specific logic. Zero form-specific tables.            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Processor subscribes:
                              │ ["REQ", "forms", {"#p": ["<processor_pubkey>"]}]
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FORM PROCESSOR (this crate)                  │
│                                                                  │
│  ALL form logic lives here:                                      │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Worker Thread                                          │    │
│  │  - Subscribe to relay for #p = processor pubkey         │    │
│  │  - Verify PoW meets minimum difficulty                  │    │
│  │  - Decrypt with processor private key                   │    │
│  │  - Look up form_id in local registry                    │    │
│  │  - Apply per-form rate limits                           │    │
│  │  - Store submission to local database                   │    │
│  │  - Forward as Nostr DM to configured recipient pubkey     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  SQLite Database (forms.db)                             │    │
│  │  - forms table (registry)                               │    │
│  │  - submissions table (history)                          │    │
│  │  - rate_limits table (tracking)                         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Web UI + API                                           │    │
│  │  - Create/manage forms                                  │    │
│  │  - View submissions                                     │    │
│  │  - Generate embed snippets                              │    │
│  │  - Configure forwarding                                 │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Design Principles

1. **Relay stays dumb** - No form-specific logic, tables, or validation in the relay
2. **Processor owns all state** - Forms, submissions, rate limits, keys
3. **One processor keypair** - All forms encrypt to same pubkey; form_id routes internally
4. **Standard Nostr** - Uses normal NIP-01 events; works with any relay

---

## Event Specification

### Form Submission Event

Any event kind works (e.g., kind 4 for DM, or custom kind 21000). The processor identifies form submissions by:
- Tagged with `#p` = processor pubkey
- Contains `form_id` tag

```json
{
  "id": "<sha256 hash>",
  "pubkey": "<sender pubkey - ephemeral or authenticated>",
  "created_at": 1700000000,
  "kind": 4,
  "tags": [
    ["p", "<PROCESSOR_PUBKEY>"],
    ["form_id", "<form_id>"],
    ["nonce", "238741", "16"]
  ],
  "content": "<NIP-44 encrypted JSON payload>",
  "sig": "<signature>"
}
```

### Encrypted Payload Schema

```json
{
  "v": 1,
  "form_id": "abc123",
  "fields": {
    "name": "John Doe",
    "email": "john@example.com",
    "message": "Hello, I'd like to..."
  },
  "meta": {
    "submitted_at": "2024-01-15T10:30:00Z",
    "user_agent": "Mozilla/5.0...",
    "referrer": "https://example.com/contact"
  }
}
```

Note: `form_id` appears both in cleartext tag (for potential relay filtering) and encrypted payload (for authenticity after decryption).

---

## Relay Requirements

**Minimal.** Any NIP-01 compatible relay works.

For nostr-inbox-rs, just add the processor's pubkey to `authorized_pubkeys`:

```json
{
  "authorized_pubkeys": [
    "your_personal_pubkey",
    "processor_pubkey_hex"
  ]
}
```

That's it. No other changes.

---

## Processor Components

### 1. Keypair

Single keypair for the processor instance:
- **Public key**: Embedded in forms.js, used by all forms
- **Private key**: Stored securely, used for decryption

### 2. Form Registry (SQLite)

```sql
CREATE TABLE forms (
    form_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pow_difficulty INTEGER DEFAULT 16,
    rate_limit_per_hour INTEGER DEFAULT 100,
    notify_pubkey TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

No per-form keys needed - processor's single key decrypts everything.

### 3. Submission Log (SQLite)

```sql
CREATE TABLE submissions (
    event_id TEXT PRIMARY KEY,
    form_id TEXT NOT NULL,
    sender_pubkey TEXT NOT NULL,
    submission_type TEXT NOT NULL,
    decrypted_content TEXT,
    received_at INTEGER NOT NULL,
    processed_at INTEGER,
    delivery_status TEXT DEFAULT 'pending',
    delivery_attempts INTEGER DEFAULT 0,
    last_delivery_error TEXT,
    FOREIGN KEY (form_id) REFERENCES forms(form_id)
);

CREATE INDEX idx_submissions_form ON submissions(form_id);
CREATE INDEX idx_submissions_status ON submissions(delivery_status);
```

### 4. Admin Whitelist (SQLite)

```sql
CREATE TABLE admin_pubkeys (
    pubkey TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);
```

### 5. Processor Config (SQLite)

```sql
CREATE TABLE processor_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Stores: processor_privkey, processor_pubkey
```

### 6. Rate Limit Tracking (SQLite)

```sql
CREATE TABLE rate_limits (
    key TEXT PRIMARY KEY,  -- "ip:1.2.3.4" or "form:abc123"
    count INTEGER DEFAULT 0,
    window_start INTEGER NOT NULL
);
```

### 5. Worker Thread

- Connects to relay via WebSocket
- Subscribes: `["REQ", "forms", {"#p": ["<processor_pubkey>"]}]`
- For each event:
  1. Verify PoW >= global minimum
  2. Decrypt content
  3. Parse form_id from payload
  4. Look up form in registry
  5. Verify PoW >= form-specific minimum
  6. Check rate limits
  7. Store submission
  8. Forward to targets

### 6. HTTP API

**Authentication:** All admin endpoints require NIP-98 HTTP Auth.

Client must:
1. Have a Nostr browser extension (NIP-07)
2. Sign an auth event with their pubkey
3. Include it in `Authorization` header
4. Pubkey must be in `admin_pubkeys` table

```
# Public (no auth)
GET    /api/config                   - Get processor pubkey

# Admin (NIP-98 required, pubkey must be whitelisted)
POST   /api/forms                    - Create form
GET    /api/forms                    - List forms
GET    /api/forms/:id                - Get form details
PATCH  /api/forms/:id                - Update form
DELETE /api/forms/:id                - Delete form
GET    /api/forms/:id/embed          - Get embed code
GET    /api/forms/:id/submissions    - List submissions
GET    /api/submissions/:id          - Get submission detail
POST   /api/submissions/:id/retry    - Retry delivery
POST   /api/admin/pubkeys            - Add admin pubkey (bootstrap only)
```

**Bootstrap:** First admin pubkey added via config file or CLI flag.

### 7. Browser SDK (forms.js)

Hosted on GitHub (or any static host). User includes in their HTML.

Configuration via `NostrForms.init()` or `data-*` attributes - no build step required.

**Processor does NOT need public internet access** - only outbound to relay.

---

## Browser SDK Specification (`forms.js`)

### Dependencies

The SDK uses `nostr-tools` which provides battle-tested implementations of:
- NIP-44 encryption/decryption
- NIP-13 proof-of-work
- NIP-07 browser extension integration
- Event serialization and signing

```bash
npm install nostr-tools
# or include via CDN
```

**Do not reimplement NIP-44.** Use the library.

### NIP-07 Support (Browser Extensions)

The SDK detects and uses Nostr browser extensions (Alby, nos2x, Flamingo, etc.):

```javascript
// NIP-07 detection flow
if (window.nostr) {
  // Extension available
  if (form.dataset.allowAuth === 'true') {
    // User opted in to reveal identity
    const pubkey = await window.nostr.getPublicKey();
    const signedEvent = await window.nostr.signEvent(unsignedEvent);
    // submission_type = 'authenticated'
  } else {
    // Extension exists but user wants anonymity
    // Generate ephemeral key, sign ourselves
    // submission_type = 'anon'
  }
} else {
  // No extension
  // Generate ephemeral key, sign ourselves
  // submission_type = 'anon'
}
```

### Signing Modes

| Mode | Condition | Sender Pubkey | Signature |
|------|-----------|---------------|----------|
| Anonymous | No extension OR `data-allow-auth` not set | Ephemeral (random) | SDK signs |
| Authenticated | Extension + `data-allow-auth="true"` | User's real pubkey | Extension signs via NIP-07 |

**Note:** Encryption is always to the processor's pubkey regardless of signing mode.

### NIP-44 Encryption

The SDK implements NIP-44 v2 encryption:

1. Generate random 32-byte conversation key
2. ECDH: shared_secret = sender_privkey × recipient_pubkey
3. HKDF-SHA256 to derive encryption key
4. XChaCha20-Poly1305 encrypt
5. Encode: version (1 byte) + nonce (24 bytes) + ciphertext
6. Base64 encode

### NIP-13 Proof-of-Work

Mining loop:

```javascript
let nonce = 0;
while (true) {
  event.tags = [...otherTags, ['nonce', nonce.toString(), difficulty.toString()]];
  const id = sha256(serializeEvent(event));
  if (countLeadingZeroBits(id) >= difficulty) {
    event.id = id;
    break;
  }
  nonce++;
}
```

### SDK API

```javascript
// Global configuration
NostrForms.init({
  relayUrl: 'wss://relay.example.com',
  processorPubkey: 'hex...',
  powDifficulty: 16,
  onProgress: (stage, data) => {},  // 'encrypting' | 'mining' | 'publishing'
  onSuccess: (eventId) => {},
  onError: (error) => {}
});

// Programmatic submission
const eventId = await NostrForms.submit(formElement);
```

### HTML Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `data-nostr-form` | Yes | Form ID from processor registry |
| `data-allow-auth` | No | If `"true"`, offer NIP-07 signing when available |
| `data-pow` | No | Override PoW difficulty for this form |
| `data-relay` | No | Override relay URL for this form |

### Example with All Options
```html
<form 
  data-nostr-form="abc123" 
  data-allow-auth="true"
  data-pow="18"
  data-relay="wss://custom-relay.com">
  <input name="email" type="email" required />
  <textarea name="message" required></textarea>
  <button type="submit">Send</button>
</form>
```

### Event Structure (Browser Output)

```json
{
  "id": "0000...(PoW prefix)",
  "pubkey": "<ephemeral or user pubkey>",
  "created_at": 1700000000,
  "kind": 4,
  "tags": [
    ["p", "<processor_pubkey>"],
    ["form_id", "abc123"],
    ["nonce", "238741", "16"]
  ],
  "content": "<NIP-44 encrypted payload>",
  "sig": "<Schnorr signature>"
}
```

### Distribution

Hosted on GitHub. Users include via:

```html
<!-- From GitHub (raw) -->
<script src="https://raw.githubusercontent.com/USER/nostr-form-rs/main/web/forms.js"></script>

<!-- Or copy to their own server -->
<script src="/js/forms.js"></script>
```

No CDN required for MVP. Forms.js is ~20KB with dependencies bundled.

### Network Topology

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Browser    │────▶│    Relay     │◀────│  Processor   │
│  (public)    │     │  (public)    │     │  (private)   │
└──────────────┘     └──────────────┘     └──────────────┘
                            ▲
                            │
                     Outbound only
                     (processor initiates)
```

**Processor requirements:**
- Outbound WebSocket to relay
- Outbound to relay (for sending DM notifications)
- NO public IP, open ports, or DNS needed

---

## Configuration

Processor config (`config.json`):

```json
{
  "relay_url": "ws://127.0.0.1:8080",
  "database_path": "./forms.db",
  "api_bind_addr": "127.0.0.1:8081",
  "default_pow_difficulty": 16,
  "bootstrap_admin_pubkey": "<your nostr pubkey>"
}
```

**Startup behavior:**
1. Open SQLite database, create tables if not exist
2. Load processor keypair from DB (generate if missing, save to DB)
3. Insert bootstrap_admin_pubkey if admin_pubkeys table empty
4. Load forms into memory
5. Subscribe to relay
6. Reload forms on SIGHUP or API call

---

## Implementation Phases

### Phase 1: Core Pipeline (MVP)
1. Processor keypair generation/loading
2. Relay subscription (filter by #p tag)
3. PoW verification
4. NIP-44 decryption
5. Form registry (SQLite)
6. Submission storage
7. DM forwarding to notify_pubkey

### Phase 2: Browser SDK
1. Form interception
2. NIP-44 encryption (use nostr-tools or noble-secp256k1)
3. NIP-13 PoW mining
4. WebSocket publication
5. NIP-07 detection (optional authenticated submission)

### Phase 3: Admin UI
1. Registry API endpoints
2. Create form flow
3. Embed code generator
4. Submissions dashboard

### Phase 4: Production Hardening
1. Delivery retry logic
4. Per-form rate limiting
5. Monitoring/metrics

---

## File Structure

```
nostr-form-rs/
├── Cargo.toml
├── README.md
├── USER_MANUAL.md
├── PLAN.md
├── config.example.json
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs
│   ├── config.rs            # Configuration
│   ├── registry/            # Form registry
│   │   ├── mod.rs
│   │   ├── models.rs        # Form, Submission types
│   │   └── storage.rs       # SQLite operations
│   ├── processor/           # Event processor
│   │   ├── mod.rs
│   │   ├── decryptor.rs     # NIP-44 decryption
│   │   ├── pow.rs           # PoW verification
│   │   └── worker.rs        # Relay subscription + processing
│   ├── forwarder/           # Delivery targets
│   │   ├── mod.rs
│   │   └── dm.rs            # NIP-44 DM to notify_pubkey
│   ├── api/                 # HTTP API
│   │   ├── mod.rs
│   │   ├── server.rs
│   │   └── handlers.rs
│   └── crypto/              # Cryptographic utilities
│       ├── mod.rs
│       ├── nip44.rs         # Encryption/decryption
│       └── keys.rs          # Key management
├── web/                     # Browser SDK + UI
│   ├── package.json         # nostr-tools dependency
│   ├── forms.js             # Embeddable SDK (uses nostr-tools)
│   ├── forms.test.js        # Vitest tests
│   ├── admin/               # Admin UI (uses NIP-07 for auth)
│   │   └── index.html
│   └── demo.html            # Demo form page
└── tests/
```

---

## Security Considerations

1. **Processor private key** - Stored in SQLite; this key decrypts ALL submissions
2. **Admin API authentication** - NIP-98 HTTP Auth; pubkey must be in whitelist
3. **PoW verification** - Processor validates; relay doesn't need to
4. **Rate limiting** - Processor enforces per-IP and per-form limits
5. **No plaintext in relay** - Relay only sees encrypted content
6. **Event deduplication** - Processor tracks event IDs to prevent replay
7. **SQLite file** - Restrict file permissions on forms.db

---

## Comparison: Old vs New Design

| Aspect | Old (Relay-heavy) | New (Processor-only) |
|--------|-------------------|----------------------|
| Relay changes | Many | Zero |
| Form registry | In relay | In processor |
| PoW validation | In relay | In processor |
| Rate limiting | In relay | In processor |
| Per-form keys | Yes | No (single processor key) |
| Works with any relay | No | Yes |
| Complexity | Distributed | Centralized in processor |

---

## Success Criteria

- [ ] Processor generates/loads keypair
- [ ] Processor subscribes to relay by #p tag
- [ ] Browser SDK encrypts to processor pubkey
- [ ] PoW mined in browser, verified in processor
- [ ] Form submission works end-to-end (browser → relay → processor → DM to recipient)
- [ ] Admin UI for form management
- [ ] Works with unmodified nostr-inbox-rs

---

## Testing Strategy

### Rust Processor Tests

**Unit tests** (`cargo test`):
- NIP-44 decryption (known test vectors)
- PoW verification (valid/invalid difficulty)
- Form registry CRUD
- Event deduplication

**Integration tests:**
- WebSocket subscription to local relay
- Full event processing pipeline
- DM sending to notify_pubkey

### Browser SDK Tests

**Unit tests** (Vitest):
- `nostr-tools` NIP-44 encryption works
- PoW mining produces valid nonce
- Event serialization matches spec
- NIP-07 mock (fake `window.nostr`)

**Cross-implementation compatibility:**
- Encrypt in JS (nostr-tools), decrypt in Rust
- Encrypt in Rust, decrypt in JS (nostr-tools)
- Use NIP-44 official test vectors for both
- **This is critical** - must pass before integration

**JS test setup:**
```bash
cd web/
npm init -y
npm install nostr-tools vitest
```

```javascript
// web/forms.test.js
import { nip44 } from 'nostr-tools';
import { describe, it, expect } from 'vitest';

describe('NIP-44', () => {
  it('encrypts and decrypts', () => {
    // test with known vectors
  });
});
```

### End-to-End Tests

**Manual with demo.html:**
1. Start nostr-inbox-rs
2. Start processor
3. Create form via admin UI
4. Open demo.html, submit form
5. Verify DM received by notify_pubkey

**Automated (Playwright, future):**
- Headless browser submits form
- Assert DM appears in recipient's inbox

### Test Cases

| Test | Expected |
|------|----------|
| PoW difficulty 16, hash has 16 zero bits | Pass |
| PoW difficulty 16, hash has 15 zero bits | Reject |
| Valid NIP-44 ciphertext | Decrypt succeeds |
| Tampered ciphertext | Decrypt fails |
| Unknown form_id | Reject with error |
| Duplicate event_id | Ignore (idempotent) |
| Rate limit exceeded | Reject |
| NIP-07 extension present, data-allow-auth=true | Use extension to sign |
| NIP-07 extension present, no data-allow-auth | Ephemeral key |

---

## Open Questions

1. **Event kind**: Use kind 4 (standard DM) or custom kind 21000?
   - Recommendation: Kind 4 for maximum relay compatibility

2. **Multiple relays**: Should processor subscribe to multiple relays?
   - Recommendation: Config option for relay list

3. **Processor clustering**: Multiple processor instances?
   - Recommendation: Future phase; single instance for MVP
