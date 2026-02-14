# nostr-form-rs Integrator's Guide

Instructions for LLMs and developers integrating encrypted contact forms into websites.

## Overview

nostr-form-rs provides encrypted form submissions via the Nostr protocol. Form data is encrypted client-side to the processor's public key, published to a Nostr relay, then decrypted and delivered as a DM to the form owner.

**Flow:**
1. User fills out form on your website
2. Browser encrypts data with NIP-44 to processor pubkey
3. Browser mines proof-of-work (spam prevention)
4. Browser publishes encrypted event to relay
5. Processor decrypts and sends DM to form owner's Nostr pubkey

## Quick Start

### 1. Get Processor Pubkey

The processor pubkey is generated on first run and stored in the database. Get it from:
- Server logs on startup
- Admin UI at `/admin`
- API endpoint: `GET /api/config` (returns `processor_pubkey`)

### 2. Create a Form via Admin UI

1. Open `http://your-server:8081/admin`
2. Sign in with a whitelisted Nostr extension (Alby, nos2x)
3. Click "New Form"
4. Enter form name and your Nostr pubkey (where you'll receive submissions)
5. Copy the generated `form_id`

### 3. Create a Form via API

```bash
# Create NIP-98 auth header (or use the JS SDK)
curl -X POST http://localhost:8081/api/forms \
  -H "Authorization: Nostr <base64-signed-event>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Contact Form",
    "notify_pubkey": "your-64-char-hex-pubkey",
    "pow_difficulty": 16
  }'
```

Response:
```json
{
  "form_id": "xK7mN2pQ",
  "processor_pubkey": "abc123..."
}
```

## HTML Integration

### Minimal Example

```html
<form data-nostr-form="YOUR_FORM_ID">
  <input name="email" type="email" required>
  <textarea name="message" required></textarea>
  <button type="submit">Send</button>
</form>

<script type="module">
  import { NostrForms } from 'https://your-cdn.com/forms.js';
  
  NostrForms.init({
    relayUrl: 'wss://your-relay.com',
    processorPubkey: 'PROCESSOR_PUBKEY_64_HEX_CHARS'
  });
</script>
```

### Full Example with Callbacks

```html
<form data-nostr-form="xK7mN2pQ" data-pow="16">
  <div class="form-group">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required>
  </div>
  
  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required>
  </div>
  
  <div class="form-group">
    <label for="message">Message</label>
    <textarea id="message" name="message" required></textarea>
  </div>
  
  <button type="submit">Send Message</button>
  <div id="status"></div>
</form>

<script type="module">
  import { NostrForms } from './forms.js';
  
  const statusEl = document.getElementById('status');
  
  NostrForms.init({
    relayUrl: 'wss://relay.example.com',
    processorPubkey: '0123456789abcdef...',
    powDifficulty: 16,
    
    onProgress: (stage, data) => {
      switch (stage) {
        case 'encrypting':
          statusEl.textContent = 'Encrypting...';
          break;
        case 'mining':
          statusEl.textContent = `Mining PoW (${data?.nonce || 0} attempts)...`;
          break;
        case 'publishing':
          statusEl.textContent = 'Sending...';
          break;
      }
    },
    
    onSuccess: (eventId) => {
      statusEl.textContent = 'Sent successfully!';
      // Optionally redirect or show confirmation
    },
    
    onError: (err) => {
      statusEl.textContent = 'Failed: ' + err.message;
    }
  });
</script>
```

## Form Attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `data-nostr-form` | Yes | Form ID from admin panel |
| `data-pow` | No | Override PoW difficulty (default: from init config) |
| `data-relay` | No | Override relay URL for this form |
| `data-allow-auth` | No | Set to `"true"` to use NIP-07 extension for authenticated submissions |

## SDK Configuration

```javascript
NostrForms.init({
  // Required
  relayUrl: 'wss://relay.example.com',
  processorPubkey: '64-char-hex-pubkey',
  
  // Optional
  powDifficulty: 16,        // Default PoW bits (8-24)
  
  // Callbacks
  onProgress: (stage, data) => {},  // 'encrypting' | 'mining' | 'publishing'
  onSuccess: (eventId) => {},       // Called with Nostr event ID
  onError: (err) => {}              // Called with Error object
});
```

## Programmatic Submission

```javascript
import { NostrForms } from './forms.js';

NostrForms.init({ relayUrl: '...', processorPubkey: '...' });

// Submit any form element
const form = document.querySelector('#my-form');
const eventId = await NostrForms.submit(form);
```

## Payload Format

The encrypted payload sent to the processor:

```json
{
  "v": 1,
  "form_id": "xK7mN2pQ",
  "fields": {
    "name": "John Doe",
    "email": "john@example.com",
    "message": "Hello world"
  },
  "meta": {
    "submitted_at": "2024-01-15T10:30:00.000Z",
    "user_agent": "Mozilla/5.0...",
    "referrer": "https://example.com/contact"
  }
}
```

## DM Format

Form owners receive submissions as Nostr DMs (kind 4):

```
New submission to "Contact Form"
Form ID: xK7mN2pQ
Time: 2024-01-15 10:30:00 UTC

--- Fields ---
name: John Doe
email: john@example.com
message: Hello world

--- Metadata ---
submitted_at: 2024-01-15T10:30:00.000Z
user_agent: Mozilla/5.0...
```

## PoW Difficulty Guidelines

| Difficulty | Avg Time | Use Case |
|------------|----------|----------|
| 8 bits | <1 sec | Testing only |
| 12 bits | 1-5 sec | Low-traffic forms |
| 16 bits | 5-30 sec | Standard contact forms |
| 20 bits | 30-120 sec | High-value forms, strong spam protection |
| 24 bits | 2-10 min | Maximum protection |

## Styling

The SDK adds these classes during submission:

```css
/* Form is being submitted */
form.submitting {
  opacity: 0.7;
  pointer-events: none;
}

/* Success message (default behavior) */
.nostr-form-success {
  color: green;
  text-align: center;
  padding: 1rem;
}
```

## Error Handling

Common errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| `processorPubkey not configured` | Missing init config | Call `NostrForms.init()` with pubkey |
| `relayUrl not configured` | Missing init config | Call `NostrForms.init()` with relay URL |
| `Event rejected by relay` | PoW too low or relay issue | Increase PoW difficulty |
| `Timeout waiting for relay` | Relay unreachable | Check relay URL and connectivity |
| `No Nostr extension found` | NIP-07 requested but unavailable | Install Alby/nos2x or disable auth |

## Security Notes

1. **Client-side encryption**: Data is encrypted in the browser before transmission
2. **No plaintext on wire**: Relay never sees unencrypted form data
3. **PoW spam protection**: Computational cost deters automated submissions
4. **Ephemeral keys**: Anonymous submissions use throwaway keypairs
5. **Authenticated submissions**: Optional NIP-07 signing for verified identity

## Hosting forms.js

Options for hosting the SDK:

1. **Self-host**: Copy `forms.js` to your static assets
2. **CDN**: Host on your CDN or use unpkg/jsdelivr
3. **Inline**: Bundle into your application

The SDK dynamically imports `nostr-tools` from esm.sh. For offline use, bundle nostr-tools locally.

## API Reference

### Create Form
```
POST /api/forms
Authorization: Nostr <base64-nip98-event>
Content-Type: application/json

{
  "name": "Contact Form",
  "notify_pubkey": "hex-pubkey",
  "pow_difficulty": 16
}
```

### List Forms
```
GET /api/forms
Authorization: Nostr <base64-nip98-event>
```

### Get Form Details
```
GET /api/forms/{form_id}
Authorization: Nostr <base64-nip98-event>
```

### Get Embed Code
```
GET /api/forms/{form_id}/embed
Authorization: Nostr <base64-nip98-event>
```

### List Submissions
```
GET /api/forms/{form_id}/submissions?limit=50
Authorization: Nostr <base64-nip98-event>
```

### Get Processor Config (Public)
```
GET /api/config

Response: { "processor_pubkey": "...", "default_pow_difficulty": 16 }
```
