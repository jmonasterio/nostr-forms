# User Manual: nostr-form-rs

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Creating Your First Form](#creating-your-first-form)
5. [Embedding Forms](#embedding-forms)
6. [Receiving Submissions](#receiving-submissions)
7. [Managing Submissions](#managing-submissions)
8. [Security](#security)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

nostr-form-rs lets you add encrypted contact forms to any website. Submissions are encrypted in the visitor's browser, transmitted through Nostr, and delivered to you as encrypted DMs.

### How It Works

1. Visitor fills out form on your website
2. Browser encrypts data to your processor's pubkey
3. Browser mines proof-of-work (spam prevention)
4. Encrypted event published to Nostr relay
5. Processor (running on your network) receives event
6. Processor decrypts and sends you a Nostr DM

### Who Is This For?

- Website owners who want contact forms without third-party services
- Privacy-conscious users who don't want intermediaries reading messages
- Nostr users who want form submissions delivered to their existing Nostr client

### Requirements

- A running Nostr relay (nostr-inbox-rs or any NIP-01 relay)
- A Nostr client to receive DMs (Damus, Amethyst, etc.)
- Ability to add JavaScript to your website

### Network Requirements

**Processor only needs outbound connectivity:**
- WebSocket to relay (for subscribing and sending DMs)
- No public IP required
- No open ports required
- Can run behind NAT/firewall

---

## Installation

### Option 1: Build from Source

```bash
git clone https://github.com/YOUR_USERNAME/nostr-form-rs
cd nostr-form-rs
cargo build --release
```

### Option 2: Download Binary

```bash
# Linux/macOS
curl -L https://github.com/YOUR_USERNAME/nostr-form-rs/releases/latest/download/nostr-form-rs -o nostr-form-rs
chmod +x nostr-form-rs
```

---

## Configuration

Create a `config.json` file:

```json
{
  "relay_url": "ws://127.0.0.1:8080",
  "database_path": "./forms.db",
  "api_bind_addr": "127.0.0.1:8081",
  "default_pow_difficulty": 16
}
```

### Configuration Fields

#### relay_url

The WebSocket URL of your Nostr relay. The processor connects here to:
- Subscribe for incoming form submissions
- Send DM notifications to form owners

```json
"relay_url": "ws://127.0.0.1:8080"
```

For remote relay with TLS:
```json
"relay_url": "wss://relay.yourdomain.com"
```

#### database_path

Where form configurations and submission logs are stored.

```json
"database_path": "./forms.db"
```

#### api_bind_addr

Address for the admin API and UI. Only needs to be accessible from your local network.

```json
"api_bind_addr": "127.0.0.1:8081"
```

#### default_pow_difficulty

Minimum proof-of-work bits required for submissions.

| Difficulty | Approx. Time | Spam Protection |
|------------|--------------|-----------------|
| 12 | ~10ms | Light |
| 16 | ~100ms | Moderate (recommended) |
| 18 | ~400ms | Strong |
| 20 | ~1.5s | Very strong |

---

## Creating Your First Form

### Step 1: Start the Processor

```bash
./nostr-form-rs
```

On first run, it generates a keypair and prints:

```
Processor pubkey: abc123...
Add this pubkey to your relay's authorized_pubkeys list.
```

### Step 2: Authorize the Processor

Add the processor's pubkey to your relay's whitelist.

For nostr-inbox-rs (`config.json`):
```json
{
  "authorized_pubkeys": [
    "your_personal_pubkey",
    "abc123..."
  ]
}
```

Restart the relay.

### Step 3: Create a Form

Open `http://localhost:8081/admin` and click **"New Form"**.

Fill in:
- **Name**: Internal identifier (e.g., "Contact Form")
- **Notify Pubkey**: Your Nostr pubkey (where you'll receive submissions)
- **PoW Difficulty**: Leave default (16) unless you have spam issues

Click **"Create"**.

### Step 4: Get Embed Code

Click on the form to see its embed code:

```html
<form data-nostr-form="FORM_ID">
  <input name="name" required />
  <input name="email" type="email" required />
  <textarea name="message" required></textarea>
  <button type="submit">Send</button>
</form>
<script src="https://raw.githubusercontent.com/USER/nostr-form-rs/main/web/forms.js"></script>
```

---

## Embedding Forms

### Basic Embed

Add this HTML to your website:

```html
<form data-nostr-form="YOUR_FORM_ID">
  <div>
    <label for="name">Name</label>
    <input type="text" name="name" id="name" required />
  </div>
  
  <div>
    <label for="email">Email</label>
    <input type="email" name="email" id="email" required />
  </div>
  
  <div>
    <label for="message">Message</label>
    <textarea name="message" id="message" required></textarea>
  </div>
  
  <button type="submit">Send Message</button>
</form>

<script src="https://raw.githubusercontent.com/YOUR_USERNAME/nostr-form-rs/main/web/forms.js"></script>

<script>
NostrForms.init({
  relayUrl: 'wss://your-relay.com',
  processorPubkey: 'YOUR_PROCESSOR_PUBKEY'
});
</script>
```

### Styling

The form uses your existing CSS. Style it like any HTML form.

### Allow Authenticated Submissions

If you want visitors with Nostr extensions to optionally identify themselves:

```html
<form data-nostr-form="YOUR_FORM_ID" data-allow-auth="true">
  ...
</form>
```

When a visitor has Alby, nos2x, or another NIP-07 extension, they can choose to sign with their real Nostr identity.

### Custom Success/Error Handling

```html
<script>
NostrForms.init({
  relayUrl: 'wss://your-relay.com',
  processorPubkey: 'YOUR_PROCESSOR_PUBKEY',
  onSuccess: function(eventId) {
    document.getElementById('my-form').innerHTML = 
      '<p>Thank you! Your message has been sent.</p>';
  },
  onError: function(error) {
    alert('Failed to send: ' + error.message);
  }
});
</script>
```

---

## Receiving Submissions

Submissions arrive as **Nostr DMs** to the pubkey you specified when creating the form.

### Where to Check

Open any Nostr client that supports DMs:
- **Damus** (iOS)
- **Amethyst** (Android)
- **Snort** (Web)
- **Coracle** (Web)

Look in your DM inbox for messages from the processor's pubkey.

### DM Format

```
New form submission: Contact Form

Name: John Doe
Email: john@example.com
Message: Hello, I have a question about...

---
Form ID: abc123
Event ID: def456...
Submitted: 2024-01-15 10:30:00 UTC
```

---

## Managing Submissions

### Admin Dashboard

Open `http://localhost:8081/admin` to:
- View all forms
- See submission history
- Check delivery status
- Retry failed deliveries

### Submission Status

| Status | Meaning |
|--------|---------|
| `pending` | Received, DM not yet sent |
| `delivered` | DM sent successfully |
| `failed` | DM sending failed (will retry) |
| `exhausted` | Max retries reached |

### Retrying Failed Deliveries

Click "Retry" on any failed submission, or via API:

```bash
curl -X POST http://localhost:8081/api/submissions/EVENT_ID/retry
```

---

## Security

### What's Encrypted

| Data | Encrypted? |
|------|-----------|
| Form field values | Yes (NIP-44) |
| Field names | Yes |
| Timestamp | No (in Nostr event) |
| Sender pubkey | No (but ephemeral by default) |
| Form ID | No |

### Key Security

The processor has ONE private key that decrypts ALL form submissions. Protect it:

- Store `forms.db` securely
- Restrict access to the processor machine
- Back up the database (contains the key)

### Anonymous vs Authenticated Submissions

| Mode | Sender Identity |
|------|-----------------|
| Anonymous (default) | Random ephemeral key (unlinkable) |
| Authenticated | Visitor's real Nostr pubkey (if they opt in) |

### Spam Prevention

Proof-of-work makes spam expensive:

- Each submission requires CPU work
- Legitimate users: ~100ms delay
- Spammers: expensive at scale

Increase difficulty if you see abuse:

```bash
curl -X PATCH http://localhost:8081/api/forms/FORM_ID \
  -d '{"pow_difficulty": 20}'
```

---

## Troubleshooting

### Form Doesn't Submit

**Check browser console for errors.**

1. **"Failed to connect to relay"**
   - Is the relay running?
   - Is the WebSocket URL correct in `NostrForms.init()`?
   
2. **"PoW rejected"**
   - Form difficulty might be set very high
   - Check processor logs

3. **"Invalid form_id"**
   - Form doesn't exist in processor registry
   - Check form_id in embed code matches admin UI

### Not Receiving DMs

1. **Check submission status** in admin UI - is it "delivered"?

2. **Check processor logs** for errors

3. **Verify notify_pubkey** is correct (your Nostr pubkey)

4. **Check your Nostr client** is connected to the same relay

### Processor Can't Connect to Relay

1. **Check relay is running**

2. **Check relay URL** in config.json

3. **Check processor pubkey is authorized** in relay config

### High Spam Volume

1. **Increase PoW difficulty**:
   ```bash
   curl -X PATCH http://localhost:8081/api/forms/FORM_ID \
     -d '{"pow_difficulty": 20}'
   ```

2. **Lower rate limits**:
   ```bash
   curl -X PATCH http://localhost:8081/api/forms/FORM_ID \
     -d '{"rate_limit_per_hour": 20}'
   ```

3. **Temporarily disable form**:
   ```bash
   curl -X PATCH http://localhost:8081/api/forms/FORM_ID \
     -d '{"status": "paused"}'
   ```

---

## API Reference

### Forms

```bash
# Create form
curl -X POST http://localhost:8081/api/forms \
  -H "Content-Type: application/json" \
  -d '{"name": "Contact", "notify_pubkey": "YOUR_PUBKEY"}'

# List forms
curl http://localhost:8081/api/forms

# Get form
curl http://localhost:8081/api/forms/FORM_ID

# Update form
curl -X PATCH http://localhost:8081/api/forms/FORM_ID \
  -d '{"pow_difficulty": 18}'

# Delete form
curl -X DELETE http://localhost:8081/api/forms/FORM_ID

# Get embed code
curl http://localhost:8081/api/forms/FORM_ID/embed
```

### Submissions

```bash
# List submissions for form
curl http://localhost:8081/api/forms/FORM_ID/submissions

# Retry failed submission
curl -X POST http://localhost:8081/api/submissions/EVENT_ID/retry
```

### Config

```bash
# Get processor pubkey
curl http://localhost:8081/api/config
```
