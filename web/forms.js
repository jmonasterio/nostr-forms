/**
 * nostr-form-rs Browser SDK
 * 
 * Encrypted form submissions via Nostr protocol.
 * Requires nostr-tools: https://github.com/nbd-wtf/nostr-tools
 * 
 * Usage:
 *   <form data-nostr-form="FORM_ID">
 *     <input name="email" type="email" />
 *     <textarea name="message"></textarea>
 *     <button type="submit">Send</button>
 *   </form>
 *   
 *   <script type="module">
 *     import { NostrForms } from './forms.js';
 *     NostrForms.init({
 *       submitUrl: 'https://forms.argw.com/submit',
 *       processorPubkey: '...'
 *     });
 *   </script>
 */

// Configuration
let config = {
  submitUrl: 'https://forms.argw.com/submit',
  processorPubkey: null,
  // Proof-of-work bits (NIP-13). The processor enforces each form's own
  // `pow_difficulty`; `data-pow` on a form overrides this default.
  powDifficulty: 16,
  // Call onSuccess(null, form) as soon as the user submits and send in the
  // background; a failure then calls onError(err, form), which must undo
  // whatever onSuccess showed. Needs both callbacks.
  optimistic: false,
  onSuccess: null,
  onError: null,
  onProgress: null
};

// Dynamically import nostr-tools (ESM)
let nostrTools = null;

async function loadNostrTools() {
  if (nostrTools) return nostrTools;

  try {
    nostrTools = await import('https://esm.sh/nostr-tools@2');
    return nostrTools;
  } catch (e) {
    console.error('Failed to load nostr-tools:', e);
    throw new Error('nostr-tools required. Include via: import from "https://esm.sh/nostr-tools@2"');
  }
}

/**
 * Initialize the SDK
 */
export function init(options) {
  config = { ...config, ...options };
  // Start fetching nostr-tools now so the first submit does not wait on it.
  loadNostrTools().catch(() => {});
  initForms();
}

/**
 * Submit a form programmatically
 */
export async function submit(formElement) {
  return submitForm(formElement);
}

/**
 * Build and submit a form
 */
async function submitForm(form) {
  const nt = await loadNostrTools();
  
  const formId = form.dataset.nostrForm;
  const allowAuth = form.dataset.allowAuth === 'true';
  const formPow = form.dataset.pow ? parseInt(form.dataset.pow) : config.powDifficulty;
  const submitUrl = config.submitUrl;
  const processorPubkey = config.processorPubkey;
  
  if (!formId) {
    throw new Error('Missing data-nostr-form attribute');
  }
  
  if (!processorPubkey) {
    throw new Error('processorPubkey not configured');
  }
  
  if (!submitUrl) {
    throw new Error('submitUrl not configured');
  }
  
  // Collect form data
  const formData = {};
  const inputs = form.querySelectorAll('input, textarea, select');
  inputs.forEach(input => {
    if (input.name && input.name !== '') {
      formData[input.name] = input.value;
    }
  });
  
  // Build payload
  const payload = {
    v: 1,
    form_id: formId,
    fields: formData,
    meta: {
      submitted_at: new Date().toISOString(),
      user_agent: navigator.userAgent,
      referrer: document.referrer || null
    }
  };
  
  if (config.onProgress) config.onProgress('encrypting');
  
  // Determine signing mode.
  // NIP-07 extensions sign but never expose the private key, so we always
  // generate an ephemeral keypair for NIP-44 encryption.  The ephemeral
  // pubkey is included in the event so the processor can derive the shared
  // secret via ECDH(ephemeral_privkey, processor_pubkey).
  let senderPrivkey = nt.generateSecretKey();
  let senderPubkey  = nt.getPublicKey(senderPrivkey);
  let submissionType = 'anon';
  let signEvent;

  if (allowAuth && window.nostr) {
    try {
      // Use the NIP-07 extension pubkey as the visible sender identity.
      // Signing is done by the extension; encryption uses the ephemeral key.
      const nip07Pubkey = await window.nostr.getPublicKey();
      senderPubkey   = nip07Pubkey;
      submissionType = 'authenticated';
      signEvent = async (event) => window.nostr.signEvent(event);
    } catch (e) {
      console.warn('NIP-07 signing failed, falling back to ephemeral key:', e);
    }
  }

  if (!signEvent) {
    signEvent = async (event) => nt.finalizeEvent(event, senderPrivkey);
  }

  // Encrypt payload using the ephemeral private key.
  // The processor decrypts with ECDH(ephemeral_pubkey, processor_privkey).
  const payloadJson = JSON.stringify(payload);
  const conversationKey = nt.nip44.getConversationKey(senderPrivkey, processorPubkey);
  const encryptedContent = nt.nip44.encrypt(payloadJson, conversationKey);

  // Build event
  let event = {
    kind: 4,
    pubkey: senderPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['p', processorPubkey],
      ['form_id', formId],
      ['nonce', '0', formPow.toString()],
      ['submission_type', submissionType],
      // Include ephemeral pubkey so processor can decrypt even when sender
      // is a NIP-07 identity (whose private key the processor doesn't have).
      ['ephemeral', nt.getPublicKey(senderPrivkey)]
    ],
    content: encryptedContent
  };
  
  // Mine PoW
  if (config.onProgress) config.onProgress('mining');
  event = await minePoW(event, formPow, config.onProgress);
  
  // Sign event
  const signedEvent = await signEvent(event);
  
  // Submit to the form processor
  if (config.onProgress) config.onProgress('publishing');
  const eventId = await postEvent(signedEvent, submitUrl);
  
  return eventId;
}

/**
 * Mine proof-of-work for an event
 */
async function minePoW(event, difficulty, onProgress) {
  // The NIP-01 id is sha256 of [0,pubkey,created_at,kind,tags,content]; only
  // the nonce changes between attempts. Serialize once around a marker, then
  // hash BATCH candidates at a time with WebCrypto running in parallel: the
  // encrypted content follows the tags, so every attempt re-hashes the whole
  // message and native SHA-256 is the fast path for that.
  const nonceTagIndex = event.tags.findIndex(t => t[0] === 'nonce');
  const MARK = '__NONCE__';
  event.tags[nonceTagIndex] = ['nonce', MARK, difficulty.toString()];
  const [prefix, suffix] = JSON.stringify([
    0, event.pubkey, event.created_at, event.kind, event.tags, event.content
  ]).split(MARK);
  const enc = new TextEncoder();
  const BATCH = 1024;

  for (let start = 0; ; start += BATCH) {
    const digests = await Promise.all(Array.from({ length: BATCH }, (_, i) =>
      crypto.subtle.digest('SHA-256', enc.encode(prefix + (start + i) + suffix))
    ));
    for (let i = 0; i < BATCH; i++) {
      const digest = new Uint8Array(digests[i]);
      if (leadingZeroBits(digest) >= difficulty) {
        event.tags[nonceTagIndex] = ['nonce', String(start + i), difficulty.toString()];
        event.id = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
        return event;
      }
    }
    if (onProgress && start % (BATCH * 16) === 0) onProgress('mining', { nonce: start, difficulty });
  }
}

/**
 * Count leading zero bits of a byte array
 */
function leadingZeroBits(bytes) {
  let count = 0;
  for (const b of bytes) {
    if (b === 0) { count += 8; continue; }
    return count + Math.clz32(b) - 24;
  }
  return count;
}

/**
 * POST the signed event to the form processor's /submit endpoint.
 * The relay no longer accepts anonymous writes (nostr-relay-rs 52e1acc,
 * 2026-07-26), so the processor takes the event directly.
 */
async function postEvent(event, submitUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const resp = await fetch(submitUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
      signal: controller.signal,
      // The page may already say "sent" (optimistic mode); let the request
      // finish if the visitor navigates away.
      keepalive: true
    });
    let body = null;
    try { body = await resp.json(); } catch (_) { /* non-JSON error page */ }
    if (!resp.ok || !body || !body.ok) {
      throw new Error((body && body.reason) || `Submit failed (HTTP ${resp.status})`);
    }
    return body.id;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Handle form submission
 */
async function handleSubmit(e) {
  e.preventDefault();
  const form = e.target;
  if (form.classList.contains('submitting')) return;

  form.classList.add('submitting');
  const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;

  const optimistic = config.optimistic && config.onSuccess && config.onError;
  if (optimistic) config.onSuccess(null, form);

  try {
    const eventId = await submitForm(form);
    if (optimistic) {
      // Already shown.
    } else if (config.onSuccess) {
      config.onSuccess(eventId, form);
    } else {
      form.innerHTML = '<p class="nostr-form-success">Thank you! Your message has been sent.</p>';
    }
  } catch (err) {
    console.error('Form submission failed:', err);
    if (config.onError) {
      config.onError(err, form);
    } else {
      alert('Failed to send message: ' + err.message);
    }
  } finally {
    form.classList.remove('submitting');
    if (submitBtn) submitBtn.disabled = false;
  }
}

/**
 * Initialize forms on page
 */
function initForms() {
  const forms = document.querySelectorAll('[data-nostr-form]');
  forms.forEach(form => {
    form.addEventListener('submit', handleSubmit);
  });
}

// Expose for non-module callers. `init()` attaches the submit handlers.
if (typeof window !== 'undefined') {
  window.NostrForms = { init, submit };
}

export const NostrForms = { init, submit };
