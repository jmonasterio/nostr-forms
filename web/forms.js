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
 *       relayUrl: 'wss://relay.example.com',
 *       processorPubkey: '...'
 *     });
 *   </script>
 */

// Configuration
let config = {
  relayUrl: null,
  processorPubkey: null,
  powDifficulty: 16,
  onSuccess: null,
  onError: null,
  onProgress: null
};

// Dynamically import nostr-tools (ESM)
let nostrTools = null;

async function loadNostrTools() {
  if (nostrTools) return nostrTools;
  
  try {
    // Try loading from CDN
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
  const formRelay = form.dataset.relay || config.relayUrl;
  const processorPubkey = config.processorPubkey;
  
  if (!formId) {
    throw new Error('Missing data-nostr-form attribute');
  }
  
  if (!processorPubkey) {
    throw new Error('processorPubkey not configured');
  }
  
  if (!formRelay) {
    throw new Error('relayUrl not configured');
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
  
  // Publish to relay
  if (config.onProgress) config.onProgress('publishing');
  const eventId = await publishEvent(signedEvent, formRelay);
  
  return eventId;
}

/**
 * Mine proof-of-work for an event
 */
async function minePoW(event, difficulty, onProgress) {
  const nt = await loadNostrTools();
  
  let nonce = 0;
  const nonceTagIndex = event.tags.findIndex(t => t[0] === 'nonce');
  
  while (true) {
    event.tags[nonceTagIndex] = ['nonce', nonce.toString(), difficulty.toString()];
    
    // Compute event ID
    const serialized = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ]);
    
    const id = await sha256Hex(serialized);
    
    // Check leading zero bits
    if (countLeadingZeroBits(id) >= difficulty) {
      event.id = id;
      return event;
    }
    
    nonce++;
    
    // Progress callback
    if (nonce % 5000 === 0 && onProgress) {
      onProgress('mining', { nonce, difficulty });
    }
    
    // Yield to prevent blocking
    if (nonce % 10000 === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
}

/**
 * Count leading zero bits in a hex string
 */
function countLeadingZeroBits(hexStr) {
  let count = 0;
  for (const char of hexStr) {
    const nibble = parseInt(char, 16);
    if (nibble === 0) {
      count += 4;
    } else {
      // Count leading zeros in this nibble
      if (nibble < 8) count += 1;
      if (nibble < 4) count += 1;
      if (nibble < 2) count += 1;
      break;
    }
  }
  return count;
}

/**
 * SHA-256 hash to hex
 */
async function sha256Hex(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Publish event to relay
 */
async function publishEvent(event, relayUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(relayUrl);
    let resolved = false;
    
    ws.onopen = () => {
      const msg = JSON.stringify(['EVENT', event]);
      ws.send(msg);
    };
    
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg[0] === 'OK' && msg[1] === event.id) {
          resolved = true;
          ws.close();
          if (msg[2]) {
            resolve(event.id);
          } else {
            reject(new Error(msg[3] || 'Event rejected by relay'));
          }
        }
      } catch (err) {
        // Ignore parse errors
      }
    };
    
    ws.onerror = () => {
      if (!resolved) {
        reject(new Error('WebSocket error'));
      }
    };
    
    ws.onclose = () => {
      if (!resolved) {
        reject(new Error('Connection closed before confirmation'));
      }
    };
    
    // Timeout
    setTimeout(() => {
      if (!resolved) {
        ws.close();
        reject(new Error('Timeout waiting for relay response'));
      }
    }, 30000);
  });
}

/**
 * Handle form submission
 */
async function handleSubmit(e) {
  e.preventDefault();
  const form = e.target;
  
  form.classList.add('submitting');
  const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;
  
  try {
    const eventId = await submitForm(form);
    
    if (config.onSuccess) {
      config.onSuccess(eventId);
    } else {
      form.innerHTML = '<p class="nostr-form-success">Thank you! Your message has been sent.</p>';
    }
  } catch (err) {
    console.error('Form submission failed:', err);
    
    if (config.onError) {
      config.onError(err);
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

// Auto-init on DOM ready if not using ES modules
if (typeof window !== 'undefined') {
  window.NostrForms = { init, submit };
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      // Only auto-init if config was set via global
      if (config.relayUrl && config.processorPubkey) {
        initForms();
      }
    });
  }
}

export const NostrForms = { init, submit };
