import { describe, it, expect } from 'vitest';
import * as nostrTools from 'nostr-tools';

describe('NIP-44 Encryption', () => {
  it('encrypts and decrypts a message', () => {
    const senderPrivkey = nostrTools.generateSecretKey();
    const senderPubkey = nostrTools.getPublicKey(senderPrivkey);
    
    const recipientPrivkey = nostrTools.generateSecretKey();
    const recipientPubkey = nostrTools.getPublicKey(recipientPrivkey);
    
    const plaintext = 'Hello, Nostr!';
    
    // Encrypt from sender to recipient
    const senderConvKey = nostrTools.nip44.getConversationKey(senderPrivkey, recipientPubkey);
    const ciphertext = nostrTools.nip44.encrypt(plaintext, senderConvKey);
    
    // Decrypt as recipient
    const recipientConvKey = nostrTools.nip44.getConversationKey(recipientPrivkey, senderPubkey);
    const decrypted = nostrTools.nip44.decrypt(ciphertext, recipientConvKey);
    
    expect(decrypted).toBe(plaintext);
  });
  
  it('encrypts JSON payload', () => {
    const senderPrivkey = nostrTools.generateSecretKey();
    const recipientPrivkey = nostrTools.generateSecretKey();
    const recipientPubkey = nostrTools.getPublicKey(recipientPrivkey);
    const senderPubkey = nostrTools.getPublicKey(senderPrivkey);
    
    const payload = {
      v: 1,
      form_id: 'test123',
      fields: {
        name: 'John Doe',
        email: 'john@example.com',
        message: 'Hello, this is a test message!'
      },
      meta: {
        submitted_at: new Date().toISOString()
      }
    };
    
    const plaintext = JSON.stringify(payload);
    
    // Encrypt
    const convKey = nostrTools.nip44.getConversationKey(senderPrivkey, recipientPubkey);
    const ciphertext = nostrTools.nip44.encrypt(plaintext, convKey);
    
    // Decrypt
    const recipientConvKey = nostrTools.nip44.getConversationKey(recipientPrivkey, senderPubkey);
    const decrypted = nostrTools.nip44.decrypt(ciphertext, recipientConvKey);
    const decryptedPayload = JSON.parse(decrypted);
    
    expect(decryptedPayload.v).toBe(1);
    expect(decryptedPayload.form_id).toBe('test123');
    expect(decryptedPayload.fields.name).toBe('John Doe');
  });
});

describe('Event Signing', () => {
  it('creates valid signed event', () => {
    const privkey = nostrTools.generateSecretKey();
    const pubkey = nostrTools.getPublicKey(privkey);
    
    const event = {
      kind: 4,
      pubkey: pubkey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['p', 'recipient_pubkey_here'],
        ['form_id', 'test123']
      ],
      content: 'encrypted_content_here'
    };
    
    const signedEvent = nostrTools.finalizeEvent(event, privkey);
    
    expect(signedEvent.id).toBeDefined();
    expect(signedEvent.sig).toBeDefined();
    expect(signedEvent.id.length).toBe(64);
    expect(signedEvent.sig.length).toBe(128);
    
    // Verify signature
    const isValid = nostrTools.verifyEvent(signedEvent);
    expect(isValid).toBe(true);
  });
});

describe('PoW Mining', () => {
  it('counts leading zero bits correctly', () => {
    // Helper function from forms.js
    function countLeadingZeroBits(hexStr) {
      let count = 0;
      for (const char of hexStr) {
        const nibble = parseInt(char, 16);
        if (nibble === 0) {
          count += 4;
        } else {
          if (nibble < 8) count += 1;
          if (nibble < 4) count += 1;
          if (nibble < 2) count += 1;
          break;
        }
      }
      return count;
    }
    
    // 0000 = 16 bits
    expect(countLeadingZeroBits('0000abcd')).toBe(16);
    
    // 0001 = 15 bits (0000 0000 0000 0001)
    expect(countLeadingZeroBits('0001abcd')).toBe(15);
    
    // 000f = 12 bits
    expect(countLeadingZeroBits('000fabcd')).toBe(12);
    
    // 00ff = 8 bits
    expect(countLeadingZeroBits('00ffabcd')).toBe(8);
    
    // 0fff = 4 bits
    expect(countLeadingZeroBits('0fffabcd')).toBe(4);
    
    // 1fff = 3 bits
    expect(countLeadingZeroBits('1fffabcd')).toBe(3);
    
    // ffff = 0 bits
    expect(countLeadingZeroBits('ffffabcd')).toBe(0);
  });
  
  it('mines valid PoW', async () => {
    const privkey = nostrTools.generateSecretKey();
    const pubkey = nostrTools.getPublicKey(privkey);
    
    const difficulty = 8; // Low difficulty for fast test
    
    let event = {
      kind: 4,
      pubkey: pubkey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['p', 'recipient_pubkey_here'],
        ['nonce', '0', difficulty.toString()]
      ],
      content: 'test'
    };
    
    // Mine
    let nonce = 0;
    let id;
    
    while (true) {
      event.tags[1] = ['nonce', nonce.toString(), difficulty.toString()];
      
      const serialized = JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
      ]);
      
      // Use Web Crypto API
      const encoder = new TextEncoder();
      const data = encoder.encode(serialized);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      id = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Check leading zeros
      const leadingZeros = countLeadingZeroBits(id);
      if (leadingZeros >= difficulty) {
        break;
      }
      
      nonce++;
      if (nonce > 1000000) {
        throw new Error('PoW mining took too long');
      }
    }
    
    // Verify the ID has required leading zeros
    function countLeadingZeroBits(hexStr) {
      let count = 0;
      for (const char of hexStr) {
        const nibble = parseInt(char, 16);
        if (nibble === 0) {
          count += 4;
        } else {
          if (nibble < 8) count += 1;
          if (nibble < 4) count += 1;
          if (nibble < 2) count += 1;
          break;
        }
      }
      return count;
    }
    
    expect(countLeadingZeroBits(id)).toBeGreaterThanOrEqual(difficulty);
  });
});
