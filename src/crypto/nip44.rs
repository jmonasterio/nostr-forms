//! NIP-44 encryption/decryption
//!
//! Implements versioned encryption with XChaCha20-Poly1305.
//! Reference: https://github.com/nostr-protocol/nips/blob/master/44.md

use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;

const NIP44_VERSION: u8 = 2;

/// Encrypt a message using NIP-44
pub fn encrypt(
    plaintext: &str,
    sender_privkey: &SecretKey,
    recipient_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    let secp = Secp256k1::new();

    // Compute shared secret using ECDH
    let shared_secret = SharedSecret::new(recipient_pubkey, sender_privkey);
    let conversation_key = derive_conversation_key(shared_secret.as_ref())?;

    // Generate random nonce (24 bytes for XChaCha20)
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive message keys
    let (chacha_key, chacha_nonce) = derive_message_keys(&conversation_key, &nonce_bytes)?;

    // Pad plaintext
    let padded = pad_plaintext(plaintext.as_bytes())?;

    // Encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&chacha_key)?;
    let nonce = XNonce::from_slice(&chacha_nonce);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Build payload: version (1) + nonce (24) + ciphertext
    let mut payload = Vec::with_capacity(1 + 24 + ciphertext.len());
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(BASE64_STANDARD.encode(&payload))
}

/// Decrypt a NIP-44 encrypted message
pub fn decrypt(
    ciphertext_b64: &str,
    recipient_privkey: &SecretKey,
    sender_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    let payload = BASE64_STANDARD.decode(ciphertext_b64)?;

    if payload.is_empty() {
        anyhow::bail!("Empty payload");
    }

    let version = payload[0];
    if version != NIP44_VERSION {
        anyhow::bail!("Unsupported NIP-44 version: {}", version);
    }

    if payload.len() < 1 + 24 + 16 {
        // version + nonce + minimum ciphertext (tag only)
        anyhow::bail!("Payload too short");
    }

    let nonce_bytes = &payload[1..25];
    let ciphertext = &payload[25..];

    // Compute shared secret using ECDH
    let shared_secret = SharedSecret::new(sender_pubkey, recipient_privkey);
    let conversation_key = derive_conversation_key(shared_secret.as_ref())?;

    // Derive message keys
    let (chacha_key, chacha_nonce) = derive_message_keys(&conversation_key, nonce_bytes)?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&chacha_key)?;
    let nonce = XNonce::from_slice(&chacha_nonce);
    let padded = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    // Unpad
    let plaintext = unpad_plaintext(&padded)?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))
}

/// Derive conversation key from shared secret
fn derive_conversation_key(shared_secret: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"nip44-v2"), shared_secret);
    let mut conversation_key = [0u8; 32];
    hk.expand(b"nip44-v2", &mut conversation_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(conversation_key)
}

/// Derive message keys from conversation key and nonce
fn derive_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8],
) -> anyhow::Result<([u8; 32], [u8; 24])> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), conversation_key);

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 24];

    hk.expand(b"nip44-v2", &mut chacha_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand key failed"))?;

    // For the nonce, we use a second HKDF expansion
    let mut nonce_material = [0u8; 24];
    let hk2 = Hkdf::<Sha256>::new(Some(&chacha_key), nonce);
    hk2.expand(b"nip44-v2", &mut nonce_material)
        .map_err(|_| anyhow::anyhow!("HKDF expand nonce failed"))?;
    chacha_nonce.copy_from_slice(&nonce_material);

    Ok((chacha_key, chacha_nonce))
}

/// Pad plaintext according to NIP-44 spec
fn pad_plaintext(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let len = plaintext.len();
    if len > 65535 {
        anyhow::bail!("Plaintext too long");
    }

    // Calculate padded length (next power of 2, minimum 32)
    let padded_len = calc_padded_len(len);

    let mut padded = Vec::with_capacity(2 + padded_len);
    // Length prefix (big-endian u16)
    padded.push((len >> 8) as u8);
    padded.push((len & 0xff) as u8);
    padded.extend_from_slice(plaintext);
    // Pad with zeros
    padded.resize(2 + padded_len, 0);

    Ok(padded)
}

/// Unpad plaintext according to NIP-44 spec
fn unpad_plaintext(padded: &[u8]) -> anyhow::Result<Vec<u8>> {
    if padded.len() < 2 {
        anyhow::bail!("Padded data too short");
    }

    let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if len + 2 > padded.len() {
        anyhow::bail!("Invalid padding length");
    }

    Ok(padded[2..2 + len].to_vec())
}

/// Calculate padded length for NIP-44
fn calc_padded_len(len: usize) -> usize {
    if len <= 32 {
        32
    } else {
        let next_power = (len + 1).next_power_of_two();
        next_power.max(32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sender_priv, sender_pub) = generate_keypair();
        let (recipient_priv, recipient_pub) = generate_keypair();

        let plaintext = "Hello, Nostr!";
        let encrypted = encrypt(plaintext, &sender_priv, &recipient_pub).unwrap();
        let decrypted = decrypt(&encrypted, &recipient_priv, &sender_pub).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_padding() {
        // Short message
        let padded = pad_plaintext(b"hi").unwrap();
        assert_eq!(padded.len(), 2 + 32); // 2 byte length + 32 byte padded content

        // Longer message
        let msg = "a".repeat(100);
        let padded = pad_plaintext(msg.as_bytes()).unwrap();
        assert_eq!(padded.len(), 2 + 128); // Next power of 2 >= 100 is 128

        // Unpad
        let unpadded = unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, msg.as_bytes());
    }
}
