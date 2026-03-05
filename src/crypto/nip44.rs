//! NIP-44 v2 encryption/decryption.
//!
//! Implements the spec exactly:
//!   - ECDH x-coordinate as shared secret
//!   - `conversation_key` = HKDF-Extract(salt="nip44-v2", IKM=shared_x)
//!   - `message_keys`     = HKDF-Expand(PRK=conversation_key, info=nonce, L=76)
//!   - ChaCha20 (RFC 8439, 12-byte nonce) for encryption
//!   - HMAC-SHA256(key=hmac_key, data=nonce‖ciphertext) for authentication
//!   - 32-byte random nonce per message
//!   - Payload: base64(version[1] ‖ nonce[32] ‖ ciphertext ‖ mac[32])
//!
//! Reference: https://github.com/nostr-protocol/nips/blob/master/44.md

use base64::prelude::*;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as ChaChaKey, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const NIP44_VERSION: u8 = 2;
/// Nonce is 32 bytes per spec (section 2: "Generate a random 32-byte nonce").
const NONCE_LEN: usize = 32;
/// MAC is 32 bytes (HMAC-SHA256 output).
const MAC_LEN: usize = 32;
/// Minimum decoded payload: version(1) + nonce(32) + min_ciphertext(34) + mac(32) = 99 bytes.
/// min_ciphertext = 2-byte length prefix + 32-byte padded block (1-byte plaintext → pad to 32).
const MIN_PAYLOAD_LEN: usize = 1 + NONCE_LEN + 34 + MAC_LEN; // 99

/// Encrypt a message using NIP-44 v2.
pub fn encrypt(
    plaintext: &str,
    sender_privkey: &SecretKey,
    recipient_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    let shared_x = ecdh_x_only(sender_privkey, recipient_pubkey);
    let conversation_key = derive_conversation_key(&shared_x);

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    encrypt_inner(plaintext, &conversation_key, &nonce)
}

/// Decrypt a NIP-44 v2 encrypted message.
pub fn decrypt(
    ciphertext_b64: &str,
    recipient_privkey: &SecretKey,
    sender_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    let shared_x = ecdh_x_only(recipient_privkey, sender_pubkey);
    let conversation_key = derive_conversation_key(&shared_x);

    decrypt_with_conversation_key(ciphertext_b64, &conversation_key)
}

// ---------------------------------------------------------------------------
// Internal helpers – pub(crate) so unit tests in this file and integration
// tests can exercise known test vectors directly.
// ---------------------------------------------------------------------------

/// Encrypt with an explicit nonce (deterministic; useful for test vectors).
pub(crate) fn encrypt_inner(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> anyhow::Result<String> {
    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conversation_key, nonce)?;
    let padded = pad_plaintext(plaintext.as_bytes())?;

    // ChaCha20 stream encryption (encrypt-in-place over a copy)
    let mut ciphertext = padded;
    let key = ChaChaKey::from_slice(&chacha_key);
    let nonce12 = ChaChaNonce::from_slice(&chacha_nonce);
    ChaCha20::new(key, nonce12).apply_keystream(&mut ciphertext);

    let mac = compute_mac(&hmac_key, nonce, &ciphertext);

    // Payload: version(1) | nonce(32) | ciphertext | mac(32)
    let mut payload = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len() + MAC_LEN);
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);

    Ok(BASE64_STANDARD.encode(&payload))
}

/// Decrypt given an already-derived conversation key (useful for test vectors).
pub(crate) fn decrypt_with_conversation_key(
    ciphertext_b64: &str,
    conversation_key: &[u8; 32],
) -> anyhow::Result<String> {
    let payload = BASE64_STANDARD.decode(ciphertext_b64)?;

    if payload.len() < MIN_PAYLOAD_LEN || payload.len() > 65603 {
        anyhow::bail!(
            "Invalid payload length: {} (must be {MIN_PAYLOAD_LEN}..=65603)",
            payload.len()
        );
    }

    if payload[0] != NIP44_VERSION {
        anyhow::bail!("Unsupported NIP-44 version: {}", payload[0]);
    }

    // version(1) | nonce(32) | ciphertext(variable) | mac(32)
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[1..1 + NONCE_LEN]);
    let mac_start = payload.len() - MAC_LEN;
    let ciphertext = &payload[1 + NONCE_LEN..mac_start];
    let mac = &payload[mac_start..];

    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conversation_key, &nonce)?;

    // Verify MAC before touching ciphertext (constant-time)
    verify_mac(&hmac_key, &nonce, ciphertext, mac)?;

    // ChaCha20 stream decryption (same as encryption for a stream cipher)
    let mut padded = ciphertext.to_vec();
    let key = ChaChaKey::from_slice(&chacha_key);
    let nonce12 = ChaChaNonce::from_slice(&chacha_nonce);
    ChaCha20::new(key, nonce12).apply_keystream(&mut padded);

    let plaintext = unpad_plaintext(&padded)?;
    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))
}

// ---------------------------------------------------------------------------
// Cryptographic primitives
// ---------------------------------------------------------------------------

/// x-only ECDH: returns the 32-byte x-coordinate of privkey·pubkey.
fn ecdh_x_only(privkey: &SecretKey, pubkey: &PublicKey) -> [u8; 32] {
    // shared_secret_point returns the 64-byte uncompressed point (x ‖ y).
    let point = shared_secret_point(pubkey, privkey);
    let mut x = [0u8; 32];
    x.copy_from_slice(&point[..32]);
    x
}

/// `conversation_key` = HKDF-Extract(salt="nip44-v2", IKM=shared_x).
///
/// This is Extract-only — the 32-byte PRK is the conversation key.
/// The spec explicitly says NOT to run Expand afterwards.
fn derive_conversation_key(shared_secret: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared_secret);
    let mut key = [0u8; 32];
    key.copy_from_slice(&prk);
    key
}

/// Derive per-message keys via HKDF-Expand(PRK=conversation_key, info=nonce, L=76).
///
/// Output layout:
///   bytes  0..32  → chacha_key   (32 bytes, ChaCha20 key)
///   bytes 32..44  → chacha_nonce (12 bytes, RFC 8439 nonce)
///   bytes 44..76  → hmac_key     (32 bytes, HMAC-SHA256 key)
fn derive_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> anyhow::Result<([u8; 32], [u8; 12], [u8; 32])> {
    // from_prk skips Extract — conversation_key IS the PRK.
    let hk = Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| anyhow::anyhow!("Invalid conversation key length"))?;
    let mut output = [0u8; 76];
    hk.expand(nonce, &mut output)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&output[0..32]);
    chacha_nonce.copy_from_slice(&output[32..44]);
    hmac_key.copy_from_slice(&output[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

/// HMAC-SHA256(key=hmac_key, data=nonce ‖ ciphertext).
fn compute_mac(hmac_key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

/// Constant-time MAC verification. Returns an error if the MAC is invalid.
fn verify_mac(
    hmac_key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    expected: &[u8],
) -> anyhow::Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac.verify_slice(expected)
        .map_err(|_| anyhow::anyhow!("MAC verification failed"))
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

/// Pad plaintext: `[len_be16][plaintext][zero_bytes]` → total = 2 + calc_padded_len(len).
fn pad_plaintext(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let len = plaintext.len();
    if len < 1 || len > 65535 {
        anyhow::bail!("Plaintext length must be 1..=65535, got {len}");
    }
    let padded_len = calc_padded_len(len);
    let mut out = Vec::with_capacity(2 + padded_len);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(plaintext);
    out.resize(2 + padded_len, 0);
    Ok(out)
}

/// Unpad and validate. Rejects if the padding length doesn't match the spec formula.
fn unpad_plaintext(padded: &[u8]) -> anyhow::Result<Vec<u8>> {
    if padded.len() < 2 {
        anyhow::bail!("Padded data too short");
    }
    let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if len < 1 || len > 65535 {
        anyhow::bail!("Invalid plaintext length in padding header: {len}");
    }
    let expected_total = 2 + calc_padded_len(len);
    if padded.len() != expected_total {
        anyhow::bail!(
            "Padding length mismatch: got {} bytes, expected {expected_total}",
            padded.len()
        );
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Calculates the padded block length per NIP-44 v2 spec.
///
/// Algorithm (matches the spec pseudocode and nostr-tools exactly):
///   next_power = 2^(⌊log₂(len−1)⌋ + 1)          // = bit_width(len−1) as a power of 2
///   chunk      = 32 if next_power ≤ 256, else next_power/8
///   padded_len = chunk × (⌊(len−1)/chunk⌋ + 1)
///
/// Special case: len ≤ 32 → always 32.
fn calc_padded_len(len: usize) -> usize {
    debug_assert!(len >= 1 && len <= 65535, "calc_padded_len: len out of range");
    if len <= 32 {
        return 32;
    }
    // bit_width(n) = ⌊log₂(n)⌋ + 1 for n ≥ 1
    let bit_width = (usize::BITS - (len - 1).leading_zeros()) as usize;
    let next_power = 1usize << bit_width;
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((len - 1) / chunk + 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn test_calc_padded_len() {
        // Boundaries that the old (next_power_of_two) algorithm got wrong:
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 64);
        assert_eq!(calc_padded_len(64), 64); // old code returned 128
        assert_eq!(calc_padded_len(65), 96); // old code returned 128
        assert_eq!(calc_padded_len(100), 128);
        assert_eq!(calc_padded_len(256), 256);
        assert_eq!(calc_padded_len(257), 320); // chunk switches to 64
        assert_eq!(calc_padded_len(320), 320);
        assert_eq!(calc_padded_len(321), 384);
    }

    #[test]
    fn test_padding_roundtrip() {
        for len in [1usize, 2, 31, 32, 33, 64, 65, 100, 256, 257, 320, 321, 1000] {
            let msg = vec![0x41u8; len]; // 'A' repeated
            let padded = pad_plaintext(&msg).unwrap();
            let unpadded = unpad_plaintext(&padded).unwrap();
            assert_eq!(unpadded, msg, "roundtrip failed for len={len}");
        }
    }

    /// Verify against an official NIP-44 v2 test vector from
    /// https://github.com/paulmillr/nip44/blob/main/vectors.json
    ///
    /// sec1 = 0x00…01, sec2 = 0x00…02
    /// conversation_key = c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d
    /// nonce            = 0x00…01
    /// plaintext        = "a"
    #[test]
    fn test_known_vector_conversation_key() {
        use hex::decode as hd;

        // Verify derive_conversation_key independently.
        // shared_x is taken from sec1=1, pub2=G*2; the spec publishes conversation_key directly.
        let expected_conv_key =
            hd("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d").unwrap();

        // Build shared_x from the two known secret keys so we can test end-to-end.
        let sec1 =
            SecretKey::from_slice(&hd("0000000000000000000000000000000000000000000000000000000000000001").unwrap())
                .unwrap();
        let sec2 =
            SecretKey::from_slice(&hd("0000000000000000000000000000000000000000000000000000000000000002").unwrap())
                .unwrap();
        let pub2 = sec2.public_key(&secp256k1::Secp256k1::new());

        let shared_x = ecdh_x_only(&sec1, &pub2);
        let conv_key = derive_conversation_key(&shared_x);

        assert_eq!(conv_key.as_slice(), expected_conv_key.as_slice());
    }

    #[test]
    fn test_known_vector_full_encrypt() {
        use hex::decode as hd;

        let conv_key: [u8; 32] =
            hd("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 32] =
            hd("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap();

        let expected = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

        let payload = encrypt_inner("a", &conv_key, &nonce).unwrap();
        assert_eq!(payload, expected, "encrypt output doesn't match NIP-44 v2 test vector");

        let decrypted = decrypt_with_conversation_key(&payload, &conv_key).unwrap();
        assert_eq!(decrypted, "a");
    }

    #[test]
    fn test_mac_tamper_rejected() {
        let (sender_priv, sender_pub) = generate_keypair();
        let (recipient_priv, recipient_pub) = generate_keypair();

        let encrypted = encrypt("secret", &sender_priv, &recipient_pub).unwrap();

        // Flip the last byte of the base64 payload to corrupt the MAC.
        let mut bytes = BASE64_STANDARD.decode(&encrypted).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = BASE64_STANDARD.encode(&bytes);

        let result = decrypt(&tampered, &recipient_priv, &sender_pub);
        assert!(result.is_err(), "tampered MAC must be rejected");
    }
}
