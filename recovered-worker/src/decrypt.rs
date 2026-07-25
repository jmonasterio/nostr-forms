//! NIP-44 v2 decryption.
//!
//! Reference: <https://github.com/nostr-protocol/nips/blob/master/44.md>
//!
//! Algorithm:
//! ```text
//!   shared_x         = ECDH(our_sk, lift_x(peer_xonly_pubkey))    // 32 bytes
//!   conversation_key = HKDF-extract(salt = "nip44-v2", ikm = shared_x)
//!   bytes            = HKDF-expand(conversation_key, info = nonce, L = 76)
//!     chacha_key   = bytes[0..32]
//!     chacha_nonce = bytes[32..44]    // 12 bytes
//!     hmac_key     = bytes[44..76]
//!
//!   payload = base64(0x02 || nonce(32) || ciphertext || mac(32))
//!   mac     = HMAC-SHA256(hmac_key, nonce || ciphertext)
//!   ciphertext = ChaCha20(chacha_key, chacha_nonce, padded_plaintext)
//!     padded_plaintext = u16_be(plaintext.len()) || plaintext || zero_padding
//! ```
//!
//! Note: NIP-44 lift_x picks the **even-y** root of the curve equation,
//! same convention as BIP-340. We get that for free by routing the
//! x-only pubkey through `k256::schnorr::VerifyingKey::from_bytes`,
//! whose `as_affine()` is already even-y normalized.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{
        group::GroupEncoding,
        sec1::ToEncodedPoint,
    },
    schnorr::VerifyingKey,
    ProjectivePoint, Scalar, SecretKey,
};
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("bad hex: {0}")]
    Hex(&'static str),
    #[error("bad base64")]
    Base64,
    #[error("payload too short")]
    TooShort,
    #[error("unsupported version {0:#x} (expected 0x02)")]
    BadVersion(u8),
    #[error("invalid secret key")]
    BadSecretKey,
    #[error("invalid peer pubkey (not on curve)")]
    BadPeerPubkey,
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("mac mismatch")]
    BadMac,
    #[error("plaintext length larger than ciphertext")]
    BadPadding,
}

/// Decrypt a NIP-44 v2 payload (base64) using our secret key (hex) and
/// the sender's x-only pubkey (hex). Returns the plaintext bytes.
pub fn nip44_v2_decrypt(
    payload_b64: &str,
    our_sk_hex: &str,
    peer_xonly_hex: &str,
) -> Result<Vec<u8>, DecryptError> {
    let payload = B64
        .decode(payload_b64.as_bytes())
        .map_err(|_| DecryptError::Base64)?;
    let sk_bytes = hex::decode(our_sk_hex).map_err(|_| DecryptError::Hex("our_sk"))?;
    let peer_bytes = hex::decode(peer_xonly_hex).map_err(|_| DecryptError::Hex("peer_pubkey"))?;
    decrypt_bytes(&payload, &sk_bytes, &peer_bytes)
}

pub fn decrypt_bytes(
    payload: &[u8],
    our_sk_bytes: &[u8],
    peer_xonly_bytes: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    // 1 (version) + 32 (nonce) + ≥2 (ct includes length prefix) + 32 (mac) = ≥67
    if payload.len() < 67 {
        return Err(DecryptError::TooShort);
    }
    let version = payload[0];
    if version != 0x02 {
        return Err(DecryptError::BadVersion(version));
    }
    let nonce: &[u8; 32] = payload[1..33].try_into().unwrap();
    let ct = &payload[33..payload.len() - 32];
    let mac: &[u8; 32] = payload[payload.len() - 32..].try_into().unwrap();

    let shared = ecdh_x(our_sk_bytes, peer_xonly_bytes)?;
    let conversation_key = hkdf_extract(b"nip44-v2", &shared);

    // Expand to 76 bytes keyed on the nonce.
    let mut okm = [0u8; 76];
    Hkdf::<Sha256>::from_prk(&conversation_key)
        .map_err(|_| DecryptError::Hkdf)?
        .expand(nonce, &mut okm)
        .map_err(|_| DecryptError::Hkdf)?;
    let chacha_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = okm[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = okm[44..76].try_into().unwrap();

    // MAC verify in constant time. NIP-44: HMAC(hmac_key, nonce || ciphertext).
    let mut mac_h = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("hmac key length");
    mac_h.update(nonce);
    mac_h.update(ct);
    mac_h.verify_slice(mac).map_err(|_| DecryptError::BadMac)?;

    // Decrypt in-place.
    let mut padded = ct.to_vec();
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut padded);

    // Unpad: first 2 bytes BE = plaintext length.
    if padded.len() < 2 {
        return Err(DecryptError::BadPadding);
    }
    let plaintext_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + plaintext_len > padded.len() {
        return Err(DecryptError::BadPadding);
    }
    Ok(padded[2..2 + plaintext_len].to_vec())
}

/// Raw ECDH: scalar * lift_x(peer_x) → 32-byte x-coordinate. No KDF.
pub fn ecdh_x(our_sk_bytes: &[u8], peer_xonly_bytes: &[u8]) -> Result<[u8; 32], DecryptError> {
    if our_sk_bytes.len() != 32 {
        return Err(DecryptError::BadSecretKey);
    }
    if peer_xonly_bytes.len() != 32 {
        return Err(DecryptError::BadPeerPubkey);
    }

    // BIP-340 lift_x via schnorr::VerifyingKey: picks the even-y root.
    let vk = VerifyingKey::from_bytes(peer_xonly_bytes)
        .map_err(|_| DecryptError::BadPeerPubkey)?;
    let peer_point = ProjectivePoint::from(*vk.as_affine());

    let sk = SecretKey::from_slice(our_sk_bytes).map_err(|_| DecryptError::BadSecretKey)?;
    let scalar: Scalar = *sk.to_nonzero_scalar().as_ref();

    let shared_point = (peer_point * scalar).to_affine();
    // SEC1 encoded uncompressed (0x04 || x || y) — take bytes 1..33.
    let enc = shared_point.to_encoded_point(false);
    let bytes = enc.as_bytes();
    if bytes.len() < 33 || bytes[0] != 0x04 {
        // Identity point (shared_point == infinity) → effectively impossible
        // with valid inputs but treat as failure.
        return Err(DecryptError::BadPeerPubkey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[1..33]);

    // Suppress unused-imports warnings on GroupEncoding by referencing it
    // for a no-op below. Keeping the use lets future helpers (compressed
    // form, identity check) compile without re-touching this header.
    let _ = <ProjectivePoint as GroupEncoding>::to_bytes;
    Ok(out)
}

/// HKDF-extract with SHA-256 (RFC 5869).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

// ---------------------------------------------------------------------------
// NIP-44 v2 encryption
//
// RECOVERED 2026-07-25. The transcript that added this to the original crate
// was pruned, so this half is a reimplementation written as the exact inverse
// of `decrypt_bytes` above. It is validated by `tests/nip44_spec_vectors.rs`
// (official NIP-44 vectors) and `tests/nip44_roundtrip.rs`, both of which are
// verbatim recoveries.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("bad hex: {0}")]
    Hex(&'static str),
    #[error("invalid secret key")]
    BadSecretKey,
    #[error("invalid peer pubkey (not on curve)")]
    BadPeerPubkey,
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("plaintext too large (max 65535)")]
    TooLong,
    #[error("rng failure")]
    Rng,
}

impl From<DecryptError> for EncryptError {
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::Hex(w) => EncryptError::Hex(w),
            DecryptError::BadSecretKey => EncryptError::BadSecretKey,
            DecryptError::Hkdf => EncryptError::Hkdf,
            _ => EncryptError::BadPeerPubkey,
        }
    }
}

/// NIP-44 §Padding: pad to the next power-of-two-derived chunk boundary so
/// ciphertext length leaks only a coarse bucket, never the exact size.
fn calc_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (unpadded_len - 1).leading_zeros()) as usize;
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((unpadded_len - 1) / chunk + 1)
}

/// Encrypt to a NIP-44 v2 base64 payload using our secret key (hex) and the
/// recipient's x-only pubkey (hex). Inverse of [`nip44_v2_decrypt`].
pub fn nip44_v2_encrypt(
    plaintext: &[u8],
    our_sk_hex: &str,
    peer_xonly_hex: &str,
) -> Result<String, EncryptError> {
    let sk_bytes = hex::decode(our_sk_hex).map_err(|_| EncryptError::Hex("our_sk"))?;
    let peer_bytes = hex::decode(peer_xonly_hex).map_err(|_| EncryptError::Hex("peer_pubkey"))?;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| EncryptError::Rng)?;

    encrypt_bytes(plaintext, &sk_bytes, &peer_bytes, &nonce)
}

/// Deterministic core, split out so the spec vectors can pin the nonce.
pub fn encrypt_bytes(
    plaintext: &[u8],
    our_sk_bytes: &[u8],
    peer_xonly_bytes: &[u8],
    nonce: &[u8; 32],
) -> Result<String, EncryptError> {
    if plaintext.len() > u16::MAX as usize {
        return Err(EncryptError::TooLong);
    }

    let shared = ecdh_x(our_sk_bytes, peer_xonly_bytes)?;
    let conversation_key = hkdf_extract(b"nip44-v2", &shared);

    let mut okm = [0u8; 76];
    Hkdf::<Sha256>::from_prk(&conversation_key)
        .map_err(|_| EncryptError::Hkdf)?
        .expand(nonce, &mut okm)
        .map_err(|_| EncryptError::Hkdf)?;
    let chacha_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = okm[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = okm[44..76].try_into().unwrap();

    // 2-byte BE length prefix, then zero padding out to the chunk boundary.
    let mut padded = Vec::with_capacity(2 + calc_padded_len(plaintext.len()));
    padded.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(2 + calc_padded_len(plaintext.len()), 0u8);

    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut padded);

    // MAC covers nonce || ciphertext, same as the verify side.
    let mut mac_h = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("hmac key length");
    mac_h.update(nonce);
    mac_h.update(&padded);
    let mac = mac_h.finalize().into_bytes();

    let mut out = Vec::with_capacity(1 + 32 + padded.len() + 32);
    out.push(0x02);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&padded);
    out.extend_from_slice(&mac);
    Ok(B64.encode(out))
}
