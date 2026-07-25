//! NIP-44 v2 round-trip: encrypt with the same algorithm we decrypt and
//! confirm we recover the plaintext.
//!
//! Encrypt is test-only (the form Worker never encrypts; it only decrypts
//! inbound envelopes). Keeping encrypt isolated to this test avoids
//! adding an unused code path to the deployed wasm binary.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use nostr_form_rs::decrypt::{ecdh_x, nip44_v2_decrypt};

#[test]
fn ecdh_x_is_symmetric() {
    let (sk_a, pk_a) = make_keypair([1u8; 32]);
    let (sk_b, pk_b) = make_keypair([2u8; 32]);
    let shared_ab = ecdh_x(&sk_a, &pk_b).expect("ab");
    let shared_ba = ecdh_x(&sk_b, &pk_a).expect("ba");
    assert_eq!(shared_ab, shared_ba, "ECDH must be symmetric");
}

#[test]
fn decrypt_round_trip_short_plaintext() {
    round_trip(b"hello nostr");
}

#[test]
fn decrypt_round_trip_long_plaintext() {
    let pt: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
    round_trip(&pt);
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let (sk_b, pk_b) = make_keypair([2u8; 32]);
    let (sk_a, pk_a) = make_keypair([1u8; 32]);
    let payload = encrypt_v2(&sk_a, &pk_b, b"secret message", [9u8; 32]);
    let mut bytes = B64.decode(&payload).unwrap();
    // Flip a byte inside the ciphertext (not the version, not the nonce,
    // not the trailing MAC — those would short-circuit other paths).
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let bad = B64.encode(&bytes);
    let result = nip44_v2_decrypt(&bad, &hex::encode(sk_b), &hex::encode(pk_a));
    assert!(result.is_err(), "tampered ciphertext must fail MAC verify");
}

#[test]
fn decrypt_rejects_wrong_version() {
    let (sk_b, pk_b) = make_keypair([2u8; 32]);
    let (sk_a, pk_a) = make_keypair([1u8; 32]);
    let payload = encrypt_v2(&sk_a, &pk_b, b"hello", [9u8; 32]);
    let mut bytes = B64.decode(&payload).unwrap();
    bytes[0] = 0x01; // pretend v1
    let bad = B64.encode(&bytes);
    let err = nip44_v2_decrypt(&bad, &hex::encode(sk_b), &hex::encode(pk_a)).unwrap_err();
    assert!(format!("{err}").contains("unsupported version"), "got {err:?}");
}

// ---------- helpers ----------

fn round_trip(plaintext: &[u8]) {
    let (sk_a, pk_a) = make_keypair([7u8; 32]);
    let (sk_b, pk_b) = make_keypair([8u8; 32]);
    let payload = encrypt_v2(&sk_a, &pk_b, plaintext, [42u8; 32]);
    let recovered =
        nip44_v2_decrypt(&payload, &hex::encode(sk_b), &hex::encode(pk_a)).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

/// Deterministic test keypair from a seed (NOT crypto-secure — tests only).
fn make_keypair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    use k256::schnorr::SigningKey;
    let sk = SigningKey::from_bytes(&seed).expect("seed must be a valid secret scalar");
    let pk = sk.verifying_key().to_bytes();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    (seed, pk_arr)
}

/// Reference NIP-44 v2 encrypt for the round-trip — should never ship.
fn encrypt_v2(sender_sk: &[u8; 32], recipient_pk: &[u8; 32], plaintext: &[u8], nonce: [u8; 32]) -> String {
    let shared = ecdh_x(sender_sk, recipient_pk).expect("ecdh");
    let prk = hkdf_extract(b"nip44-v2", &shared);

    let mut okm = [0u8; 76];
    Hkdf::<Sha256>::from_prk(&prk)
        .unwrap()
        .expand(&nonce, &mut okm)
        .unwrap();
    let chacha_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = okm[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = okm[44..76].try_into().unwrap();

    // Pad: u16_be(len) || plaintext || zero pad to next power of two ≥ 32.
    let pad_total = calc_padded_len(plaintext.len());
    let mut padded = Vec::with_capacity(2 + pad_total);
    padded.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(2 + pad_total, 0u8);

    // Encrypt.
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut padded);

    // MAC = HMAC-SHA256(hmac_key, nonce || ciphertext)
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&nonce);
    mac.update(&padded);
    let mac_tag = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + padded.len() + 32);
    payload.push(0x02);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&padded);
    payload.extend_from_slice(&mac_tag);
    B64.encode(&payload)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// NIP-44 padding: ciphertext (excluding the 2-byte length prefix) is
/// padded to the next power of two ≥ 32. For the test we keep parity with
/// the spec but the decryptor only relies on the leading length prefix.
fn calc_padded_len(pt_len: usize) -> usize {
    let min = 32usize;
    if pt_len <= min {
        min
    } else {
        let mut n = min;
        while n < pt_len {
            n *= 2;
        }
        n
    }
}
