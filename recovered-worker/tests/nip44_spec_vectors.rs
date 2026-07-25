//! Byte-level conformance to the official NIP-44 v2 vectors
//! (github.com/paulmillr/nip44). Guarantees the worker's `encrypt_bytes`
//! produces ciphertext that spec-conformant decryptors — notably NIP-07
//! `nip44.decrypt` (nostr-tools), which validates padding length — accept.
//! Without this, the encrypted DM and the at-rest dashboard blob would be
//! rejected by the recipient/browser.

use k256::schnorr::SigningKey;
use serde_json::Value;

use nostr_form_rs::decrypt::{encrypt_bytes, nip44_v2_decrypt};

const VECTORS: &str = include_str!("nip44_spec_vectors.json");

fn xonly_hex(sk_hex: &str) -> String {
    let bytes = hex::decode(sk_hex).expect("sk hex");
    let sk = SigningKey::from_bytes(&bytes).expect("valid scalar");
    hex::encode(sk.verifying_key().to_bytes())
}

#[test]
fn encrypt_matches_spec_vectors_byte_for_byte() {
    let root: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = root["encrypt_decrypt"].as_array().unwrap();
    assert!(!cases.is_empty());
    for (i, c) in cases.iter().enumerate() {
        let sec1 = c["sec1"].as_str().unwrap();
        let sec2 = c["sec2"].as_str().unwrap();
        let nonce_hex = c["nonce"].as_str().unwrap();
        let plaintext = c["plaintext"].as_str().unwrap();
        let expected_payload = c["payload"].as_str().unwrap();

        let pub2 = xonly_hex(sec2);
        let sk1 = hex::decode(sec1).unwrap();
        let pk2 = hex::decode(&pub2).unwrap();
        let nonce_vec = hex::decode(nonce_hex).unwrap();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_vec);

        let got = encrypt_bytes(plaintext.as_bytes(), &sk1, &pk2, &nonce)
            .unwrap_or_else(|e| panic!("vector {i} encrypt: {e}"));
        assert_eq!(
            got, expected_payload,
            "vector {i}: encrypt payload mismatch for plaintext {plaintext:?}"
        );

        // And the recipient (sec2, peer = pub1) must recover the plaintext.
        let pub1 = xonly_hex(sec1);
        let recovered = nip44_v2_decrypt(expected_payload, sec2, &pub1)
            .unwrap_or_else(|e| panic!("vector {i} decrypt: {e}"));
        assert_eq!(
            String::from_utf8(recovered).unwrap(),
            plaintext,
            "vector {i}: decrypt mismatch"
        );
    }
}

#[test]
fn padding_matches_spec_via_payload_length() {
    // calc_padded_len is private; validate it through the public encrypt:
    // payload bytes = 1 (version) + 32 (nonce) + (2 + padded) + 32 (mac).
    let root: Value = serde_json::from_str(VECTORS).unwrap();
    let pairs = root["calc_padded_len"].as_array().unwrap();
    let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let peer = xonly_hex("0000000000000000000000000000000000000000000000000000000000000002");
    let peer = hex::decode(&peer).unwrap();
    let nonce = [7u8; 32];
    for pair in pairs {
        let unpadded = pair[0].as_u64().unwrap() as usize;
        let padded = pair[1].as_u64().unwrap() as usize;
        if unpadded == 0 || unpadded > 65535 {
            continue; // outside NIP-44 plaintext bounds
        }
        let pt = vec![b'x'; unpadded];
        let payload = encrypt_bytes(&pt, &sk, &peer, &nonce).expect("encrypt");
        let raw = base64_decode(&payload);
        assert_eq!(
            raw.len(),
            67 + padded,
            "calc_padded_len({unpadded}) expected {padded}"
        );
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    B64.decode(s).unwrap()
}
