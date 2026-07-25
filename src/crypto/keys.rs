//! Nostr keypair helpers backed by the shared `nostr-crypto` crate's k256
//! implementation (`../../../nostr-crypto-rs`) — pure Rust, wasm32-clean,
//! unlike the `secp256k1` C-binding crate this used to wrap. Single source
//! of truth across the nostr stack (kvdb, form-rs, relay's NIP-98 admin
//! auth); see CLAUDE.md "Deployment" for why wasm-clean crypto matters here.

use k256::{PublicKey, SecretKey};

/// Generate a new keypair.
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret_key = nostr_crypto::keys::random_secret();
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

/// Convert public key to hex string (x-only, 32 bytes).
pub fn pubkey_to_hex(pubkey: &PublicKey) -> String {
    nostr_crypto::keys::xonly_hex(pubkey)
}

/// Convert secret key to hex string.
pub fn privkey_to_hex(privkey: &SecretKey) -> String {
    hex::encode(privkey.to_bytes())
}

/// Parse secret key from hex.
pub fn privkey_from_hex(hex_str: &str) -> anyhow::Result<SecretKey> {
    let bytes = hex::decode(hex_str)?;
    let key = SecretKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("invalid secret key: {e}"))?;
    Ok(key)
}

/// Parse public key from hex (x-only, 32 bytes). Lifts to the even-y point
/// per the Nostr/BIP-340 convention — there is exactly one valid x-only
/// pubkey per key, so (unlike the old secp256k1 code) there's no need to
/// try both parities.
pub fn pubkey_from_hex(hex_str: &str) -> anyhow::Result<PublicKey> {
    let bytes = hex::decode(hex_str)?;
    let xonly: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pubkey length"))?;
    Ok(nostr_crypto::nip44::pubkey_from_xonly(&xonly)?)
}

/// Generate a random form ID (8 base58-like characters)
pub fn generate_form_id() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut random_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut random_bytes);

    let mut id = String::new();
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for byte in &random_bytes {
        id.push(ALPHABET[(*byte as usize) % ALPHABET.len()] as char);
    }
    id
}

/// Verify NIP-13 proof-of-work on an event ID
pub fn verify_pow(event_id_hex: &str, required_bits: u8) -> bool {
    let Ok(bytes) = hex::decode(event_id_hex) else {
        return false;
    };

    if bytes.len() != 32 {
        return false;
    }

    let leading_zeros = count_leading_zero_bits(&bytes);
    leading_zeros >= required_bits
}

/// Count leading zero bits in a byte array
fn count_leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u8;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (privkey, pubkey) = generate_keypair();
        let priv_hex = privkey_to_hex(&privkey);
        let pub_hex = pubkey_to_hex(&pubkey);

        assert_eq!(priv_hex.len(), 64);
        assert_eq!(pub_hex.len(), 64);

        // Round-trip
        let privkey2 = privkey_from_hex(&priv_hex).unwrap();
        let pubkey2 = pubkey_from_hex(&pub_hex).unwrap();

        assert_eq!(priv_hex, privkey_to_hex(&privkey2));
        assert_eq!(pub_hex, pubkey_to_hex(&pubkey2));
    }

    #[test]
    fn test_pow_verification() {
        // Event ID with 16 leading zero bits (4 hex zeros)
        let id_16_bits = "0000abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456";
        assert!(verify_pow(id_16_bits, 16));
        assert!(!verify_pow(id_16_bits, 20));

        // Event ID with no leading zeros
        let id_no_zeros = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(!verify_pow(id_no_zeros, 1));
    }

    #[test]
    fn test_form_id_generation() {
        let form_id = generate_form_id();

        // Should be 8 characters
        assert_eq!(form_id.len(), 8);

        // Should only contain base58 characters
        for c in form_id.chars() {
            assert!(c.is_ascii_alphanumeric());
            assert!(c != '0' && c != 'O' && c != 'I' && c != 'l');
        }

        // Two IDs should be different
        let form_id2 = generate_form_id();
        assert_ne!(form_id, form_id2);
    }
}
