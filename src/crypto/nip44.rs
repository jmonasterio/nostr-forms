//! NIP-44 v2 encrypt/decrypt — thin wrapper over the shared `nostr-crypto`
//! crate (`../../../nostr-crypto-rs`), the single source of truth for this
//! protocol across the nostr stack (kvdb, form-rs, relay's admin-auth path).
//!
//! Do not re-add a parallel implementation here. The byte-for-byte official
//! NIP-44 v2 test-vector pin — the drift gate against nostr-tools — now
//! lives in that crate (`nostr-crypto-rs::nip44::tests::official_vector_*`)
//! and must always pass there. This module only exists to keep the
//! `crate::crypto::nip44::{encrypt, decrypt}` call sites unchanged and to
//! convert `nostr_crypto::CryptoError` into `anyhow::Error`.

use k256::{PublicKey, SecretKey};

/// Encrypt a message using NIP-44 v2.
pub fn encrypt(
    plaintext: &str,
    sender_privkey: &SecretKey,
    recipient_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    Ok(nostr_crypto::nip44::encrypt(
        plaintext,
        sender_privkey,
        recipient_pubkey,
    )?)
}

/// Decrypt a NIP-44 v2 encrypted message.
pub fn decrypt(
    ciphertext_b64: &str,
    recipient_privkey: &SecretKey,
    sender_pubkey: &PublicKey,
) -> anyhow::Result<String> {
    Ok(nostr_crypto::nip44::decrypt(
        ciphertext_b64,
        recipient_privkey,
        sender_pubkey,
    )?)
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
    fn test_decrypt_rejects_garbage() {
        let (_, sender_pub) = generate_keypair();
        let (recipient_priv, _) = generate_keypair();

        // Not a valid NIP-44 payload at all — must error, not panic.
        let result = decrypt("not-a-real-payload", &recipient_priv, &sender_pub);
        assert!(result.is_err());
    }
}
