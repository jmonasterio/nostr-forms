//! Event signing — used by `notify.rs` to publish admin DMs back through
//! the relay. Computes the NIP-01 canonical id and Schnorr-signs it with
//! k256.

use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

use crate::event::Event;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("invalid secret key")]
    BadSecretKey,
    #[error("serialization failed")]
    Serialization,
    #[error("schnorr signing failed")]
    Schnorr,
}

/// Mutate `event` in place: fill `id` (canonical sha256) and `sig`
/// (BIP-340 over the id). Caller must have already populated `pubkey`,
/// `created_at`, `kind`, `tags`, `content`.
pub fn sign_in_place(sk_bytes: &[u8; 32], event: &mut Event) -> Result<(), SignError> {
    let serialized = serde_json::to_string(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .map_err(|_| SignError::Serialization)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let id_bytes: [u8; 32] = hasher.finalize().into();
    event.id = hex::encode(id_bytes);

    let sk = SigningKey::from_bytes(sk_bytes).map_err(|_| SignError::BadSecretKey)?;
    // BIP-340 over the 32-byte id. `sign_raw` skips the implicit SHA-256
    // hashing of the message that `try_sign` would apply.
    let sig = sk.sign_raw(&id_bytes, &[0u8; 32]).map_err(|_| SignError::Schnorr)?;
    event.sig = hex::encode(sig.to_bytes());
    Ok(())
}

/// Derive the x-only public key bytes from a secret key. Useful to
/// confirm `PROCESSOR_PUBKEY` env var matches `PROCESSOR_NSEC` at boot.
pub fn xonly_pubkey(sk_bytes: &[u8; 32]) -> Result<[u8; 32], SignError> {
    let sk = SigningKey::from_bytes(sk_bytes).map_err(|_| SignError::BadSecretKey)?;
    let pk = sk.verifying_key().to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk);
    Ok(out)
}
