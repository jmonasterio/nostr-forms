//! NIP-17 / NIP-59 private direct message (gift wrap).
//!
//! Builds the three-layer envelope a Nostr client renders as a private DM:
//!   rumor (kind 14, unsigned) → seal (kind 13, signed by sender, NIP-44
//!   to recipient) → gift wrap (kind 1059, signed by a fresh ephemeral key,
//!   NIP-44 to recipient, `#p` recipient).
//!
//! Sender here is the processor; recipient is a form's notify pubkey. The
//! gift wrap is published via the relay's `/admin/publish`.
//!
//! Pure (no `worker` deps) so it unit-tests on the host.

use crate::decrypt::{nip44_v2_encrypt, EncryptError};
use crate::event::Event;
use crate::sign::{self, SignError};

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("encrypt: {0}")]
    Encrypt(#[from] EncryptError),
    #[error("sign: {0}")]
    Sign(#[from] SignError),
    #[error("serialize")]
    Serialize,
    #[error("rng")]
    Rng,
    #[error("bad processor key")]
    BadKey,
}

/// Maximum backdating applied to seal/wrap timestamps (NIP-59 suggests up
/// to ~2 days to blur metadata). 172800 = 48 h.
const MAX_BACKDATE_SECS: u64 = 172_800;

/// Produce a kind-1059 gift wrap of `message` from the processor to
/// `recipient_pubkey_hex`, ready to publish. `now` is unix seconds.
pub fn gift_wrap(
    processor_sk_bytes: &[u8; 32],
    processor_pubkey_hex: &str,
    recipient_pubkey_hex: &str,
    message: &str,
    now: u64,
) -> Result<Event, SealError> {
    let processor_sk_hex = hex::encode(processor_sk_bytes);

    // 1) Rumor: unsigned kind-14 chat event (has id, empty sig).
    let mut rumor = Event {
        id: String::new(),
        pubkey: processor_pubkey_hex.to_string(),
        created_at: now,
        kind: 14,
        tags: vec![vec!["p".to_string(), recipient_pubkey_hex.to_string()]],
        content: message.to_string(),
        sig: String::new(),
    };
    rumor.id = compute_id(&rumor);
    let rumor_json = serde_json::to_string(&rumor).map_err(|_| SealError::Serialize)?;

    // 2) Seal: kind-13 signed by the processor, NIP-44(processor→recipient).
    let seal_content = nip44_v2_encrypt(rumor_json.as_bytes(), &processor_sk_hex, recipient_pubkey_hex)?;
    let mut seal = Event {
        id: String::new(),
        pubkey: processor_pubkey_hex.to_string(),
        created_at: backdated(now)?,
        kind: 13,
        tags: vec![],
        content: seal_content,
        sig: String::new(),
    };
    sign::sign_in_place(processor_sk_bytes, &mut seal)?;
    let seal_json = serde_json::to_string(&seal).map_err(|_| SealError::Serialize)?;

    // 3) Gift wrap: kind-1059 signed by a fresh ephemeral key,
    //    NIP-44(ephemeral→recipient), #p recipient.
    let mut ephemeral_sk = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_sk).map_err(|_| SealError::Rng)?;
    let ephemeral_pubkey = sign::xonly_pubkey(&ephemeral_sk)?;
    let ephemeral_sk_hex = hex::encode(ephemeral_sk);

    let wrap_content = nip44_v2_encrypt(seal_json.as_bytes(), &ephemeral_sk_hex, recipient_pubkey_hex)?;
    let mut wrap = Event {
        id: String::new(),
        pubkey: hex::encode(ephemeral_pubkey),
        created_at: backdated(now)?,
        kind: 1059,
        tags: vec![vec!["p".to_string(), recipient_pubkey_hex.to_string()]],
        content: wrap_content,
        sig: String::new(),
    };
    sign::sign_in_place(&ephemeral_sk, &mut wrap)?;
    Ok(wrap)
}

/// Subtract a random offset in `0..=MAX_BACKDATE_SECS` from `now`.
fn backdated(now: u64) -> Result<u64, SealError> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|_| SealError::Rng)?;
    let off = u64::from_le_bytes(b) % (MAX_BACKDATE_SECS + 1);
    Ok(now.saturating_sub(off))
}

/// Canonical NIP-01 id over `[0,pubkey,created_at,kind,tags,content]`.
fn compute_id(event: &Event) -> String {
    use sha2::{Digest, Sha256};
    let serialized = serde_json::to_string(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(serialized.as_bytes());
    hex::encode(h.finalize())
}
