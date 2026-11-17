//! Minimal Nostr event type. Wire-compatible with `nostr-relay::nip01::Event`
//! (both serialize through `serde_json` with the same field names), but
//! kept local so this crate doesn't carry the relay crate as a dependency.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Returns the first `#p` recipient if present.
    pub fn first_p_tag(&self) -> Option<&str> {
        for tag in &self.tags {
            if tag.first().map(String::as_str) == Some("p") {
                if let Some(v) = tag.get(1) {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Canonical NIP-01 id: sha256 of `[0,pubkey,created_at,kind,tags,content]`.
    pub fn compute_id(&self) -> String {
        let serialized = serde_json::to_string(&(
            0u8,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .unwrap_or_default();
        let mut h = Sha256::new();
        h.update(serialized.as_bytes());
        hex::encode(h.finalize())
    }

    /// BIP-340 verify of `sig` over `id` by `pubkey` (mirrors `nostr-relay::nip01`).
    /// Does not recompute the id; pair with [`Event::compute_id`].
    pub fn verify_signature(&self) -> bool {
        use k256::schnorr::{Signature as SchnorrSig, VerifyingKey};

        let pk_bytes = match hex::decode(&self.pubkey) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let vk = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig_bytes = match hex::decode(&self.sig) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let sig = match SchnorrSig::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let id_bytes = match hex::decode(&self.id) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        vk.verify_raw(&id_bytes, &sig).is_ok()
    }
}
