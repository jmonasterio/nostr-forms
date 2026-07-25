//! Minimal Nostr event type. Wire-compatible with `nostr-relay::nip01::Event`
//! (both serialize through `serde_json` with the same field names), but
//! kept local so this crate doesn't carry the relay crate as a dependency.

use serde::{Deserialize, Serialize};

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
}
