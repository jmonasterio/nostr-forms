//! NIP-17 private direct message delivery.
//!
//! Implements the gift-wrap scheme (NIP-59) carrying a private DM (NIP-17):
//!
//!   rumor   – unsigned kind-14 event (the actual message)
//!   seal    – kind-13: NIP-44 encrypt the rumor to recipient, signed by sender (processor)
//!   wrap    – kind-1059: NIP-44 encrypt the seal using a random one-time key,
//!             tagged with recipient, published to relay
//!
//! Modern clients (Alby, Damus, Amethyst, …) surface kind-1059 events as
//! regular DMs.  The one-time wrap key means the processor pubkey is not
//! exposed on the wire.

use futures_util::SinkExt;
use secp256k1::{Secp256k1, SecretKey};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto::{keys, nip44};
use crate::registry::models::SubmissionPayload;

/// Shared WebSocket write half – passed in from the worker so we reuse the
/// connection instead of opening a fresh one per submission.
pub type WsSink = Mutex<
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
>;

/// Send a form submission to `notify_pubkey` as a NIP-17 private DM,
/// using the shared relay connection `sink`.
pub async fn send_dm(
    sink: &WsSink,
    processor_privkey: &SecretKey,
    notify_pubkey: &str,
    form_name: &str,
    event_id: &str,
    payload: &SubmissionPayload,
    sender_pubkey: &str,
    pow_difficulty: u8,
) -> anyhow::Result<()> {
    // ── Build message text ───────────────────────────────────────────────────
    let mut content = format!("New submission: {}\n\n", form_name);
    for (key, value) in &payload.fields {
        let val_str = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        content.push_str(&format!("{}: {}\n", key, val_str));
    }
    content.push_str(&format!("\n---\nEvent: {}\nSender: {}\n", event_id, sender_pubkey));
    if let Some(ref ts) = payload.meta.submitted_at {
        content.push_str(&format!("Submitted: {}\n", ts));
    }

    // ── Recipient pubkey ─────────────────────────────────────────────────────
    let recipient_pubkey = keys::pubkey_from_hex(notify_pubkey)?;

    // ── Step 1: rumor (unsigned kind-14) ─────────────────────────────────────
    let secp = Secp256k1::new();
    let processor_pub = secp256k1::PublicKey::from_secret_key(&secp, processor_privkey);
    let processor_pub_hex = keys::pubkey_to_hex(&processor_pub);

    let rumor_created_at = chrono::Utc::now().timestamp();
    let rumor = json!({
        "kind": 14,
        "pubkey": processor_pub_hex,
        "created_at": rumor_created_at,
        "tags": [["p", notify_pubkey]],
        "content": content
    });

    // ── Step 2: seal (kind-13) ───────────────────────────────────────────────
    // Encrypt rumor JSON to recipient using processor privkey (ECDH with recipient).
    let rumor_json = serde_json::to_string(&rumor)?;
    let seal_content = nip44::encrypt(&rumor_json, processor_privkey, &recipient_pubkey)?;

    let seal_created_at = jitter_timestamp(rumor_created_at);
    let seal_json = json!([
        0,
        processor_pub_hex,
        seal_created_at,
        13,
        [],
        seal_content
    ]);
    let seal_id = event_id_hash(&seal_json)?;
    let seal_sig = schnorr_sign(&seal_id, processor_privkey, &secp)?;

    let seal = json!({
        "id":         seal_id,
        "pubkey":     processor_pub_hex,
        "created_at": seal_created_at,
        "kind":       13,
        "tags":       [],
        "content":    seal_content,
        "sig":        seal_sig
    });

    // ── Step 3: gift-wrap (kind-1059) ────────────────────────────────────────
    // Random one-time keypair — decouples the wrap from the processor identity.
    let (wrap_privkey, wrap_pubkey) = keys::generate_keypair();
    let wrap_pub_hex = keys::pubkey_to_hex(&wrap_pubkey);

    let seal_str = serde_json::to_string(&seal)?;
    let wrap_content = nip44::encrypt(&seal_str, &wrap_privkey, &recipient_pubkey)?;

    let wrap_created_at = jitter_timestamp(rumor_created_at);

    // Mine PoW so relay.argw.com's external_pow_bits gate accepts the wrap.
    let (wrap_id, wrap_nonce) = mine_event_pow(
        &wrap_pub_hex,
        wrap_created_at,
        1059,
        notify_pubkey,
        &wrap_content,
        pow_difficulty,
    )?;
    let wrap_sig = schnorr_sign(&wrap_id, &wrap_privkey, &secp)?;

    let gift_wrap = json!({
        "id":         wrap_id,
        "pubkey":     wrap_pub_hex,
        "created_at": wrap_created_at,
        "kind":       1059,
        "tags":       [["p", notify_pubkey], ["nonce", wrap_nonce.to_string(), pow_difficulty.to_string()]],
        "content":    wrap_content,
        "sig":        wrap_sig
    });

    // ── Publish via shared connection ─────────────────────────────────────────
    let msg = json!(["EVENT", gift_wrap]);
    sink.lock().await.send(Message::Text(msg.to_string())).await?;

    tracing::info!(
        "NIP-17 DM sent to {}… for form '{}'",
        &notify_pubkey[..16],
        form_name
    );

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// SHA-256 of the canonical NIP-01 serialisation, returned as hex.
fn event_id_hash(canonical: &Value) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let s = serde_json::to_string(canonical)?;
    Ok(hex::encode(Sha256::digest(s.as_bytes())))
}

/// Schnorr-sign an event id (hex) with the given key.
fn schnorr_sign(id_hex: &str, privkey: &SecretKey, secp: &Secp256k1<secp256k1::All>) -> anyhow::Result<String> {
    let id_bytes = hex::decode(id_hex)?;
    let msg = secp256k1::Message::from_digest_slice(&id_bytes)?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &privkey.keypair(secp));
    Ok(hex::encode(sig.as_ref()))
}

/// Add a small random jitter (±300 s) to a timestamp to prevent timing
/// correlation between the rumor, seal, and wrap.
fn jitter_timestamp(base: i64) -> i64 {
    use rand::Rng;
    let jitter: i64 = rand::thread_rng().gen_range(-300..=300);
    base + jitter
}

/// Mine NIP-13 proof-of-work for an event. Returns (event_id_hex, winning_nonce).
fn mine_event_pow(
    pub_hex: &str,
    created_at: i64,
    kind: u16,
    p_tag: &str,
    content: &str,
    difficulty: u8,
) -> anyhow::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    for nonce in 0u64.. {
        let tags = serde_json::json!([
            ["p", p_tag],
            ["nonce", nonce.to_string(), difficulty.to_string()],
        ]);
        let canonical = serde_json::to_string(&serde_json::json!(
            [0, pub_hex, created_at, kind, tags, content]
        ))?;
        let hash = Sha256::digest(canonical.as_bytes());
        let mut bits = 0u8;
        for byte in &hash {
            if *byte == 0 { bits += 8; }
            else { bits += byte.leading_zeros() as u8; break; }
        }
        if bits >= difficulty {
            return Ok((hex::encode(&hash), nonce));
        }
    }
    anyhow::bail!("PoW mining exhausted")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;

    /// Verify the NIP-44 round-trip that the gift-wrap layer uses.
    #[test]
    fn test_seal_roundtrip() {
        let (sender_priv, _sender_pub) = generate_keypair();
        let (recipient_priv, recipient_pub) = generate_keypair();

        let plaintext = r#"{"kind":14,"content":"hello"}"#;
        let encrypted = nip44::encrypt(plaintext, &sender_priv, &recipient_pub).unwrap();

        let sender_pub = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sender_priv);
        let decrypted = nip44::decrypt(&encrypted, &recipient_priv, &sender_pub).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_event_id_hash_deterministic() {
        let canonical = json!([0, "pubkey", 1234567890i64, 13, [], "content"]);
        let id1 = event_id_hash(&canonical).unwrap();
        let id2 = event_id_hash(&canonical).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn test_jitter_within_bounds() {
        let base = 1_700_000_000i64;
        for _ in 0..100 {
            let j = jitter_timestamp(base);
            assert!((base - 300..=base + 300).contains(&j));
        }
    }
}
