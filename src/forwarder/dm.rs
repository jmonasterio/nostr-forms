use secp256k1::{Secp256k1, SecretKey};
use serde_json::json;

use crate::crypto::{keys, nip44};
use crate::registry::models::SubmissionPayload;

/// Send form submission as encrypted Nostr DM to the notify_pubkey
pub async fn send_dm(
    relay_url: &str,
    processor_privkey: &SecretKey,
    notify_pubkey: &str,
    form_name: &str,
    event_id: &str,
    payload: &SubmissionPayload,
    sender_pubkey: &str,
) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    // Build DM content
    let mut content = format!("New form submission: {}\n\n", form_name);

    for (key, value) in &payload.fields {
        let value_str = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        content.push_str(&format!("{}: {}\n", key, value_str));
    }

    content.push_str(&format!("\n---\nEvent ID: {}\n", event_id));
    content.push_str(&format!("Sender: {}\n", sender_pubkey));
    if let Some(ref submitted_at) = payload.meta.submitted_at {
        content.push_str(&format!("Submitted: {}\n", submitted_at));
    }

    // Encrypt content to notify_pubkey
    let recipient_pubkey = keys::pubkey_from_hex(notify_pubkey)?;
    let encrypted_content = nip44::encrypt(&content, processor_privkey, &recipient_pubkey)?;

    // Build DM event (kind 4)
    let secp = Secp256k1::new();
    let processor_pubkey = secp256k1::PublicKey::from_secret_key(&secp, processor_privkey);
    let processor_pubkey_hex = keys::pubkey_to_hex(&processor_pubkey);

    let created_at = chrono::Utc::now().timestamp();

    let event_json = json!([
        0,
        processor_pubkey_hex,
        created_at,
        4,  // kind 4 = encrypted DM
        [["p", notify_pubkey]],
        encrypted_content
    ]);

    // Compute event ID
    let event_serialized = serde_json::to_string(&event_json)?;
    let event_hash = sha2::Sha256::digest(event_serialized.as_bytes());
    let event_id_hex = hex::encode(event_hash);

    // Sign event
    let msg = secp256k1::Message::from_digest_slice(&event_hash)?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &processor_privkey.keypair(&secp));
    let sig_hex = hex::encode(sig.as_ref());

    // Build final event
    let dm_event = json!({
        "id": event_id_hex,
        "pubkey": processor_pubkey_hex,
        "created_at": created_at,
        "kind": 4,
        "tags": [["p", notify_pubkey]],
        "content": encrypted_content,
        "sig": sig_hex
    });

    // Connect to relay and publish
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    let msg = json!(["EVENT", dm_event]);
    write.send(Message::Text(msg.to_string())).await?;

    // Wait for OK response
    let timeout = tokio::time::Duration::from_secs(10);
    let result = tokio::time::timeout(timeout, async {
        while let Some(msg) = read.next().await {
            if let Ok(Message::Text(text)) = msg {
                if let Ok(response) = serde_json::from_str::<serde_json::Value>(&text) {
                    if response.get(0).and_then(|v| v.as_str()) == Some("OK") {
                        let accepted = response.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                        if accepted {
                            return Ok(());
                        } else {
                            let reason = response.get(3).and_then(|v| v.as_str()).unwrap_or("unknown");
                            anyhow::bail!("Relay rejected DM: {}", reason);
                        }
                    }
                }
            }
        }
        anyhow::bail!("Connection closed without OK")
    })
    .await;

    match result {
        Ok(Ok(())) => {
            tracing::info!("DM sent to {} for form '{}'", &notify_pubkey[..16], form_name);
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("Timeout waiting for relay response"),
    }
}

use sha2::Digest;
