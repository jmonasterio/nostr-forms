use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::SecretKey;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::crypto::keys::{self, verify_pow};
use crate::forwarder::send_dm;
use crate::registry::models::{DeliveryStatus, Submission, SubmissionType};
use crate::registry::storage::Database;

use super::decryptor::decrypt_submission;

/// Run the processor worker that subscribes to the relay and processes form submissions
pub async fn run(
    relay_url: String,
    db: Database,
    processor_privkey: SecretKey,
) -> anyhow::Result<()> {
    let processor_pubkey = {
        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &processor_privkey);
        keys::pubkey_to_hex(&pubkey)
    };

    info!("Processor pubkey: {}", processor_pubkey);
    info!("Starting processor worker, connecting to {}", relay_url);

    loop {
        match run_connection(&relay_url, &db, &processor_privkey, &processor_pubkey).await {
            Ok(_) => {
                info!("Connection closed cleanly");
            }
            Err(e) => {
                error!("Connection error: {}", e);
            }
        }

        info!("Reconnecting in 5 seconds...");
        sleep(Duration::from_secs(5)).await;
    }
}

async fn run_connection(
    relay_url: &str,
    db: &Database,
    processor_privkey: &SecretKey,
    processor_pubkey: &str,
) -> anyhow::Result<()> {
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    info!("Connected to relay");

    // Subscribe to events tagged with processor pubkey
    let sub_id = "form_processor";
    let req = serde_json::json!([
        "REQ",
        sub_id,
        {
            "#p": [processor_pubkey],
            "since": chrono::Utc::now().timestamp() - 3600 // Last hour
        }
    ]);

    write.send(Message::Text(req.to_string())).await?;
    info!("Subscribed to events tagged with processor pubkey");

    while let Some(msg) = read.next().await {
        let msg = msg?;

        if let Message::Text(text) = msg {
            if let Err(e) = handle_message(&text, db, processor_privkey, relay_url).await {
                warn!("Error handling message: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_message(
    text: &str,
    db: &Database,
    processor_privkey: &SecretKey,
    relay_url: &str,
) -> anyhow::Result<()> {
    let msg: serde_json::Value = serde_json::from_str(text)?;

    let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "EVENT" => {
            if let Some(event) = msg.get(2) {
                handle_event(event, db, processor_privkey, relay_url).await?;
            }
        }
        "EOSE" => {
            debug!("End of stored events");
        }
        "OK" => {
            // Event acceptance confirmation
        }
        "NOTICE" => {
            if let Some(notice) = msg.get(1).and_then(|v| v.as_str()) {
                info!("Relay notice: {}", notice);
            }
        }
        _ => {
            debug!("Unknown message type: {}", msg_type);
        }
    }

    Ok(())
}

async fn handle_event(
    event: &serde_json::Value,
    db: &Database,
    processor_privkey: &SecretKey,
    relay_url: &str,
) -> anyhow::Result<()> {
    let event_id = event["id"].as_str().unwrap_or("");
    let pubkey = event["pubkey"].as_str().unwrap_or("");
    let content = event["content"].as_str().unwrap_or("");
    let created_at = event["created_at"].as_i64().unwrap_or(0);
    let tags = event["tags"].as_array();

    // Check if already processed
    if db.submission_exists(event_id)? {
        debug!("Event {} already processed, skipping", event_id);
        return Ok(());
    }

    info!("Processing event: {}", event_id);

    // Extract tags
    let mut form_id = None;
    let mut submission_type = SubmissionType::Anon;
    let mut pow_difficulty: u8 = 0;

    if let Some(tags) = tags {
        for tag in tags {
            if let Some(tag_arr) = tag.as_array() {
                let tag_name = tag_arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let tag_value = tag_arr.get(1).and_then(|v| v.as_str()).unwrap_or("");

                match tag_name {
                    "form_id" => form_id = Some(tag_value.to_string()),
                    "submission_type" => {
                        if tag_value == "authenticated" {
                            submission_type = SubmissionType::Authenticated;
                        }
                    }
                    "nonce" => {
                        // Parse claimed difficulty from nonce tag
                        if let Some(diff) = tag_arr.get(2).and_then(|v| v.as_str()) {
                            pow_difficulty = diff.parse().unwrap_or(0);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Verify PoW
    if pow_difficulty > 0 {
        if !verify_pow(event_id, pow_difficulty) {
            warn!(
                "Event {} failed PoW verification (claimed {} bits)",
                event_id, pow_difficulty
            );
            return Ok(());
        }
        debug!(
            "Event {} passed PoW verification ({} bits)",
            event_id, pow_difficulty
        );
    }

    // Look up form
    let form_id = match form_id {
        Some(id) => id,
        None => {
            warn!("Event {} missing form_id tag", event_id);
            return Ok(());
        }
    };

    let form = match db.get_form(&form_id)? {
        Some(f) => f,
        None => {
            warn!("No form found for form_id {} (event {})", form_id, event_id);
            return Ok(());
        }
    };

    // Check form-specific PoW requirement
    if pow_difficulty < form.pow_difficulty {
        warn!(
            "Event {} PoW {} < required {} for form {}",
            event_id, pow_difficulty, form.pow_difficulty, form_id
        );
        return Ok(());
    }

    // Check rate limit
    let rate_key = format!("form:{}", form_id);
    if !db.check_rate_limit(&rate_key, form.rate_limit_per_hour, 3600)? {
        warn!("Rate limit exceeded for form {}", form_id);
        return Ok(());
    }

    // Create submission record
    let submission = Submission {
        event_id: event_id.to_string(),
        form_id: form_id.clone(),
        sender_pubkey: pubkey.to_string(),
        submission_type,
        encrypted_content: content.to_string(),
        decrypted_content: None,
        received_at: created_at,
        processed_at: None,
        delivery_status: DeliveryStatus::Pending,
        delivery_attempts: 0,
        last_delivery_error: None,
    };

    db.create_submission(&submission)?;
    info!("Stored submission {} for form {}", event_id, form_id);

    // Try to decrypt
    match decrypt_submission(content, pubkey, processor_privkey) {
        Ok(payload) => {
            let decrypted_json = serde_json::to_string(&payload)?;
            db.update_submission_decrypted(event_id, &decrypted_json)?;

            info!(
                "Decrypted submission {}: {} fields",
                event_id,
                payload.fields.len()
            );

            // Send DM to notify_pubkey
            match send_dm(
                relay_url,
                processor_privkey,
                &form.notify_pubkey,
                &form.name,
                event_id,
                &payload,
                pubkey,
            )
            .await
            {
                Ok(_) => {
                    db.update_submission_status(event_id, DeliveryStatus::Delivered, None)?;
                    info!("DM sent for submission {}", event_id);
                }
                Err(e) => {
                    let error_msg = format!("DM failed: {}", e);
                    db.update_submission_status(
                        event_id,
                        DeliveryStatus::Failed,
                        Some(&error_msg),
                    )?;
                    warn!("Failed to send DM for {}: {}", event_id, e);
                }
            }
        }
        Err(e) => {
            warn!("Failed to decrypt submission {}: {}", event_id, e);
            db.update_submission_status(
                event_id,
                DeliveryStatus::Failed,
                Some(&format!("Decryption failed: {}", e)),
            )?;
        }
    }

    Ok(())
}
