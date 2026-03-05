use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::SecretKey;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::crypto::keys::{self, verify_pow};
use crate::forwarder::{send_dm, WsSink};
use crate::registry::models::{DeliveryStatus, FormStatus, Submission, SubmissionType};
use crate::registry::storage::Database;

use super::decryptor::decrypt_submission;

/// Maximum delivery attempts before a submission is marked Exhausted.
const MAX_ATTEMPTS: u32 = 5;

/// Run the processor worker. Reconnects with backoff on failure.
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
            Ok(_) => info!("Connection closed cleanly"),
            Err(e) => error!("Connection error: {}", e),
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
    let (write, mut read) = ws_stream.split();
    let sink: Arc<WsSink> = Arc::new(Mutex::new(write));

    info!("Connected to relay");

    // Subscribe to events tagged with processor pubkey (last hour).
    // We retry older Failed submissions explicitly below rather than
    // relying on relay history.
    let req = serde_json::json!([
        "REQ",
        "form_processor",
        {
            "#p": [processor_pubkey],
            "since": chrono::Utc::now().timestamp() - 3600
        }
    ]);
    sink.lock().await.send(Message::Text(req.to_string())).await?;
    info!("Subscribed to events tagged with processor pubkey");

    // Retry any previously-failed submissions using this connection.
    retry_failed(db, processor_privkey, &sink).await;

    while let Some(msg) = read.next().await {
        let msg = msg?;
        if let Message::Text(text) = msg {
            if let Err(e) =
                handle_message(&text, db, processor_privkey, &sink).await
            {
                warn!("Error handling message: {}", e);
            }
        }
    }

    Ok(())
}

/// On each fresh connection, retry every Failed submission that has not yet
/// been exhausted.
async fn retry_failed(db: &Database, processor_privkey: &SecretKey, sink: &Arc<WsSink>) {
    let failed = match db.list_failed_submissions() {
        Ok(v) => v,
        Err(e) => {
            warn!("Could not load failed submissions: {}", e);
            return;
        }
    };

    if failed.is_empty() {
        return;
    }

    info!("Retrying {} failed submission(s)", failed.len());

    for sub in failed {
        if let Err(e) = retry_submission(&sub, db, processor_privkey, sink).await {
            warn!("Retry failed for {}: {}", sub.event_id, e);
        }
    }
}

async fn retry_submission(
    sub: &Submission,
    db: &Database,
    processor_privkey: &SecretKey,
    sink: &Arc<WsSink>,
) -> anyhow::Result<()> {
    // Exhaustion check
    if sub.delivery_attempts >= MAX_ATTEMPTS {
        db.update_submission_status(&sub.event_id, DeliveryStatus::Exhausted, None)?;
        info!("Submission {} exhausted after {} attempts", sub.event_id, sub.delivery_attempts);
        return Ok(());
    }

    let form = match db.get_form(&sub.form_id)? {
        Some(f) => f,
        None => {
            warn!("Form {} not found for retry of {}", sub.form_id, sub.event_id);
            return Ok(());
        }
    };

    if form.status == FormStatus::Paused || form.status == FormStatus::Deleted {
        debug!("Skipping retry for {} — form is {:?}", sub.event_id, form.status);
        return Ok(());
    }

    // Need decrypted content; it should already be stored.
    let decrypted_json = match &sub.decrypted_content {
        Some(j) => j.clone(),
        None => {
            warn!("No decrypted content for {}, cannot retry", sub.event_id);
            return Ok(());
        }
    };

    let payload: crate::registry::models::SubmissionPayload =
        serde_json::from_str(&decrypted_json)?;

    dispatch_dm(db, processor_privkey, sink, &sub.event_id, &form, &payload, &sub.sender_pubkey, form.pow_difficulty)
        .await
}

async fn handle_message(
    text: &str,
    db: &Database,
    processor_privkey: &SecretKey,
    sink: &Arc<WsSink>,
) -> anyhow::Result<()> {
    let msg: serde_json::Value = serde_json::from_str(text)?;
    let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "EVENT" => {
            if let Some(event) = msg.get(2) {
                handle_event(event, db, processor_privkey, sink).await?;
            }
        }
        "EOSE" => debug!("End of stored events"),
        "OK"   => {} // publication confirmation; already logged on send
        "NOTICE" => {
            if let Some(notice) = msg.get(1).and_then(|v| v.as_str()) {
                info!("Relay notice: {}", notice);
            }
        }
        _ => debug!("Unknown message type: {}", msg_type),
    }

    Ok(())
}

async fn handle_event(
    event: &serde_json::Value,
    db: &Database,
    processor_privkey: &SecretKey,
    sink: &Arc<WsSink>,
) -> anyhow::Result<()> {
    let event_id  = event["id"].as_str().unwrap_or("");
    let pubkey    = event["pubkey"].as_str().unwrap_or("");
    let content   = event["content"].as_str().unwrap_or("");
    let created_at = event["created_at"].as_i64().unwrap_or(0);
    let tags      = event["tags"].as_array();

    if db.submission_exists(event_id)? {
        debug!("Event {} already processed, skipping", event_id);
        return Ok(());
    }

    info!("Processing event: {}", event_id);

    // Extract tags
    let mut form_id = None;
    let mut submission_type = SubmissionType::Anon;
    let mut pow_difficulty: u8 = 0;
    // Present when sender used NIP-07: the ephemeral pubkey was used for NIP-44.
    let mut ephemeral_pubkey: Option<String> = None;

    if let Some(tags) = tags {
        for tag in tags {
            if let Some(arr) = tag.as_array() {
                let name  = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let value = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
                match name {
                    "form_id" => form_id = Some(value.to_string()),
                    "submission_type" => {
                        if value == "authenticated" {
                            submission_type = SubmissionType::Authenticated;
                        }
                    }
                    "nonce" => {
                        if let Some(diff) = arr.get(2).and_then(|v| v.as_str()) {
                            pow_difficulty = diff.parse().unwrap_or(0);
                        }
                    }
                    "ephemeral" => ephemeral_pubkey = Some(value.to_string()),
                    _ => {}
                }
            }
        }
    }

    // Verify PoW
    if pow_difficulty > 0 && !verify_pow(event_id, pow_difficulty) {
        warn!("Event {} failed PoW verification (claimed {} bits)", event_id, pow_difficulty);
        return Ok(());
    }

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

    // Respect Paused / Deleted status — don't accept new submissions
    if form.status == FormStatus::Paused || form.status == FormStatus::Deleted {
        debug!("Ignoring event {} — form {} is {:?}", event_id, form_id, form.status);
        return Ok(());
    }

    // Form-specific PoW floor
    if pow_difficulty < form.pow_difficulty {
        warn!(
            "Event {} PoW {} < required {} for form {}",
            event_id, pow_difficulty, form.pow_difficulty, form_id
        );
        return Ok(());
    }

    // Rate limit
    let rate_key = format!("form:{}", form_id);
    if !db.check_rate_limit(&rate_key, form.rate_limit_per_hour, 3600)? {
        warn!("Rate limit exceeded for form {}", form_id);
        return Ok(());
    }

    // Store submission
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

    // Decrypt: use the ephemeral pubkey if present (NIP-07 authenticated path),
    // otherwise use the event sender pubkey (anon path).
    let decrypt_pubkey = ephemeral_pubkey.as_deref().unwrap_or(pubkey);
    match decrypt_submission(content, decrypt_pubkey, processor_privkey) {
        Ok(payload) => {
            let decrypted_json = serde_json::to_string(&payload)?;
            db.update_submission_decrypted(event_id, &decrypted_json)?;
            info!("Decrypted submission {}: {} fields", event_id, payload.fields.len());

            dispatch_dm(db, processor_privkey, sink, event_id, &form, &payload, pubkey, form.pow_difficulty).await?;
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

/// Send a DM and update the submission status.
async fn dispatch_dm(
    db: &Database,
    processor_privkey: &SecretKey,
    sink: &Arc<WsSink>,
    event_id: &str,
    form: &crate::registry::models::Form,
    payload: &crate::registry::models::SubmissionPayload,
    sender_pubkey: &str,
    pow_difficulty: u8,
) -> anyhow::Result<()> {
    match send_dm(
        sink,
        processor_privkey,
        &form.notify_pubkey,
        &form.name,
        event_id,
        payload,
        sender_pubkey,
        pow_difficulty,
    )
    .await
    {
        Ok(_) => {
            db.update_submission_status(event_id, DeliveryStatus::Delivered, None)?;
            info!("DM delivered for submission {}", event_id);
        }
        Err(e) => {
            let msg = format!("DM failed: {}", e);
            warn!("{} for submission {}", msg, event_id);

            // Look up current attempt count to decide fate
            let attempts = db
                .get_submission(event_id)?
                .map(|s| s.delivery_attempts + 1)
                .unwrap_or(1);

            let next_status = if attempts >= MAX_ATTEMPTS {
                DeliveryStatus::Exhausted
            } else {
                DeliveryStatus::Failed
            };

            db.update_submission_status(event_id, next_status, Some(&msg))?;
        }
    }

    Ok(())
}
