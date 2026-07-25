//! Poll handler — pulls fresh envelopes from the relay, decrypts, routes by
//! form, rate-limits, seals at rest (NIP-44 to the admin), stores, and
//! delivers a NIP-17 DM to the form's notify pubkey.
//!
//! Pipeline per tick:
//! 1. Retry metadata-only delivery for any still-`pending` submissions.
//! 2. Read `cursor`; POST the poll filter to the relay (service binding).
//! 3. For each event: dedupe → decrypt → resolve form (active?) → PoW →
//!    rate-limit → seal → insert → deliver → update status.
//! 4. Advance `cursor` to max(created_at) seen.

use worker::*;

use crate::decrypt::{nip44_v2_decrypt, nip44_v2_encrypt};
use crate::event::Event;
use crate::notify;
use crate::pow;
use crate::storage;

/// Result of the booking claim for a submission carrying `slot_id`.
enum BookingOutcome {
    Booked { slot: String, starts_at: i64, duration_min: u32 },
    Conflict { slot: String },
    Invalid { slot: String },
}

pub async fn run_once(env: &Env) -> Result<()> {
    let db = env.d1("FORMS")?;
    storage::ensure_schema(&db).await?;

    let processor_pubkey = env
        .var("PROCESSOR_PUBKEY")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    if processor_pubkey.is_empty() {
        return Err(Error::RustError("PROCESSOR_PUBKEY not set".into()));
    }
    let processor_sk_hex = match env.secret("PROCESSOR_NSEC") {
        Ok(s) => s.to_string(),
        Err(_) => return Err(Error::RustError("PROCESSOR_NSEC not set".into())),
    };
    let processor_sk_bytes = match hex_to_array32(&processor_sk_hex) {
        Some(b) => b,
        None => return Err(Error::RustError("PROCESSOR_NSEC not 32-byte hex".into())),
    };
    // At-rest recipient: the dashboard admin (defaults to ADMIN_PUBKEY).
    let archive_pubkey = env
        .var("ADMIN_PUBKEY")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    if archive_pubkey.is_empty() {
        return Err(Error::RustError("ADMIN_PUBKEY (at-rest recipient) not set".into()));
    }
    let admin_token = match env.secret("ADMIN_INTERNAL_TOKEN") {
        Ok(s) => s.to_string(),
        Err(_) => return Err(Error::RustError("ADMIN_INTERNAL_TOKEN not set".into())),
    };

    let now_secs: i64 = (Date::now().as_millis() / 1000) as i64;

    // 1) Retry pending deliveries (metadata-only; full content stays in the
    //    dashboard since it is sealed to the admin, not the processor).
    retry_pending(env, &db, &processor_sk_bytes, &processor_pubkey, now_secs).await;

    // 2) Pull from the relay.
    let cursor = storage::get_cursor(&db).await?;
    let filter = storage::build_poll_filter(&processor_pubkey, cursor);
    let relay = env.service("RELAY")?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    headers.set("X-Admin-Token", &admin_token)?;
    let req = Request::new_with_init(
        "https://relay.internal/admin/poll",
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(filter.to_string().into())),
    )?;
    let mut resp = relay.fetch_request(req).await?;
    if resp.status_code() != 200 {
        return Err(Error::RustError(format!(
            "relay /admin/poll returned {}",
            resp.status_code()
        )));
    }
    let body = resp.text().await?;
    let events: Vec<Event> = serde_json::from_str(&body)
        .map_err(|e| Error::RustError(format!("poll: parse events: {e}")))?;
    console_log!("poll: fetched {} events", events.len());

    let mut max_created_at = cursor;
    let (mut inserted, mut skipped, mut rejected, mut delivered) = (0u64, 0u64, 0u64, 0u64);

    for event in events {
        max_created_at = max_created_at.max(event.created_at as i64);
        if storage::has_submission(&db, &event.id).await? {
            skipped += 1;
            continue;
        }

        let plaintext = match nip44_v2_decrypt(&event.content, &processor_sk_hex, &event.pubkey) {
            Ok(pt) => match String::from_utf8(pt) {
                Ok(s) => s,
                Err(_) => {
                    rejected += 1;
                    continue;
                }
            },
            Err(e) => {
                console_log!("poll: decrypt failed for {}: {e}", event.id);
                rejected += 1;
                continue;
            }
        };

        let slug = crate::form_id::resolve_slug(&plaintext, &archive_pubkey);
        let form = match storage::get_form(&db, &slug).await? {
            Some(f) if f.status == "active" => f,
            _ => {
                console_log!("poll: no active form '{slug}' for {}", event.id);
                rejected += 1;
                continue;
            }
        };

        if !pow::verify_pow(&event.id, form.pow_difficulty.max(0) as u32) {
            console_log!("poll: insufficient PoW for {} (form needs {})", event.id, form.pow_difficulty);
            rejected += 1;
            continue;
        }

        if !storage::rate_limit_check_and_inc(&db, &form.slug, &event.pubkey, now_secs, form.rate_limit_per_hour).await? {
            console_log!("poll: rate-limited {} on form {}", event.pubkey, form.slug);
            rejected += 1;
            continue;
        }

        // Booking path (BOOKING-PLAN §Routes): a top-level `slot_id` in the
        // payload means this submission claims a calendar slot. Validation
        // is membership in the same expansion the public route serves, so we
        // can never honor a slot that was never offerable. The claim is the
        // atomic INSERT-or-lose; losers are stored with a conflict status so
        // nothing is silently dropped.
        let booking_outcome = match crate::booking::extract_slot_id(&plaintext) {
            None => None,
            Some(slot) => match crate::booking::parse_config(&form.options_json) {
                Ok(Some(cfg)) => match crate::booking::slot_is_valid(&cfg, &form.slug, &slot, now_secs) {
                    Some(starts_at) => {
                        if storage::claim_slot(&db, &slot, &form.slug, starts_at, cfg.duration_min as i64, &event.id, now_secs).await? {
                            Some(BookingOutcome::Booked { slot, starts_at, duration_min: cfg.duration_min })
                        } else {
                            Some(BookingOutcome::Conflict { slot })
                        }
                    }
                    None => Some(BookingOutcome::Invalid { slot }),
                },
                Ok(None) => {
                    console_log!("poll: slot_id on non-booking form '{}' for {} — treating as plain submission", form.slug, event.id);
                    None
                }
                Err(e) => {
                    console_log!("poll: bad booking config on '{}': {e}", form.slug);
                    Some(BookingOutcome::Invalid { slot })
                }
            },
        };

        // Seal at rest to the admin, then store.
        let sealed = nip44_v2_encrypt(plaintext.as_bytes(), &processor_sk_hex, &archive_pubkey)
            .map_err(|e| Error::RustError(format!("seal at rest: {e}")))?;
        storage::insert_submission(&db, &event, &form.slug, &sealed, now_secs).await?;
        inserted += 1;

        // Deliver. Booking outcomes get dedicated messages (ICS on success);
        // plain submissions keep the existing notify/full split.
        let (message, ok_status) = match &booking_outcome {
            Some(BookingOutcome::Booked { slot, starts_at, duration_min }) => {
                let ics = crate::booking::ics_vevent(
                    slot,
                    *starts_at,
                    *duration_min,
                    &format!("Booking: {}", form.name),
                    &plaintext,
                );
                (notify::booking_message(&form.slug, &plaintext, *starts_at, &ics), "delivered")
            }
            Some(BookingOutcome::Conflict { slot }) => {
                (notify::booking_conflict_message(&form.slug, slot, &plaintext), "slot_conflict")
            }
            Some(BookingOutcome::Invalid { slot }) => {
                (notify::booking_invalid_message(&form.slug, slot, &plaintext), "slot_invalid")
            }
            None if form.delivery_mode == "notify" => {
                (notify::notice_message(&form.slug, &event.pubkey), "delivered")
            }
            None => (notify::full_message(&form.slug, &plaintext), "delivered"),
        };
        match notify::publish_dm(env, &processor_sk_bytes, &processor_pubkey, &form.notify_pubkey, &message, now_secs as u64).await {
            Ok(()) => {
                storage::set_delivery(&db, &event.id, ok_status, true).await?;
                delivered += 1;
            }
            Err(e) => console_log!("poll: delivery failed for {}: {e:?}", event.id),
        }
    }

    storage::set_cursor(&db, max_created_at, now_secs).await?;
    console_log!(
        "poll: cursor={max_created_at} inserted={inserted} delivered={delivered} skipped={skipped} rejected={rejected}"
    );
    Ok(())
}

/// Best-effort metadata-only redelivery of pending submissions.
async fn retry_pending(
    env: &Env,
    db: &D1Database,
    processor_sk_bytes: &[u8; 32],
    processor_pubkey: &str,
    now: i64,
) {
    let pending = match storage::pending_submissions(db, 20).await {
        Ok(p) => p,
        Err(e) => {
            console_log!("poll: pending query failed: {e:?}");
            return;
        }
    };
    for row in pending {
        let form = match storage::get_form(db, &row.form_slug).await {
            Ok(Some(f)) => f,
            _ => continue,
        };
        let msg = notify::notice_message(&row.form_slug, &row.submitter_pubkey);
        if notify::publish_dm(env, processor_sk_bytes, processor_pubkey, &form.notify_pubkey, &msg, now as u64)
            .await
            .is_ok()
        {
            let _ = storage::set_delivery(db, &row.event_id, "delivered", true).await;
        }
    }
}


fn hex_to_array32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}
