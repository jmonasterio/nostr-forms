//! Submission processing — decrypts, routes by form, rate-limits, seals at
//! rest (NIP-44 to the admin), stores, delivers a NIP-17 DM to the form's
//! notify pubkey, and emails the owner.
//!
//! Entry points:
//! * [`process_event`] — one envelope, from `POST /submit` (`submit_route`).
//! * [`retry_pending`] — metadata-only DM redelivery for rows whose DM
//!   failed, from `POST /admin/retry-pending`.
//!
//! Until 2026-11-17 a cron polled envelopes off the relay every minute
//! (`/admin/poll`). The relay stopped accepting anonymous writes on
//! 2026-07-26, so nothing arrived that way after that date; the browser SDK
//! now POSTs to `/submit` and the cron is gone.

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

/// Processor identity and at-rest recipient, read once per invocation.
#[derive(Clone)]
pub struct Keys {
    pub processor_pubkey: String,
    processor_sk_hex: String,
    processor_sk_bytes: [u8; 32],
    archive_pubkey: String,
}

impl Keys {
    pub fn from_env(env: &Env) -> Result<Self> {
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
        Ok(Keys { processor_pubkey, processor_sk_hex, processor_sk_bytes, archive_pubkey })
    }
}

/// What happened to one envelope.
pub enum Outcome {
    /// Already stored (same event id); nothing done.
    Duplicate,
    /// Not stored. The reason is short and safe to return to a browser.
    Rejected(&'static str),
    /// Stored in D1. The DM and owner email still have to go out:
    /// pass this to [`deliver`] (`/submit` does it after responding).
    Stored(Delivery),
}

/// Everything [`deliver`] needs, owned so it can outlive the request.
pub struct Delivery {
    event_id: String,
    submitter_pubkey: String,
    form: storage::Form,
    plaintext: String,
    booking_outcome: Option<BookingOutcome>,
}

/// Retry the DM for up to 20 `pending` rows. Returns how many were pending.
pub async fn retry_pending(env: &Env) -> Result<usize> {
    let db = env.d1("FORMS")?;
    storage::ensure_schema(&db).await?;
    let keys = Keys::from_env(env)?;
    let now: i64 = (Date::now().as_millis() / 1000) as i64;

    let pending = storage::pending_submissions(&db, 20).await?;
    let count = pending.len();
    for row in pending {
        let form = match storage::get_form(&db, &row.form_slug).await {
            Ok(Some(f)) => f,
            _ => continue,
        };
        let msg = notify::notice_message(&row.form_slug, &row.submitter_pubkey);
        if notify::publish_dm(env, &keys.processor_sk_bytes, &keys.processor_pubkey, &form.notify_pubkey, &msg, now as u64)
            .await
            .is_ok()
        {
            let _ = storage::set_delivery(&db, &row.event_id, "delivered", true).await;
        }
    }
    Ok(count)
}

/// dedupe → decrypt → resolve form (active?) → PoW → rate-limit → seal →
/// insert. Delivery is separate ([`deliver`]) so `/submit` can answer the
/// browser as soon as the row is stored. The caller has already checked the
/// envelope's id and signature (`submit::parse_and_check`).
pub async fn process_event(db: &D1Database, keys: &Keys, event: &Event, now_secs: i64) -> Result<Outcome> {
    if storage::has_submission(db, &event.id).await? {
        return Ok(Outcome::Duplicate);
    }

    let plaintext = match nip44_v2_decrypt(&event.content, &keys.processor_sk_hex, &event.pubkey) {
        Ok(pt) => match String::from_utf8(pt) {
            Ok(s) => s,
            Err(_) => return Ok(Outcome::Rejected("decrypt")),
        },
        Err(e) => {
            console_log!("process: decrypt failed for {}: {e}", event.id);
            return Ok(Outcome::Rejected("decrypt"));
        }
    };

    let slug = crate::form_id::resolve_slug(&plaintext, &keys.archive_pubkey);
    let form = match storage::get_form(db, &slug).await? {
        Some(f) if f.status == "active" => f,
        _ => {
            console_log!("process: no active form '{slug}' for {}", event.id);
            return Ok(Outcome::Rejected("unknown-form"));
        }
    };

    if !pow::verify_pow(&event.id, form.pow_difficulty.max(0) as u32) {
        console_log!("process: insufficient PoW for {} (form needs {})", event.id, form.pow_difficulty);
        return Ok(Outcome::Rejected("insufficient-pow"));
    }

    if !storage::rate_limit_check_and_inc(db, &form.slug, &event.pubkey, now_secs, form.rate_limit_per_hour).await? {
        console_log!("process: rate-limited {} on form {}", event.pubkey, form.slug);
        return Ok(Outcome::Rejected("rate-limited"));
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
                    if storage::claim_slot(db, &slot, &form.slug, starts_at, cfg.duration_min as i64, &event.id, now_secs).await? {
                        Some(BookingOutcome::Booked { slot, starts_at, duration_min: cfg.duration_min })
                    } else {
                        Some(BookingOutcome::Conflict { slot })
                    }
                }
                None => Some(BookingOutcome::Invalid { slot }),
            },
            Ok(None) => {
                console_log!("process: slot_id on non-booking form '{}' for {} — treating as plain submission", form.slug, event.id);
                None
            }
            Err(e) => {
                console_log!("process: bad booking config on '{}': {e}", form.slug);
                Some(BookingOutcome::Invalid { slot })
            }
        },
    };

    // Seal at rest to the admin, then store.
    let sealed = nip44_v2_encrypt(plaintext.as_bytes(), &keys.processor_sk_hex, &keys.archive_pubkey)
        .map_err(|e| Error::RustError(format!("seal at rest: {e}")))?;
    storage::insert_submission(db, event, &form.slug, &sealed, now_secs).await?;
    Ok(Outcome::Stored(Delivery {
        event_id: event.id.clone(),
        submitter_pubkey: event.pubkey.clone(),
        form,
        plaintext,
        booking_outcome,
    }))
}

/// NIP-17 DM to the form's notify key (through the relay), then the owner
/// email. Returns whether the DM went out; a failed DM leaves the row
/// `pending` for `POST /admin/retry-pending`.
pub async fn deliver(env: &Env, keys: &Keys, d: Delivery, now_secs: i64) -> bool {
    let Delivery { event_id, submitter_pubkey, form, plaintext, booking_outcome } = d;

    // Booking outcomes get dedicated messages (ICS on success); plain
    // submissions keep the existing notify/full split.
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
            (notify::notice_message(&form.slug, &submitter_pubkey), "delivered")
        }
        None => (notify::full_message(&form.slug, &plaintext), "delivered"),
    };
    let delivered = match notify::publish_dm(env, &keys.processor_sk_bytes, &keys.processor_pubkey, &form.notify_pubkey, &message, now_secs as u64).await {
        Ok(()) => {
            match env.d1("FORMS") {
                Ok(db) => {
                    if let Err(e) = storage::set_delivery(&db, &event_id, ok_status, true).await {
                        console_log!("process: set_delivery failed for {event_id}: {e:?}");
                    }
                }
                Err(e) => console_log!("process: FORMS binding: {e:?}"),
            }
            true
        }
        Err(e) => {
            console_log!("process: delivery failed for {event_id}: {e:?}");
            false
        }
    };

    // Owner email alert via the NOTIFY binding. Metadata + the decrypted
    // fields; nostr-notify renders and sends. Sent whether or not the DM
    // went out: the DM rides the relay, and a relay fault must not also
    // silence the email. A failure here only logs.
    let fields = notify::fields_of(&plaintext);
    let alert = match &booking_outcome {
        Some(BookingOutcome::Booked { starts_at, .. }) => {
            notify::alert_booking(&form.name, *starts_at, "booked", fields)
        }
        // `slot_id` is `<slug>:<starts_at>` — recover the time so the email
        // still says *when*, even on a failed claim.
        Some(BookingOutcome::Conflict { slot }) => {
            let at = crate::booking::parse_slot_id(slot).map(|(_, t)| t).unwrap_or(0);
            notify::alert_booking(&form.name, at, "conflict", fields)
        }
        Some(BookingOutcome::Invalid { slot }) => {
            let at = crate::booking::parse_slot_id(slot).map(|(_, t)| t).unwrap_or(0);
            notify::alert_booking(&form.name, at, "invalid", fields)
        }
        None => notify::alert_submission(&form.name, fields),
    };
    if let Err(e) = notify::send_alert(env, &alert).await {
        console_log!("process: alert failed for {event_id}: {e:?}");
    }
    delivered
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
