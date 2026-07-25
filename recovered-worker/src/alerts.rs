//! Owner email-alert bodies — pure string builders, no worker deps so they
//! compile and unit-test on the host (like `booking` / `form_id`).
//!
//! These become the `content` of the plaintext `["l","email"]` event the
//! processor publishes (see `notify::publish_email_alert`); the relay's
//! NOTIFY hook forwards it to the emailer, which turns the first line into
//! the email subject. **Metadata-only** — never embed the sealed submission
//! payload here.

/// Truncate a pubkey to a short, log-safe prefix (never the full key).
fn short_pk(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(12)]
}

/// Plain (non-booking) submission landed on a form.
pub fn submission(form_name: &str, submitter_pubkey: &str) -> String {
    format!(
        "New submission on \"{form_name}\" from {}",
        short_pk(submitter_pubkey)
    )
}

/// A calendar slot was successfully claimed.
pub fn booking(form_name: &str, starts_at_utc: &str) -> String {
    format!("New BOOKING on \"{form_name}\" — {starts_at_utc} UTC")
}

/// A booking attempt lost the slot race (someone got it first).
pub fn booking_missed(form_name: &str, slot: &str) -> String {
    format!("MISSED booking on \"{form_name}\" — slot {slot} already taken")
}

/// A booking attempt referenced a slot that was never offerable.
pub fn booking_rejected(form_name: &str, slot: &str) -> String {
    format!("Rejected booking on \"{form_name}\" — slot {slot} not offerable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6";

    #[test]
    fn short_pk_truncates_and_handles_short_input() {
        assert_eq!(short_pk("abc"), "abc");
        assert_eq!(short_pk(PK).len(), 12);
        assert_eq!(short_pk(PK), &PK[..12]);
    }

    #[test]
    fn submission_alert_is_metadata_only() {
        let body = submission("Contact", PK);
        assert!(body.contains("Contact"));
        assert!(body.contains(&PK[..12]));
        // Never leak the full submitter key (and certainly no payload).
        assert!(!body.contains(PK));
    }

    #[test]
    fn booking_alerts_lead_with_status_and_form() {
        assert!(booking("Discovery", "2026-06-20 17:00").contains("BOOKING"));
        assert!(booking("Discovery", "2026-06-20 17:00").contains("Discovery"));
        assert!(booking_missed("Discovery", "booking:1781787600").contains("MISSED"));
        assert!(booking_rejected("Discovery", "booking:1781787600").contains("Rejected"));
    }
}
