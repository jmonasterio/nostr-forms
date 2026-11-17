//! `POST /submit` envelope checks: the part of direct submission that needs
//! no D1, no key and no network, so it unit-tests on the host.
//!
//! The browser SDK (`web/forms.js`) used to publish its kind-4 envelope to
//! `wss://relay.argw.com` and this Worker polled it back. The relay stopped
//! accepting anonymous writes on 2026-07-26 (nostr-relay-rs `52e1acc`), so the
//! SDK now POSTs the same signed event here. These checks stand in for what
//! the relay used to do at ingest: a well-formed, signed, current event
//! addressed to this processor. Everything after that (decrypt, form lookup,
//! per-form PoW, per-key rate limit, booking, delivery) is
//! `process::process_event`.

use crate::event::Event;

/// Largest body accepted. A contact form envelope is a few KB; the relay's
/// own cap on an event is 64 KiB.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// How far `created_at` may sit from the Worker's clock, either way. The SDK
/// stamps the event just before mining PoW, which takes seconds at 16 bits.
pub const MAX_SKEW_SECS: u64 = 10 * 60;

/// Envelope kind the SDK sends (NIP-04 kind number, NIP-44 content).
pub const SUBMISSION_KIND: u16 = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    TooLarge,
    BadJson,
    WrongKind,
    WrongRecipient,
    StaleOrFuture,
    IdMismatch,
    BadSignature,
}

impl Reject {
    /// Short machine-readable reason returned to the browser.
    pub fn reason(&self) -> &'static str {
        match self {
            Reject::TooLarge => "too-large",
            Reject::BadJson => "bad-json",
            Reject::WrongKind => "wrong-kind",
            Reject::WrongRecipient => "wrong-recipient",
            Reject::StaleOrFuture => "bad-created-at",
            Reject::IdMismatch => "bad-id",
            Reject::BadSignature => "bad-signature",
        }
    }
}

/// Parse and check one submitted envelope. Cheap checks run before the
/// Schnorr verify so junk costs as little CPU as possible.
pub fn parse_and_check(body: &[u8], processor_pubkey: &str, now_secs: u64) -> Result<Event, Reject> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Reject::TooLarge);
    }
    let event: Event = serde_json::from_slice(body).map_err(|_| Reject::BadJson)?;
    if event.kind != SUBMISSION_KIND {
        return Err(Reject::WrongKind);
    }
    if event.first_p_tag() != Some(processor_pubkey) {
        return Err(Reject::WrongRecipient);
    }
    if event.created_at.abs_diff(now_secs) > MAX_SKEW_SECS {
        return Err(Reject::StaleOrFuture);
    }
    if event.compute_id() != event.id {
        return Err(Reject::IdMismatch);
    }
    if !event.verify_signature() {
        return Err(Reject::BadSignature);
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{sign_in_place, xonly_pubkey};

    const PROCESSOR: &str = "43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6";
    const NOW: u64 = 1_800_000_000;
    const SK: [u8; 32] = [7u8; 32];

    fn envelope(kind: u16, p: &str, created_at: u64) -> Event {
        let mut ev = Event {
            id: String::new(),
            pubkey: hex::encode(xonly_pubkey(&SK).unwrap()),
            created_at,
            kind,
            tags: vec![vec!["p".into(), p.into()], vec!["form_id".into(), "MpAETNds".into()]],
            content: "ciphertext".into(),
            sig: String::new(),
        };
        sign_in_place(&SK, &mut ev).unwrap();
        ev
    }

    fn body(ev: &Event) -> Vec<u8> {
        serde_json::to_vec(ev).unwrap()
    }

    #[test]
    fn accepts_a_signed_current_envelope_to_the_processor() {
        let ev = envelope(4, PROCESSOR, NOW - 30);
        assert_eq!(parse_and_check(&body(&ev), PROCESSOR, NOW).unwrap().id, ev.id);
    }

    #[test]
    fn rejects_an_envelope_for_another_recipient() {
        let ev = envelope(4, &"0".repeat(64), NOW);
        assert_eq!(parse_and_check(&body(&ev), PROCESSOR, NOW).unwrap_err(), Reject::WrongRecipient);
    }

    #[test]
    fn rejects_other_kinds() {
        let ev = envelope(1, PROCESSOR, NOW);
        assert_eq!(parse_and_check(&body(&ev), PROCESSOR, NOW).unwrap_err(), Reject::WrongKind);
    }

    #[test]
    fn rejects_created_at_outside_the_window_both_ways() {
        let old = envelope(4, PROCESSOR, NOW - MAX_SKEW_SECS - 1);
        let future = envelope(4, PROCESSOR, NOW + MAX_SKEW_SECS + 1);
        assert_eq!(parse_and_check(&body(&old), PROCESSOR, NOW).unwrap_err(), Reject::StaleOrFuture);
        assert_eq!(parse_and_check(&body(&future), PROCESSOR, NOW).unwrap_err(), Reject::StaleOrFuture);
    }

    #[test]
    fn rejects_tampered_content() {
        let mut ev = envelope(4, PROCESSOR, NOW);
        ev.content.push('x');
        assert_eq!(parse_and_check(&body(&ev), PROCESSOR, NOW).unwrap_err(), Reject::IdMismatch);
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let mut ev = envelope(4, PROCESSOR, NOW);
        let other = envelope(4, PROCESSOR, NOW - 1);
        ev.sig = other.sig;
        assert_eq!(parse_and_check(&body(&ev), PROCESSOR, NOW).unwrap_err(), Reject::BadSignature);
    }

    #[test]
    fn rejects_oversized_and_malformed_bodies() {
        assert_eq!(parse_and_check(&vec![b' '; MAX_BODY_BYTES + 1], PROCESSOR, NOW).unwrap_err(), Reject::TooLarge);
        assert_eq!(parse_and_check(b"{\"kind\":4}", PROCESSOR, NOW).unwrap_err(), Reject::BadJson);
    }
}
