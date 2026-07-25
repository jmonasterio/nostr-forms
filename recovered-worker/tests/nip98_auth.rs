//! NIP-98 verification: happy path + each rejection branch. Builds and
//! signs real kind-27235 events with the worker's own signer.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

use nostr_form_rs::event::Event;
use nostr_form_rs::nip98::{verify, AuthError};
use nostr_form_rs::sign::sign_in_place;

const SK: [u8; 32] = [3u8; 32];
const NOW: u64 = 1_780_000_000;

fn pubkey_hex() -> String {
    hex::encode(SigningKey::from_bytes(&SK).unwrap().verifying_key().to_bytes())
}

fn hexsha(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

fn make_header(method: &str, url: &str, body: &[u8], created_at: u64) -> String {
    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if !body.is_empty() {
        tags.push(vec!["payload".to_string(), hexsha(body)]);
    }
    let mut ev = Event {
        id: String::new(),
        pubkey: pubkey_hex(),
        created_at,
        kind: 27235,
        tags,
        content: String::new(),
        sig: String::new(),
    };
    sign_in_place(&SK, &mut ev).unwrap();
    let json = serde_json::to_vec(&ev).unwrap();
    format!("Nostr {}", B64.encode(json))
}

#[test]
fn accepts_valid_get() {
    let url = "https://x.workers.dev/admin/forms";
    let h = make_header("GET", url, b"", NOW);
    let v = verify(&h, "GET", url, b"", NOW).expect("valid");
    assert_eq!(v.pubkey, pubkey_hex());
}

#[test]
fn accepts_valid_post_with_payload() {
    let url = "https://x.workers.dev/admin/forms";
    let body = br#"{"slug":"contact"}"#;
    let h = make_header("POST", url, body, NOW);
    verify(&h, "POST", url, body, NOW).expect("valid post");
}

#[test]
fn rejects_wrong_method() {
    let url = "https://x.workers.dev/admin/forms";
    let h = make_header("GET", url, b"", NOW);
    assert_eq!(verify(&h, "POST", url, b"", NOW).unwrap_err(), AuthError::MethodMismatch);
}

#[test]
fn rejects_wrong_url() {
    let h = make_header("GET", "https://x.workers.dev/admin/forms", b"", NOW);
    assert_eq!(
        verify(&h, "GET", "https://x.workers.dev/admin/submissions", b"", NOW).unwrap_err(),
        AuthError::UrlMismatch
    );
}

#[test]
fn rejects_tampered_body() {
    let url = "https://x.workers.dev/admin/forms";
    let h = make_header("POST", url, br#"{"slug":"a"}"#, NOW);
    assert_eq!(
        verify(&h, "POST", url, br#"{"slug":"b"}"#, NOW).unwrap_err(),
        AuthError::PayloadMismatch
    );
}

#[test]
fn rejects_stale_timestamp() {
    let url = "https://x.workers.dev/admin/forms";
    let h = make_header("GET", url, b"", NOW - 600);
    assert_eq!(verify(&h, "GET", url, b"", NOW).unwrap_err(), AuthError::StaleTimestamp);
}

#[test]
fn rejects_tampered_signature() {
    // Flip a tag after signing → id recomputation fails.
    let url = "https://x.workers.dev/admin/forms";
    let mut ev = Event {
        id: String::new(),
        pubkey: pubkey_hex(),
        created_at: NOW,
        kind: 27235,
        tags: vec![vec!["u".into(), url.into()], vec!["method".into(), "GET".into()]],
        content: String::new(),
        sig: String::new(),
    };
    sign_in_place(&SK, &mut ev).unwrap();
    ev.tags[0][1] = "https://evil.example/admin".into(); // mutate after signing
    let h = format!("Nostr {}", B64.encode(serde_json::to_vec(&ev).unwrap()));
    let err = verify(&h, "GET", "https://evil.example/admin", b"", NOW).unwrap_err();
    assert_eq!(err, AuthError::IdMismatch);
}

#[test]
fn rejects_wrong_kind() {
    let url = "https://x.workers.dev/admin/forms";
    let mut ev = Event {
        id: String::new(),
        pubkey: pubkey_hex(),
        created_at: NOW,
        kind: 1,
        tags: vec![vec!["u".into(), url.into()], vec!["method".into(), "GET".into()]],
        content: String::new(),
        sig: String::new(),
    };
    sign_in_place(&SK, &mut ev).unwrap();
    let h = format!("Nostr {}", B64.encode(serde_json::to_vec(&ev).unwrap()));
    assert_eq!(verify(&h, "GET", url, b"", NOW).unwrap_err(), AuthError::WrongKind(1));
}
