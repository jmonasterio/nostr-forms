//! Throwaway verification helper (native). Subcommands:
//!   keypair                         -> prints "<sk_hex> <pubkey_hex>"
//!   nip98 <sk> <method> <url> [body] -> prints an Authorization header value
//!   submission <proc_pub> <slug> <msg> [bits] -> prints a mined+signed event
//!
//! Used only to drive end-to-end verification of the deployed worker with a
//! key under our control (the real admin key is the user's and not available).

use nostr_form_rs::decrypt::nip44_v2_encrypt;
use nostr_form_rs::event::Event;
use nostr_form_rs::{pow, sign};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}
fn sha256hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}
fn compute_id(e: &Event) -> String {
    let s = serde_json::to_string(&(0u8, &e.pubkey, e.created_at, e.kind, &e.tags, &e.content)).unwrap();
    sha256hex(s.as_bytes())
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keypair") => {
            let mut sk = [0u8; 32];
            getrandom::getrandom(&mut sk).unwrap();
            println!("{} {}", hex::encode(sk), hex::encode(sign::xonly_pubkey(&sk).unwrap()));
        }
        Some("nip98") => {
            let sk = hex32(&a[2]);
            let (method, url) = (a[3].clone(), a[4].clone());
            let body = a.get(5).cloned().unwrap_or_default();
            let pubkey = hex::encode(sign::xonly_pubkey(&sk).unwrap());
            let mut tags = vec![vec!["u".into(), url], vec!["method".into(), method]];
            if !body.is_empty() {
                tags.push(vec!["payload".into(), sha256hex(body.as_bytes())]);
            }
            let mut ev = Event { id: String::new(), pubkey, created_at: now(), kind: 27235, tags, content: String::new(), sig: String::new() };
            sign::sign_in_place(&sk, &mut ev).unwrap();
            print!("Nostr {}", B64.encode(serde_json::to_string(&ev).unwrap()));
        }
        Some("submission") => {
            let proc_pub = a[2].clone();
            let slug = a[3].clone();
            let msg = a[4].clone();
            let bits: u32 = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(16);
            let slot = a.get(6).cloned();
            let mut sk = [0u8; 32];
            getrandom::getrandom(&mut sk).unwrap();
            let eph_pub = hex::encode(sign::xonly_pubkey(&sk).unwrap());
            let slot_field = slot
                .map(|s| format!("\"slot_id\":\"{s}\","))
                .unwrap_or_default();
            let plaintext =
                format!("{{\"form_id\":\"{slug}\",{slot_field}\"fields\":{{\"message\":\"{msg}\"}}}}");
            let ct = nip44_v2_encrypt(plaintext.as_bytes(), &hex::encode(sk), &proc_pub).expect("encrypt");

            // Mine the NIP-13 nonce tag until the event id carries `bits` of PoW.
            let mut counter: u64 = 0;
            loop {
                let mut ev = Event {
                    id: String::new(),
                    pubkey: eph_pub.clone(),
                    created_at: now(),
                    kind: 4,
                    tags: vec![
                        vec!["p".into(), proc_pub.clone()],
                        vec!["nonce".into(), counter.to_string(), bits.to_string()],
                    ],
                    content: ct.clone(),
                    sig: String::new(),
                };
                ev.id = compute_id(&ev);
                if pow::verify_pow(&ev.id, bits) {
                    sign::sign_in_place(&sk, &mut ev).unwrap();
                    println!("{}", serde_json::to_string(&ev).unwrap());
                    break;
                }
                counter += 1;
            }
        }
        _ => eprintln!("usage: keypair | nip98 <sk> <method> <url> [body] | submission <proc_pub> <slug> <msg> [bits] [slot_id]"),
    }
}