//! NIP-17 gift wrap: build a wrap and unwrap it as a recipient client
//! would (two NIP-44 decryptions), confirming structure and recovery.

use k256::schnorr::SigningKey;

use nostr_form_rs::decrypt::nip44_v2_decrypt;
use nostr_form_rs::event::Event;
use nostr_form_rs::seal::gift_wrap;

fn keypair(seed: u8) -> ([u8; 32], String) {
    let sk = [seed; 32];
    let pk = SigningKey::from_bytes(&sk).unwrap().verifying_key().to_bytes();
    (sk, hex::encode(pk))
}

#[test]
fn wrap_unwraps_to_original_message() {
    let (proc_sk, proc_pk) = keypair(11);
    let (recip_sk, recip_pk) = keypair(22);
    let recip_sk_hex = hex::encode(recip_sk);
    let msg = r#"{"v":1,"form_id":"contact","fields":{"email":"a@b.c","message":"hi"}}"#;
    let now = 1_780_000_000u64;

    let wrap = gift_wrap(&proc_sk, &proc_pk, &recip_pk, msg, now).expect("wrap");

    // Outer gift wrap: kind 1059, ephemeral author, #p recipient,
    // timestamp backdated (<= now).
    assert_eq!(wrap.kind, 1059);
    assert_ne!(wrap.pubkey, proc_pk, "wrap must be signed by an ephemeral key");
    assert!(wrap.created_at <= now);
    assert_eq!(wrap.first_p_tag(), Some(recip_pk.as_str()));

    // Recipient unwraps layer 1: NIP-44(recipient_sk, ephemeral_pub).
    let seal_json = nip44_v2_decrypt(&wrap.content, &recip_sk_hex, &wrap.pubkey).expect("unwrap seal");
    let seal: Event = serde_json::from_slice(&seal_json).unwrap();
    assert_eq!(seal.kind, 13);
    assert_eq!(seal.pubkey, proc_pk, "seal authored by processor");

    // Layer 2: NIP-44(recipient_sk, processor_pub) → rumor.
    let rumor_json = nip44_v2_decrypt(&seal.content, &recip_sk_hex, &seal.pubkey).expect("unwrap rumor");
    let rumor: Event = serde_json::from_slice(&rumor_json).unwrap();
    assert_eq!(rumor.kind, 14);
    assert_eq!(rumor.pubkey, proc_pk);
    assert_eq!(rumor.first_p_tag(), Some(recip_pk.as_str()));
    assert_eq!(rumor.content, msg, "recovered message must equal original");
    assert!(rumor.sig.is_empty(), "rumor is unsigned");
}

#[test]
fn each_wrap_uses_a_fresh_ephemeral_key() {
    let (proc_sk, proc_pk) = keypair(11);
    let (_r, recip_pk) = keypair(22);
    let a = gift_wrap(&proc_sk, &proc_pk, &recip_pk, "x", 1_780_000_000).unwrap();
    let b = gift_wrap(&proc_sk, &proc_pk, &recip_pk, "x", 1_780_000_000).unwrap();
    assert_ne!(a.pubkey, b.pubkey, "ephemeral keys must differ per wrap");
    assert_ne!(a.id, b.id);
}
