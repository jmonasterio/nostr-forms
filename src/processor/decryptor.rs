use crate::crypto::{keys, nip44};
use crate::registry::models::SubmissionPayload;
use secp256k1::SecretKey;

/// Decrypt a form submission and parse the payload
pub fn decrypt_submission(
    encrypted_content: &str,
    sender_pubkey_hex: &str,
    recipient_privkey: &SecretKey,
) -> anyhow::Result<SubmissionPayload> {
    // Parse sender pubkey
    let sender_pubkey = keys::pubkey_from_hex(sender_pubkey_hex)?;

    // Decrypt
    let plaintext = nip44::decrypt(encrypted_content, recipient_privkey, &sender_pubkey)?;

    // Parse JSON payload
    let payload: SubmissionPayload = serde_json::from_str(&plaintext)?;

    // Validate payload version
    if payload.v != 1 {
        anyhow::bail!("Unsupported payload version: {}", payload.v);
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;
    use crate::crypto::nip44::encrypt;

    #[test]
    fn test_decrypt_submission() {
        let (sender_priv, sender_pub) = generate_keypair();
        let (recipient_priv, recipient_pub) = generate_keypair();

        let payload = r#"{
            "v": 1,
            "fields": {
                "name": "Test User",
                "email": "test@example.com"
            },
            "meta": {}
        }"#;

        let encrypted = encrypt(payload, &sender_priv, &recipient_pub).unwrap();
        let sender_pubkey_hex = keys::pubkey_to_hex(&sender_pub);

        let result = decrypt_submission(&encrypted, &sender_pubkey_hex, &recipient_priv).unwrap();

        assert_eq!(result.v, 1);
        assert_eq!(
            result.fields.get("name").unwrap().as_str().unwrap(),
            "Test User"
        );
    }
}
