//! NIP-13 proof-of-work verifier — leading zero **bits** of the event id.
//! Same algorithm as `nostr-relay::pow`. Used as defense-in-depth on the
//! processor side (the relay already gates PoW at ingest).

/// Count leading zero bits in a hex-encoded id. `None` on invalid hex.
pub fn leading_zero_bits(id_hex: &str) -> Option<u32> {
    let mut bits: u32 = 0;
    for ch in id_hex.chars() {
        let nibble = ch.to_digit(16)?;
        if nibble == 0 {
            bits += 4;
        } else {
            bits += (nibble as u8).leading_zeros().saturating_sub(4);
            return Some(bits);
        }
    }
    Some(bits)
}

pub fn verify_pow(id_hex: &str, required_bits: u32) -> bool {
    leading_zero_bits(id_hex).is_some_and(|b| b >= required_bits)
}
