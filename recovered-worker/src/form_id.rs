//! Form identifier resolution.
//!
//! A submission names its form either as a bare registry slug
//! (`"form_id":"MpAETNds"`) or as a NIP-101-style addressable coordinate
//! `30168:<owner-pubkey>:<slug>` (draft: nostr-protocol/nips PR #1190).
//! The coordinate form is self-certifying: the identifier is rooted in the
//! owner's pubkey instead of being a free-floating string, and it is the
//! `a`-tag format formstr-compatible clients use.
//!
//! A coordinate whose pubkey is not `owner_pubkey` (or whose kind is not
//! 30168) is NOT silently truncated to its slug — it resolves to the full
//! raw string, which cannot match a registry row, so the submission is
//! rejected downstream exactly like an unknown form.

/// Addressable-event kind for form templates (draft NIP-101).
pub const FORM_KIND: &str = "30168";

/// Resolve the registry slug from a decrypted submission payload.
/// Field precedence: `form_id` (the real client field), then `_form`,
/// then the catch-all `"default"`.
pub fn resolve_slug(plaintext: &str, owner_pubkey: &str) -> String {
    let raw = serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()
        .and_then(|v| {
            v.get("form_id")
                .or_else(|| v.get("_form"))
                .and_then(|x| x.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "default".to_string());
    match coordinate_slug(&raw, owner_pubkey) {
        Some(slug) => slug.to_string(),
        None => raw,
    }
}

/// If `id` is a well-formed `30168:<owner_pubkey>:<slug>` coordinate for
/// this owner, return the slug segment; otherwise `None`.
fn coordinate_slug<'a>(id: &'a str, owner_pubkey: &str) -> Option<&'a str> {
    let mut parts = id.splitn(3, ':');
    let kind = parts.next()?;
    let pubkey = parts.next()?;
    let slug = parts.next()?;
    if kind != FORM_KIND || slug.is_empty() {
        return None;
    }
    // Owner pubkeys are 64-char hex; compare case-insensitively.
    if pubkey.len() == 64 && pubkey.eq_ignore_ascii_case(owner_pubkey) {
        Some(slug)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "777d0ead9065a316d57773164ac4d013708f30f1235f089e12c22c4bbe4b625a";

    fn payload(form_id: &str) -> String {
        format!("{{\"form_id\":\"{form_id}\",\"fields\":{{\"message\":\"hi\"}}}}")
    }

    #[test]
    fn bare_slug_passes_through() {
        assert_eq!(resolve_slug(&payload("MpAETNds"), OWNER), "MpAETNds");
    }

    #[test]
    fn coordinate_resolves_to_slug() {
        let id = format!("30168:{OWNER}:booking");
        assert_eq!(resolve_slug(&payload(&id), OWNER), "booking");
    }

    #[test]
    fn coordinate_pubkey_case_insensitive() {
        let id = format!("30168:{}:booking", OWNER.to_uppercase());
        assert_eq!(resolve_slug(&payload(&id), OWNER), "booking");
    }

    #[test]
    fn coordinate_slug_may_contain_colons() {
        let id = format!("30168:{OWNER}:a:b");
        assert_eq!(resolve_slug(&payload(&id), OWNER), "a:b");
    }

    #[test]
    fn foreign_pubkey_is_not_truncated() {
        let other = "43100984ca619f567af6863c551c7c9ce5b75caead212e9334ca8cc88c9bc6c6";
        let id = format!("30168:{other}:booking");
        // Resolves to the full raw string -> unknown form -> rejected.
        assert_eq!(resolve_slug(&payload(&id), OWNER), id);
    }

    #[test]
    fn wrong_kind_is_not_truncated() {
        let id = format!("31923:{OWNER}:booking");
        assert_eq!(resolve_slug(&payload(&id), OWNER), id);
    }

    #[test]
    fn empty_coordinate_slug_is_not_truncated() {
        let id = format!("30168:{OWNER}:");
        assert_eq!(resolve_slug(&payload(&id), OWNER), id);
    }

    #[test]
    fn form_field_fallback_and_default() {
        assert_eq!(resolve_slug("{\"_form\":\"x\"}", OWNER), "x");
        assert_eq!(resolve_slug("{\"fields\":{}}", OWNER), "default");
        assert_eq!(resolve_slug("not json", OWNER), "default");
    }
}
