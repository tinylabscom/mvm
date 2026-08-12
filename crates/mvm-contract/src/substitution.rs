//! The guest-side placeholder token: its reserved namespace, its opaque
//! newtype, and the scan that locates one inside a request header.
//!
//! A guest never holds a credential. It holds a [`Placeholder`] — an opaque,
//! per-session token — and routes the request to a host-local substitution
//! endpoint, which resolves the token, checks the destination binding, and
//! puts the real credential on the wire. This module is the part of that
//! path with no custody, no I/O and no randomness: what a token looks like,
//! and how to find one in a string.
//!
//! Minting stays host-side. Generating a token draws from the OS RNG, which
//! is exactly the `getrandom`-in-the-bundle dependency the browser build
//! avoids, so [`Placeholder::new`] takes the token as given and the caller
//! decides where the bytes came from.
//!
//! # Three prefixes, none interchangeable
//!
//! Be precise about which notation you mean:
//!
//! | Notation | Where | What it is |
//! |---|---|---|
//! | `mvm-secret-<hex>` | here | the runtime wire token a guest actually holds |
//! | `mvm-managed:<var>` | [`crate::policy::secret_binding`] | a CLI binding's display form |
//! | `${NAME}` | the Workload IR | an authoring notation; nothing resolves it at runtime |
//!
//! The constant here is [`SECRET_PLACEHOLDER_PREFIX`] rather than a third
//! `PLACEHOLDER_PREFIX` precisely so the first two cannot be confused at a
//! glance in this crate.

use alloc::string::String;

/// The host-owned namespace every minted [`Placeholder`] carries. This prefix
/// is reserved: it must never appear in a workload's own egress, so the
/// leak scan can drop any non-substitution egress that contains it — the
/// legitimate substitution path routes the placeholder to the host-local
/// endpoint, never out the raw egress wire.
pub const SECRET_PLACEHOLDER_PREFIX: &str = "mvm-secret-";

/// An opaque, per-session placeholder standing in for a secret on the guest
/// side. **Not** the secret name and **not** the value: a leaked
/// placeholder reveals nothing and resolves to nothing outside the session
/// registry that minted it. Destination non-replay comes from the binding
/// check at substitution time, not the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Placeholder(String);

impl Placeholder {
    /// Wrap an already-generated token.
    ///
    /// Deliberately does not generate one: entropy is the caller's business,
    /// which keeps the RNG on the host side of this crate's boundary. A
    /// caller that hands over a low-entropy or attacker-chosen string gets a
    /// guessable placeholder — the type is a wrapper, not a guarantee.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The on-the-wire token form the guest embeds in its request.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Find the first placeholder token embedded in `text` (e.g. a header value
/// `Bearer mvm-secret-<hex>`). Returns the `mvm-secret-<hex>` slice — the
/// reserved prefix plus its trailing hex run — or `None` if no token is
/// present. Used by the substitution endpoint to locate the placeholder a
/// guest put in a request header without the guest having to name the header.
pub fn find_placeholder(text: &str) -> Option<&str> {
    let start = text.find(SECRET_PLACEHOLDER_PREFIX)?;
    let after = start + SECRET_PLACEHOLDER_PREFIX.len();
    let hex_len = text[after..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    if hex_len == 0 {
        return None;
    }
    Some(&text[start..after + hex_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;

    #[test]
    fn find_placeholder_extracts_token_from_a_header_value() {
        let ph = Placeholder::new(format!("{SECRET_PLACEHOLDER_PREFIX}deadbeef"));
        let header = format!("Bearer {}", ph.as_str());
        assert_eq!(find_placeholder(&header), Some(ph.as_str()));
    }

    #[test]
    fn find_placeholder_stops_at_non_hex_and_ignores_clean_text() {
        // Trailing non-hex (quote, space) bounds the token.
        assert_eq!(
            find_placeholder("Bearer mvm-secret-abc123\"; x=1"),
            Some("mvm-secret-abc123")
        );
        // No token, and the bare prefix with no hex run, both yield None.
        assert_eq!(find_placeholder("Bearer ya29.real-token"), None);
        assert_eq!(find_placeholder("mvm-secret-"), None);
    }

    #[test]
    fn the_two_reserved_prefixes_do_not_collide() {
        // `mvm-managed:` is the CLI binding's display form and must never be
        // mistaken for a runtime token. Asserted rather than assumed, because
        // both now live in this crate.
        let managed = crate::policy::secret_binding::PLACEHOLDER_PREFIX;
        assert_ne!(managed, SECRET_PLACEHOLDER_PREFIX);
        assert_eq!(find_placeholder("mvm-managed:OPENAI_API_KEY"), None);
    }
}
