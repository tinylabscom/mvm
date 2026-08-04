//! Redacted, zeroizing wrapper for a secret value on its way into storage.
//!
//! [`SecretValueInput`] is the only shape secret material takes inside the
//! secret service, and it is strictly write-only: the wrapped value can be
//! handed to a [`mvm_core::crypto::secret_store::SecretStore`] for encrypted
//! persistence, but there is no public accessor, no `Display`, no serde, and
//! `Debug` prints a fixed redaction marker. The inner buffer is zeroized on
//! drop (via `secrecy`), so the plaintext lives exactly as long as the store
//! call that consumes it.

use secrecy::SecretBox;

/// A secret value accepted by the service for storage.
///
/// Construction moves the caller's `String` into a zeroize-on-drop container;
/// no copy of the plaintext remains under the caller's control. The service
/// consumes the input by value, so it is dropped — and its buffer zeroized —
/// immediately after the store write returns.
pub struct SecretValueInput {
    value: SecretBox<String>,
}

impl SecretValueInput {
    /// Wrap a plaintext value. The `String` is moved, not copied.
    pub fn new(value: String) -> Self {
        Self {
            value: SecretBox::new(Box::new(value)),
        }
    }

    /// Hand the wrapped value to the encrypted store. Crate-private on
    /// purpose: external callers can put a value in but never get one out.
    pub(crate) fn storage_value(&self) -> &SecretBox<String> {
        &self.value
    }
}

impl From<String> for SecretValueInput {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Debug for SecretValueInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValueInput(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn debug_output_is_redacted_and_never_contains_the_value() {
        let input = SecretValueInput::new("sk-live-topsecret".into());
        let rendered = format!("{input:?}");
        assert_eq!(rendered, "SecretValueInput(REDACTED)");
        assert!(!rendered.contains("topsecret"));
    }

    #[test]
    fn from_string_wraps_the_value_for_storage() {
        let input = SecretValueInput::from(String::from("v-123"));
        // In-crate storage handoff still carries the exact value; this is
        // the sole path out and it terminates inside the store.
        assert_eq!(input.storage_value().expose_secret(), "v-123");
    }
}
