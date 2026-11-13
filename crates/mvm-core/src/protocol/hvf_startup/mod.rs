//! Held startup bytes and experimental framing, never launch or capture authority.
//!
//! Decode before adopting descriptors. Independently validate the actual startup
//! configuration, original parent, consumed admission and native owner afterward.

use std::io::{self, Write};
use std::sync::Arc;

use serde::{Serialize, de::IgnoredAny};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "experimental-owned-capture")]
mod envelope;
#[cfg(feature = "experimental-owned-capture")]
pub use envelope::{MAX_ENVELOPE_BYTES, StartupEnvelope};
#[cfg(test)]
mod tests;

/// Existing inner supervisor configuration ceiling.
pub const CONFIG_LIMIT: usize = 8 * 1024 * 1024;

/// Discriminator is visible even in builds that must refuse the experimental input.
pub const OWNED_CAPTURE_MAGIC: &[u8; 8] = b"MVMOCAP\0";

/// Immutable configuration bytes. Clones share the original held allocation.
/// This is data, not a permit or proof of admission.
#[derive(Clone)]
pub struct FrozenConfig {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    digest: [u8; 32],
}

impl std::fmt::Debug for FrozenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrozenConfig")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Payload-free startup input errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StartupInputError {
    #[error("supervisor startup input exceeds its bounds or is truncated")]
    Bounds,
    #[error("supervisor startup input is malformed or unsupported")]
    Invalid,
    #[error("supervisor startup configuration digest does not match")]
    Binding,
}

type Result<T> = std::result::Result<T, StartupInputError>;

impl FrozenConfig {
    /// Serialize the final config once. Use this object's bytes for every startup
    /// destination and retain this object, not a second serialization, for binding.
    pub fn serialize<T: Serialize>(config: &T) -> Result<Self> {
        let mut output = ConfigBuffer::default();
        let result = serde_json::to_writer(&mut output, config);
        if output.exceeded {
            return Err(StartupInputError::Bounds);
        }
        result.map_err(|_| StartupInputError::Invalid)?;
        Self::from_held_json(output.bytes)
    }

    /// Preserve original input bytes, including whitespace. Valid JSON is not
    /// sufficient to establish the supervisor schema or admission authority.
    pub fn from_json(bytes: Vec<u8>) -> Result<Self> {
        Self::from_held_json(Zeroizing::new(bytes))
    }

    fn from_held_json(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > CONFIG_LIMIT {
            return Err(StartupInputError::Bounds);
        }
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{')
            || std::str::from_utf8(&bytes).is_err()
        {
            return Err(StartupInputError::Invalid);
        }
        serde_json::from_slice::<IgnoredAny>(&bytes).map_err(|_| StartupInputError::Invalid)?;
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            bytes: Arc::new(bytes),
            digest,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Default)]
struct ConfigBuffer {
    bytes: Zeroizing<Vec<u8>>,
    exceeded: bool,
}

impl Write for ConfigBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > CONFIG_LIMIT)
        {
            self.exceeded = true;
            return Err(io::Error::other(
                "supervisor configuration exceeds its byte bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
