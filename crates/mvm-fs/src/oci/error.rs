//! Typed errors for `mvm-oci`.
//!
//! Each variant carries only the information needed to diagnose the
//! failure. Registry hostnames, repository names, and manifest media
//! types are not secrets and appear in error messages verbatim.
//! When private-registry auth lands, credential material will be
//! carried via [`secrecy::SecretString`] and the `Display` impl will
//! redact — that path is gated by the
//! `xtask check-no-display-on-secret-types` lint, so this enum can
//! stay plain until then.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OciError {
    /// The reference string did not parse — empty, malformed, or
    /// contained components that are reserved by the OCI spec.
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    /// Fetched-manifest content digest did not match the digest the
    /// caller pinned (or the digest the registry advertised). Always
    /// fail closed.
    #[error("manifest digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: String, computed: String },

    /// Caller asked us to verify a digest using an algorithm we do
    /// not implement. v1 supports `sha256` only; the OCI spec allows
    /// other algorithms but we narrow until they are explicitly
    /// audited.
    #[error("unsupported digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(String),

    /// Digest string was malformed (missing `algorithm:` prefix,
    /// truncated hex, mixed case, …). Spec compliance is strict; we
    /// do not silently normalize.
    #[error("malformed digest string: {0}")]
    MalformedDigest(String),

    /// The registry returned an error or the network call failed.
    /// The wrapped string is the upstream message verbatim — no
    /// credentials flow through this variant.
    #[error("registry error: {0}")]
    Registry(String),

    /// A layer descriptor's declared size, or the streamed byte
    /// count, exceeded the configured size cap. Decompression-bomb /
    /// oversized-layer mitigation. The
    /// `declared` value is the size the manifest claimed; `cap` is
    /// the value configured on `LayerFetchOptions::max_size`.
    #[error("layer size {declared} bytes exceeds cap of {cap} bytes")]
    LayerTooLarge { declared: u64, cap: u64 },
}
