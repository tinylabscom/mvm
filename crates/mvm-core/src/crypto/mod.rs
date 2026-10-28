pub mod aead;
pub mod attestation;
pub mod checkpoint_object;
// Host-side command gating (secret-token scanning). Off in guest builds.
#[cfg(feature = "host-state")]
pub mod command_gate;
pub mod constant_time;
pub mod digest_cache;
pub mod ed25519_keypair;
// Per-VM name-constrained egress CA for transparent https substitution.
// Gated so the runtime-free default build skips `rcgen`.
#[cfg(feature = "egress-ca")]
pub mod egress_ca;
pub mod entrypoint_delegation;
pub mod entrypoint_identity;
pub mod image_verify;
pub mod key_rotation;
// Key-provider backends (env/file/OS keychain). Only the pure
// `validate_shell_id` name validator is compiled for guests — the plan
// manifest validator shares it; every stateful provider is host-state.
pub mod keystore;
pub mod policy;
pub mod posture;
pub mod rate_limiter;
pub mod rotation_policy;
pub mod seccomp;
pub mod secret_binding;
// Secret-value stores. Host-state: secrets are written and read host-side.
#[cfg(feature = "host-state")]
pub mod secret_store;
pub mod snapshot_crypto;
pub mod snapshot_encryption;
pub mod snapshot_hmac;
pub mod snapshot_sign;
// Host-side threat classification of command lines. Off in guest builds.
#[cfg(feature = "host-state")]
pub mod threat_classifier;
pub mod verified_digest;
pub mod vmgenid;
pub mod volume;
