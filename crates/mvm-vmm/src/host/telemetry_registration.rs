//! Authoritative host-side binding of a guest's telemetry key to one boot.
//!
//! The encrypted telemetry transport pins an expected guest key, but a key
//! alone cannot say *which boot* it authenticates: a warm child restores its
//! parent's key from memory, and a state dir outlives every boot that used
//! it. This record is the host's answer — written at the same seam that
//! establishes the guest identity, once per boot, and consulted by whatever
//! dials the guest's telemetry port. A collector that resolved a peer before
//! a re-registration holds a stale boot and is refused, so records from a
//! previous boot cannot authorize a connection to the current one.
//!
//! Registration is authority for *expectation*, not proof of delivery: the
//! cryptographic session still authenticates the peer; this file only decides
//! which key and which boot the host is willing to authenticate against.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Filename of the per-boot telemetry registration, inside a VM's state dir.
pub const TELEMETRY_REGISTRATION_FILE: &str = "telemetry-registration.json";

/// One boot's registration: the key the host will authenticate, bound to a
/// fresh boot id and a per-state-dir generation counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryBootRegistration {
    /// The VM this registration is for; a resolver asking for another name
    /// is refused rather than handed a neighbouring VM's key.
    pub vm_name: String,
    /// Fresh 16-byte hex id per registration. Two boots never share one,
    /// even when a warm child inherits its parent's key unchanged.
    pub boot_id: String,
    /// 1-based, incremented on every registration in this state dir, so a
    /// restart that reuses the dir demotes every earlier record.
    pub generation: u64,
    /// The guest verifying key this boot's telemetry peer must prove.
    pub guest_verifying_key_base64: String,
}

/// What a dialer needs to authenticate the *current* boot, resolved from the
/// registration and never from guest-supplied data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTelemetryPeer {
    /// The registered guest verifying key, decoded and validated.
    pub key: VerifyingKey,
    /// The boot this expectation belongs to.
    pub boot_id: String,
    /// The registration generation this expectation was resolved from.
    pub generation: u64,
}

fn decode_key(guest_verifying_key_base64: &str) -> Result<VerifyingKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(guest_verifying_key_base64)
        .context("invalid registered guest key encoding")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid registered guest key length"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid registered guest key")
}

/// Register the current boot's telemetry identity in `state_dir`.
///
/// Validates the key before writing (a registration nothing can authenticate
/// against is a wiring bug, refused at boot rather than at first dial),
/// supersedes any previous registration in the dir, and writes atomically so
/// a reader never observes a half-written record.
pub fn register_telemetry_boot(
    state_dir: &Path,
    vm_name: &str,
    guest_verifying_key_base64: &str,
) -> Result<TelemetryBootRegistration> {
    decode_key(guest_verifying_key_base64)?;
    if vm_name.trim().is_empty() {
        bail!("telemetry registration requires a VM name");
    }
    let generation = load_telemetry_registration(state_dir)?
        .map(|previous| previous.generation + 1)
        .unwrap_or(1);
    let mut boot_id = [0u8; 16];
    rand::rng().fill_bytes(&mut boot_id);
    let registration = TelemetryBootRegistration {
        vm_name: vm_name.to_string(),
        boot_id: hex::encode(boot_id),
        generation,
        guest_verifying_key_base64: guest_verifying_key_base64.to_string(),
    };
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let path = state_dir.join(TELEMETRY_REGISTRATION_FILE);
    let json = serde_json::to_vec_pretty(&registration)
        .context("serializing the telemetry boot registration")?;
    let staged = path.with_extension("json.tmp");
    std::fs::write(&staged, json).with_context(|| format!("writing {}", staged.display()))?;
    std::fs::rename(&staged, &path).with_context(|| format!("publishing {}", path.display()))?;
    Ok(registration)
}

/// Load the registration a boot persisted in `state_dir`, if any.
pub fn load_telemetry_registration(state_dir: &Path) -> Result<Option<TelemetryBootRegistration>> {
    let path = state_dir.join(TELEMETRY_REGISTRATION_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Resolve the expected peer for `vm_name`'s current boot.
///
/// Refuses a missing registration, a registration for a different VM, and a
/// key that no longer decodes — each by name, because every one of them is a
/// host wiring failure, not a guest the transport should try to talk to.
pub fn resolve_expected_telemetry_peer(
    state_dir: &Path,
    vm_name: &str,
) -> Result<ExpectedTelemetryPeer> {
    let registration = load_telemetry_registration(state_dir)?.with_context(|| {
        format!(
            "no telemetry boot registration in {}; this boot's identity was never registered",
            state_dir.display()
        )
    })?;
    if registration.vm_name != vm_name {
        bail!(
            "telemetry registration in {} is for VM {:?}, not {vm_name:?}",
            state_dir.display(),
            registration.vm_name,
        );
    }
    Ok(ExpectedTelemetryPeer {
        key: decode_key(&registration.guest_verifying_key_base64)?,
        boot_id: registration.boot_id,
        generation: registration.generation,
    })
}

/// Refuse an expectation resolved from a superseded registration.
///
/// The wrong-boot/wrong-generation gate: after a re-registration (restart,
/// warm claim into the same dir), an expectation carrying the old boot id or
/// generation must not authenticate anything — even when the key itself is
/// unchanged, because a warm child inherits its parent's key.
pub fn assert_peer_is_current(state_dir: &Path, peer: &ExpectedTelemetryPeer) -> Result<()> {
    let current = load_telemetry_registration(state_dir)?.with_context(|| {
        format!(
            "no telemetry boot registration in {}; nothing is current",
            state_dir.display()
        )
    })?;
    if current.boot_id != peer.boot_id || current.generation != peer.generation {
        bail!(
            "telemetry expectation is stale: resolved for boot {} (generation {}), current \
             registration is boot {} (generation {})",
            peer.boot_id,
            peer.generation,
            current.boot_id,
            current.generation,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key_b64() -> String {
        let key = SigningKey::from_bytes(&[7; 32]);
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
    }

    #[test]
    fn first_registration_starts_generation_one_with_a_fresh_hex_boot_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        assert_eq!(reg.generation, 1);
        assert_eq!(reg.vm_name, "vm-a");
        assert_eq!(reg.boot_id.len(), 32);
        assert!(reg.boot_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            load_telemetry_registration(dir.path()).unwrap().unwrap(),
            reg
        );
    }

    #[test]
    fn reregistration_bumps_the_generation_and_changes_the_boot_id() {
        let dir = tempfile::tempdir().unwrap();
        let first = register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        let second = register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        assert_eq!(second.generation, 2);
        assert_ne!(second.boot_id, first.boot_id);
        assert_eq!(
            second.guest_verifying_key_base64, first.guest_verifying_key_base64,
            "an inherited key re-registers unchanged"
        );
    }

    /// The wrong-boot refusal: a warm child inherits its parent's key, so the
    /// key alone cannot distinguish boots — the registration must.
    #[test]
    fn a_stale_expectation_is_refused_after_reregistration_even_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        let stale = resolve_expected_telemetry_peer(dir.path(), "vm-a").unwrap();
        assert_peer_is_current(dir.path(), &stale).unwrap();

        register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        let error = assert_peer_is_current(dir.path(), &stale)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stale"), "{error}");

        let fresh = resolve_expected_telemetry_peer(dir.path(), "vm-a").unwrap();
        assert_peer_is_current(dir.path(), &fresh).unwrap();
        assert_eq!(
            fresh.key, stale.key,
            "same key on both sides; only the boot binding distinguishes them"
        );
    }

    /// The wrong-VM refusal: a resolver must never be handed another VM's key.
    #[test]
    fn resolving_under_the_wrong_vm_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        let error = resolve_expected_telemetry_peer(dir.path(), "vm-b")
            .unwrap_err()
            .to_string();
        assert!(error.contains("vm-a") && error.contains("vm-b"), "{error}");
    }

    #[test]
    fn missing_registration_and_empty_vm_name_are_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let error = resolve_expected_telemetry_peer(dir.path(), "vm-a")
            .unwrap_err()
            .to_string();
        assert!(error.contains("never registered"), "{error}");
        assert!(
            assert_peer_is_current(
                dir.path(),
                &ExpectedTelemetryPeer {
                    key: SigningKey::from_bytes(&[7; 32]).verifying_key(),
                    boot_id: "0".repeat(32),
                    generation: 1,
                }
            )
            .is_err()
        );
        assert!(
            register_telemetry_boot(dir.path(), "  ", &key_b64())
                .unwrap_err()
                .to_string()
                .contains("VM name")
        );
    }

    #[test]
    fn invalid_keys_are_refused_at_registration_and_at_resolve() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["not base64!", "aGVsbG8="] {
            assert!(
                register_telemetry_boot(dir.path(), "vm-a", bad).is_err(),
                "{bad}"
            );
        }
        // A record tampered after registration fails at resolve, not silently.
        register_telemetry_boot(dir.path(), "vm-a", &key_b64()).unwrap();
        let path = dir.path().join(TELEMETRY_REGISTRATION_FILE);
        let mut reg: TelemetryBootRegistration =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        reg.guest_verifying_key_base64 = "aGVsbG8=".into();
        std::fs::write(&path, serde_json::to_vec(&reg).unwrap()).unwrap();
        assert!(resolve_expected_telemetry_peer(dir.path(), "vm-a").is_err());
    }

    #[test]
    fn unknown_fields_and_malformed_records_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TELEMETRY_REGISTRATION_FILE);
        std::fs::write(&path, br#"{"vm_name":"a","boot_id":"b","generation":1,"guest_verifying_key_base64":"c","surprise":true}"#).unwrap();
        assert!(load_telemetry_registration(dir.path()).is_err());
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_telemetry_registration(dir.path()).is_err());
    }
}
