//! Per-VM handoff of the admission-minted secret placeholders + egress-proxy
//! env. Written by the per-VM supervisor at boot (Plan 129 #1b), consumed by
//! `mvmctl` invoke (the `RunEntrypoint` workload env) and the guest `/init`.
//!
//! A sidecar in the VM state dir, parallel to the runtime `mode.json` that
//! `mvm_backend::base::runtime_meta` writes. It lives in `mvm-core` because
//! it is the lowest crate both the producer (`mvm-vm-host` supervisor bin)
//! and the consumer (`mvm-cli`) already depend on.
//!
//! The file carries only **opaque placeholders** (`mvm-secret-<hex>` tokens)
//! plus the loopback `HTTP_PROXY` env — never a real secret value
//! (ADR-067 §4 / claim 13). It is mode 0600 as defense-in-depth, not because
//! the tokens are themselves sensitive.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::vm_state_dir;

/// Ready-to-inject workload env for a running VM's egress substitution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstitutionHandoff {
    /// `(name, value)` env pairs injected into the workload after
    /// `env_clear()`: `HTTP_PROXY`/`HTTPS_PROXY` pointing at the guest-local
    /// forward proxy, plus the opaque placeholder vars (e.g. `OPENAI_API_KEY`
    /// -> `mvm-secret-<hex>`). No real secret bytes ever land here.
    pub env: Vec<(String, String)>,
}

impl SubstitutionHandoff {
    /// Nothing to inject — the supervisor skips writing the sidecar for a
    /// plan with no secret bindings, so consumers treat absent and empty
    /// identically.
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
    }
}

/// Sidecar path for `name`: `<vm_state_dir>/substitution.json`.
pub fn handoff_path(name: &str) -> PathBuf {
    vm_state_dir(name).join("substitution.json")
}

/// Write the handoff sidecar for `name` (mode 0600), creating the VM state
/// dir if absent. Errors propagate: a producer that can't persist the
/// placeholders must decide how to fail — it must not silently boot a
/// workload that believes its secrets are wired when they aren't.
pub fn write(name: &str, handoff: &SubstitutionHandoff) -> io::Result<()> {
    write_at(&handoff_path(name), handoff)
}

/// Read the handoff sidecar for `name`. `Ok(None)` when absent (no secrets,
/// or not yet written) — the backward-compatible default the invoke path
/// relies on to preserve its no-injected-env behavior.
pub fn read(name: &str) -> io::Result<Option<SubstitutionHandoff>> {
    read_at(&handoff_path(name))
}

fn write_at(path: &Path, handoff: &SubstitutionHandoff) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string(handoff).map_err(io::Error::from)?;
    std::fs::write(path, format!("{body}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn read_at(path: &Path) -> io::Result<Option<SubstitutionHandoff>> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let handoff = serde_json::from_str(&body).map_err(io::Error::from)?;
    Ok(Some(handoff))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SubstitutionHandoff {
        SubstitutionHandoff {
            env: vec![
                ("HTTP_PROXY".into(), "http://127.0.0.1:5254".into()),
                ("HTTPS_PROXY".into(), "http://127.0.0.1:5254".into()),
                ("OPENAI_API_KEY".into(), "mvm-secret-deadbeef".into()),
            ],
        }
    }

    #[test]
    fn roundtrip_preserves_env_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("substitution.json");
        let handoff = sample();
        write_at(&path, &handoff).unwrap();
        assert_eq!(read_at(&path).unwrap(), Some(handoff));
    }

    #[test]
    fn read_absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_at(&dir.path().join("nope.json")).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn written_file_is_private_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("substitution.json");
        write_at(&path, &sample()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_unknown_fields() {
        // A tampered or future-shaped sidecar fails closed rather than
        // silently dropping fields.
        assert!(serde_json::from_str::<SubstitutionHandoff>(r#"{"env":[],"x":1}"#).is_err());
    }

    #[test]
    fn empty_when_no_pairs() {
        assert!(SubstitutionHandoff::default().is_empty());
        assert!(!sample().is_empty());
    }
}
