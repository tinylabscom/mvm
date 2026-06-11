//! Per-VM runtime metadata persisted to `~/.mvm/vms/<name>/mode.json`.
//!
//! Backend-agnostic. Today libkrun is the only writer (intent recording
//! for `StartMode::Attached`/`Detached`); the meta also carries the
//! `accessible` flag that gates `mvmctl console` against sealed images.
//!
//! ## File shape
//!
//! ```json
//! {"mode": "attached" | "detached", "accessible": true | false}
//! ```
//!
//! Older single-field shape (`{"mode": "..."}`) is parsed with
//! `accessible: true` as a backward-compat default — VMs predating the
//! accessible flag were all dev-style accessible images.
//!
//! ## Failure mode
//!
//! Writes are best-effort: a failure logs a warning and the VM start
//! proceeds. The `accessible` field is load-bearing only when the
//! console gate consults it; if the file is missing the gate defaults
//! to allow (`accessible: true`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::vm_backend::StartMode;
use serde::{Deserialize, Serialize};

/// Workspace-wide test serialization for tests that mutate `HOME`
/// (or any other process-global env var). Multiple modules across
/// `mvm` and `mvm-backend` need this; sharing one lock
/// prevents the modules' tests from racing each other when run on
/// the same `cargo test` binary. Exposed unconditionally so
/// downstream test suites can serialize against it without an
/// extra feature gate.
pub static HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runtime metadata persisted alongside a started VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRuntimeMeta {
    /// Caller's start-mode intent. Written by libkrun's
    /// `start_with_mode`; consumed by the handle registry for
    /// signal forwarding.
    pub mode: StartModeKind,

    /// Whether `mvmctl console` may attach to this VM.
    ///
    /// Mirrors `passthru.mvm.accessible` from the Nix-built image.
    /// Sealed (production) images set `false`; dev images set `true`.
    /// Older mode.json files without this field are read as `true`
    /// (VMs predating the flag were all accessible).
    #[serde(default = "default_accessible")]
    pub accessible: bool,
}

fn default_accessible() -> bool {
    true
}

/// Wire-format mirror of `StartMode` so serde can round-trip it without
/// requiring `mvm_core` to derive Serialize/Deserialize on the public
/// trait type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartModeKind {
    Attached,
    Detached,
}

impl From<StartMode> for StartModeKind {
    fn from(m: StartMode) -> Self {
        match m {
            StartMode::Attached => StartModeKind::Attached,
            StartMode::Detached => StartModeKind::Detached,
        }
    }
}

impl From<StartModeKind> for StartMode {
    fn from(m: StartModeKind) -> Self {
        match m {
            StartModeKind::Attached => StartMode::Attached,
            StartModeKind::Detached => StartMode::Detached,
        }
    }
}

fn meta_path(name: &str) -> Result<PathBuf> {
    Ok(mvm_core::config::vm_state_dir(name).join("mode.json"))
}

/// Write the metadata file.
///
/// Return contract — split deliberately so callers know what each
/// error class means:
///
/// - **`Err(...)`** is reserved for *programmer* failures: a missing
///   `$HOME`, or a `VmRuntimeMeta` shape that can't be serialized
///   (which would be a bug in the type, not the environment). These
///   always propagate so a regression is visible.
/// - **`Ok(())`** is returned on both success and *environmental*
///   failures (mkdir failed, disk full, file write blocked). These
///   log a WARN and continue — the metadata file is an advisory
///   cache that `mvmctl console` reads to enforce its accessible-vs-
///   sealed gate; a missing or stale file makes the gate default to
///   "accessible" (legacy behavior). Failure to write is therefore
///   degraded UX, not a security boundary failure.
///
/// **Security trust note**: the accessible-vs-sealed gate in
/// `mvmctl console` is the *runtime* enforcement of the no-interactive-
/// access-to-a-sealed-image claim. It depends on this file being
/// written. If you're tightening the
/// security posture in the future and want the gate to fail closed
/// when this write doesn't land, you'd flip both this function's
/// return shape and the gate's read-fail handling at the same time.
pub fn write(name: &str, meta: &VmRuntimeMeta) -> Result<()> {
    let path = meta_path(name)?;
    let body = serde_json::to_string(meta).context("serializing VmRuntimeMeta")?;

    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(error = %e, vm = %name, "runtime_meta: mkdir failed");
        return Ok(());
    }
    if let Err(e) = std::fs::write(&path, format!("{body}\n")) {
        tracing::warn!(error = %e, vm = %name, "runtime_meta: write failed");
    }
    Ok(())
}

/// Read the metadata file. Returns `Ok(None)` if the file is missing
/// (the VM was never started, or the writer skipped due to a
/// best-effort failure). Errors only on malformed JSON that has
/// neither the new nor the legacy shape.
pub fn read(name: &str) -> Result<Option<VmRuntimeMeta>> {
    let path = meta_path(name)?;
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let meta: VmRuntimeMeta =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(meta))
}

/// Convenience constructor for the common case: a VM started in
/// `mode` from an accessible (dev) image.
pub fn dev_attached(mode: StartMode) -> VmRuntimeMeta {
    VmRuntimeMeta {
        mode: mode.into(),
        accessible: true,
    }
}

/// Build a `VmRuntimeMeta` from the `mvm-meta.json` `GuestSidecar`
/// that the build pipeline emits next to a rootfs. When the sidecar
/// is absent or unreadable, fall back to `accessible: true` to
/// preserve backward-compatible behavior for artifacts predating the
/// sidecar. Failures only surface when the sidecar exists and is
/// malformed.
pub fn from_sidecar(mode: StartMode, rootfs_dir: &std::path::Path) -> Result<VmRuntimeMeta> {
    let sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(rootfs_dir)
        .with_context(|| format!("reading mvm-meta.json sidecar in {}", rootfs_dir.display()))?;
    let accessible = sidecar.map(|s| s.accessible).unwrap_or(true);
    Ok(VmRuntimeMeta {
        mode: mode.into(),
        accessible,
    })
}

/// One-call helper used by VM backend `start` paths: looks for the
/// sidecar next to `rootfs`, builds a [`VmRuntimeMeta`] (defaulting
/// to `accessible: true` if absent), and writes it to
/// `~/.mvm/vms/<name>/mode.json`.
///
/// Cross-backend: call this from any `VmBackend::start_with_mode`
/// or `VmBackend::start` impl so `mvmctl console`'s accessible-vs-
/// sealed gate works consistently regardless of which hypervisor is
/// active.
/// Errors propagate when the sidecar exists but is malformed (a
/// build pipeline bug worth surfacing); the underlying `write`
/// step is best-effort and only logs warnings.
pub fn record_from_rootfs(name: &str, mode: StartMode, rootfs: &std::path::Path) -> Result<()> {
    let dir = rootfs.parent().unwrap_or_else(|| std::path::Path::new("."));
    let meta = from_sidecar(mode, dir)?;
    write(name, &meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home_temp<F>(f: F)
    where
        F: FnOnce(&std::path::Path),
    {
        let _guard = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let prev = std::env::var_os("HOME");
        // `meta_path` resolves via `vm_state_dir`, which prefers MVM_DATA_DIR
        // over $HOME — clear it so these $HOME-rooted assertions hold even if
        // a sibling test (under the same lock) leaked the override.
        let prev_data = std::env::var_os("MVM_DATA_DIR");
        // SAFETY: tests only; HOME/MVM_DATA_DIR are process-global but the
        // HOME_TEST_LOCK serializes us with everything else that reads them.
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::remove_var("MVM_DATA_DIR");
        }
        f(tmp.path());
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_data {
                Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                None => std::env::remove_var("MVM_DATA_DIR"),
            }
        }
    }

    #[test]
    fn round_trip_attached_accessible() {
        with_home_temp(|_home| {
            let meta = VmRuntimeMeta {
                mode: StartModeKind::Attached,
                accessible: true,
            };
            write("rt-test-1", &meta).expect("write");
            let read_back = read("rt-test-1").expect("read").expect("present");
            assert_eq!(read_back, meta);
        });
    }

    #[test]
    fn round_trip_detached_sealed() {
        with_home_temp(|_home| {
            let meta = VmRuntimeMeta {
                mode: StartModeKind::Detached,
                accessible: false,
            };
            write("rt-test-2", &meta).expect("write");
            let read_back = read("rt-test-2").expect("read").expect("present");
            assert_eq!(read_back, meta);
        });
    }

    #[test]
    fn missing_file_returns_none() {
        with_home_temp(|_home| {
            assert!(read("never-started").expect("ok").is_none());
        });
    }

    #[test]
    fn legacy_shape_parses_as_accessible() {
        // Older VMs wrote only `{"mode":"attached"}`; we treat them
        // as accessible by default to preserve historical behavior.
        with_home_temp(|home| {
            let dir = home.join(".mvm").join("vms").join("legacy");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("mode.json"), "{\"mode\":\"attached\"}\n").unwrap();
            let meta = read("legacy").expect("read").expect("present");
            assert_eq!(meta.mode, StartModeKind::Attached);
            assert!(meta.accessible, "legacy default should be accessible");
        });
    }

    #[test]
    fn dev_attached_helper_is_accessible() {
        let meta = dev_attached(StartMode::Attached);
        assert_eq!(meta.mode, StartModeKind::Attached);
        assert!(meta.accessible);
    }

    #[test]
    fn from_sidecar_missing_defaults_to_accessible() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let meta = from_sidecar(StartMode::Attached, tmp.path()).expect("ok");
        assert!(
            meta.accessible,
            "missing sidecar should default to accessible"
        );
        assert_eq!(meta.mode, StartModeKind::Attached);
    }

    #[test]
    fn from_sidecar_present_uses_recorded_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "sealed-vm".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
        };
        sidecar.write_to_dir(tmp.path()).expect("write sidecar");
        let meta = from_sidecar(StartMode::Detached, tmp.path()).expect("ok");
        assert!(!meta.accessible);
        assert_eq!(meta.mode, StartModeKind::Detached);
    }

    #[test]
    fn from_sidecar_malformed_propagates_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
            "{not json",
        )
        .expect("write malformed");
        let result = from_sidecar(StartMode::Attached, tmp.path());
        assert!(result.is_err(), "malformed sidecar should error");
    }
}
