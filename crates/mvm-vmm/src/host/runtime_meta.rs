//! Per-VM runtime metadata persisted to `~/.mvm/vms/<name>/mode.json`.
//!
//! Backend-agnostic. Today libkrun is the only writer (intent recording
//! for `StartMode::Attached`/`Detached`); the meta also carries the
//! `accessible` flag that gates `mvmctl console` against sealed images.
//!
//! ## File shape
//!
//! ```json
//! {"mode": "attached" | "detached", "accessible": true | false, ...}
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

use anyhow::{Context, Result, bail};
use mvm_core::vm_backend::{StartMode, VmStartConfig};
use serde::{Deserialize, Serialize};

pub use crate::host::observability_target::{
    ProcessTarget, VmObservabilityTarget, VmmTarget, VsockTarget,
};

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

    /// Absolute path to the rootfs image the VM was started from.
    ///
    /// Written at start time by every backend that calls
    /// `record_from_rootfs`. Absent in older mode.json files (reads
    /// as `None`). Used by the fs_quick checkpoint path to resolve the
    /// rootfs backend-neutrally without requiring a backend-specific
    /// supervisor config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_path: Option<String>,

    /// Version of the runtime overlay actually attached for this boot, if any.
    ///
    /// This is observational boot metadata, not a live control knob:
    /// ordinary future boots still resolve the current host-matched overlay,
    /// while lifecycle consumers that need same-version continuity
    /// (checkpoint/fork-style fresh boots) may reuse the recorded value
    /// explicitly. Running VMs never treat this field as permission to
    /// remount or hot-swap a different runtime in place.
    /// Older mode.json files and rootfs-only boots read as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_overlay_version: Option<String>,

    /// Host-side observability target for eBPF/procfs telemetry collectors.
    ///
    /// Best-effort: if the file cannot be written the VM still starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability_target: Option<VmObservabilityTarget>,
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

/// Update just the `observability_target` field of an existing metadata file.
///
/// Best-effort: logs a warning and returns `Ok(())` if the file cannot be
/// read or written. This keeps observability metadata from failing VM start.
pub fn update_observability_target(name: &str, target: &VmObservabilityTarget) -> Result<()> {
    let mut meta = match read(name)? {
        Some(m) => m,
        None => {
            tracing::warn!(vm = %name, "runtime_meta: no existing mode.json to update observability target");
            return Ok(());
        }
    };
    meta.observability_target = Some(target.clone());
    write(name, &meta)
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
        rootfs_path: None,
        runtime_overlay_version: None,
        observability_target: None,
    }
}

const SIDECAR_FILENAME: &str = "mvm-meta.json";

/// Minimal subset of the `mvm-meta.json` sidecar that runtime metadata
/// needs. The full sidecar shape lives in `mvm-build`; this crate only
/// reads the accessibility bit so it can stay below `mvm-runtime` and
/// `mvm-build` in the dependency graph.
#[derive(Debug, Clone, Deserialize)]
struct AccessibleSidecar {
    #[serde(default = "default_accessible")]
    accessible: bool,
}

/// Minimal subset of the `mvm-meta.json` sidecar needed to admit the
/// runtime-overlay contract. The full sidecar shape lives in `mvm-build`;
/// this crate only reads the overlay bits so it can stay below `mvm-runtime`
/// and `mvm-build` in the dependency graph.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverlayAwareSidecar {
    #[serde(default)]
    overlay_aware: bool,
    #[serde(default)]
    runtime_lean: bool,
}

/// Admission gate for the runtime-overlay contract.
///
/// The overlay is the single source of the guest binaries, so every boot needs
/// both an overlay-aware rootfs and a runtime-lean one: a rootfs still carrying
/// a baked agent/netinit pair could silently degrade back to it.
pub fn admit_runtime_overlay_contract(rootfs_dir: &std::path::Path) -> Result<()> {
    let path = rootfs_dir.join(SIDECAR_FILENAME);
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "refusing to start VM: rootfs at {} has no `mvm-meta.json` sidecar. \
                 The build pipeline that produced this rootfs predates the W6.2 \
                 sidecar emit, which means it also predates W1.4b runtime overlay \
                 (no `/mvm/runtime` mount point in the rootfs). Rebuild the image \
                 with current mkGuest, or drop the cached template.",
                rootfs_dir.display()
            )
        }
        Err(e) => return Err(e.into()),
    };
    let sidecar: OverlayAwareSidecar =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    if !sidecar.overlay_aware {
        bail!(
            "refusing to start VM: rootfs at {} has `overlay_aware: false` \
             in its `mvm-meta.json` sidecar. Pre-W1.4b cached templates have no \
                 `/mvm/runtime` mount point; attaching the runtime overlay disk to \
                 them would either fail or silently degrade to the baked-in agent. \
                 Rebuild the image with current mkGuest (`passthru.mvm.overlayAware = true`).",
            rootfs_dir.display()
        )
    }
    if !sidecar.runtime_lean {
        bail!(
            "refusing to start VM: rootfs at {} is marked `overlayAware: true` but \
                 not `runtimeLean: true` in its `mvm-meta.json` sidecar. Every \
                 boot must use a rootfs that intentionally omits the baked \
                 `/usr/local/bin/mvm-guest-agent` + `mvm-guest-netinit` fallback so the \
                 boot contract cannot silently degrade. Rebuild the image with the \
                 sealed/required-overlay mkGuest shape.",
            rootfs_dir.display()
        )
    }
    Ok(())
}

fn read_sidecar_accessible(rootfs_dir: &std::path::Path) -> Result<bool> {
    let path = rootfs_dir.join(SIDECAR_FILENAME);
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    let sidecar: AccessibleSidecar =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(sidecar.accessible)
}

/// Build a `VmRuntimeMeta` from the `mvm-meta.json` sidecar that the
/// build pipeline emits next to a rootfs. When the sidecar is absent or
/// unreadable, fall back to `accessible: true` to preserve backward-
/// compatible behavior for artifacts predating the sidecar. Failures only
/// surface when the sidecar exists and is malformed.
pub fn from_sidecar(mode: StartMode, rootfs_dir: &std::path::Path) -> Result<VmRuntimeMeta> {
    let accessible = read_sidecar_accessible(rootfs_dir)
        .with_context(|| format!("reading mvm-meta.json sidecar in {}", rootfs_dir.display()))?;
    Ok(VmRuntimeMeta {
        mode: mode.into(),
        accessible,
        rootfs_path: None,
        runtime_overlay_version: None,
        observability_target: None,
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
    let mut meta = from_sidecar(mode, dir)?;
    meta.rootfs_path = Some(rootfs.to_string_lossy().into_owned());
    write(name, &meta)
}

/// Preferred writer for backend start paths: captures the sidecar-derived
/// accessibility bit plus the concrete boot contract from `VmStartConfig`.
pub fn record_from_start_config(
    name: &str,
    mode: StartMode,
    start_config: &VmStartConfig,
) -> Result<()> {
    let rootfs = std::path::Path::new(&start_config.rootfs_path);
    let dir = rootfs.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut meta = from_sidecar(mode, dir)?;
    meta.rootfs_path = Some(start_config.rootfs_path.clone());
    meta.runtime_overlay_version = start_config.runtime_overlay_version.clone();
    write(name, &meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn with_home_temp<F>(f: F)
    where
        F: FnOnce(&std::path::Path),
    {
        let _guard = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        // `meta_path` resolves via `vm_state_dir`, which honors the MVM_HOME
        // override — point it at the tempdir so every path lands there, even
        // if a sibling test (under the same lock) leaked its own override.
        env.set("MVM_HOME", tmp.path());
        f(tmp.path());
    }

    #[test]
    fn round_trip_attached_accessible() {
        with_home_temp(|_home| {
            let meta = VmRuntimeMeta {
                mode: StartModeKind::Attached,
                accessible: true,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
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
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
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
            let dir = home.join("vms").join("legacy");
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
        assert!(meta.runtime_overlay_version.is_none());
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
        std::fs::write(
            tmp.path().join(SIDECAR_FILENAME),
            r#"{"accessible": false}"#,
        )
        .expect("write sidecar");
        let meta = from_sidecar(StartMode::Detached, tmp.path()).expect("ok");
        assert!(!meta.accessible);
        assert_eq!(meta.mode, StartModeKind::Detached);
    }

    #[test]
    fn from_sidecar_malformed_propagates_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(SIDECAR_FILENAME), "{not json").expect("write malformed");
        let result = from_sidecar(StartMode::Attached, tmp.path());
        assert!(result.is_err(), "malformed sidecar should error");
    }

    // ── rootfs_path field ────────────────────────────────────────────────

    /// `record_from_rootfs` stores the absolute rootfs path and round-trips it.
    #[test]
    fn rootfs_path_round_trips_via_record_from_rootfs() {
        with_home_temp(|_home| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let rootfs = tmp.path().join("rootfs.ext4");
            std::fs::write(&rootfs, b"fake").expect("write rootfs");

            record_from_rootfs("rt-rootfs-test", StartMode::Detached, &rootfs).expect("record");

            let meta = read("rt-rootfs-test")
                .expect("read ok")
                .expect("file present");
            assert_eq!(
                meta.rootfs_path.as_deref(),
                Some(rootfs.to_str().unwrap()),
                "rootfs_path must match the path passed to record_from_rootfs"
            );
        });
    }

    /// Older mode.json files that lack the `rootfs_path` field parse as `None`.
    #[test]
    fn rootfs_path_absent_in_old_file_reads_as_none() {
        with_home_temp(|home| {
            let dir = home.join("vms").join("oldvm");
            std::fs::create_dir_all(&dir).unwrap();
            // Old shape: no rootfs_path field.
            std::fs::write(
                dir.join("mode.json"),
                "{\"mode\":\"detached\",\"accessible\":false}\n",
            )
            .unwrap();
            let meta = read("oldvm").expect("read").expect("present");
            assert!(
                meta.rootfs_path.is_none(),
                "missing rootfs_path field must parse as None"
            );
        });
    }

    /// A meta with `rootfs_path: Some(...)` serializes it; `None` omits it
    /// (skip_serializing_if).
    #[test]
    fn rootfs_path_serialization_round_trip() {
        with_home_temp(|_home| {
            let with_path = VmRuntimeMeta {
                mode: StartModeKind::Detached,
                accessible: false,
                rootfs_path: Some("/abs/path/rootfs.ext4".to_string()),
                runtime_overlay_version: Some("0.17.0".to_string()),
                observability_target: None,
            };
            write("rp-with", &with_path).expect("write");
            let back = read("rp-with").expect("read").expect("present");
            assert_eq!(back.rootfs_path.as_deref(), Some("/abs/path/rootfs.ext4"));
            assert_eq!(back.runtime_overlay_version.as_deref(), Some("0.17.0"));

            let without_path = VmRuntimeMeta {
                mode: StartModeKind::Attached,
                accessible: true,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
            };
            write("rp-without", &without_path).expect("write");
            let back2 = read("rp-without").expect("read").expect("present");
            assert!(back2.rootfs_path.is_none());
            assert!(back2.runtime_overlay_version.is_none());
        });
    }

    #[test]
    fn runtime_overlay_fields_absent_in_old_file_read_as_defaults() {
        with_home_temp(|home| {
            let dir = home.join("vms").join("oldvm-runtime");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("mode.json"),
                "{\"mode\":\"detached\",\"accessible\":false,\"rootfs_path\":\"/r.ext4\"}\n",
            )
            .unwrap();
            let meta = read("oldvm-runtime").expect("read").expect("present");
            assert!(meta.runtime_overlay_version.is_none());
        });
    }

    #[test]
    fn record_from_start_config_persists_runtime_overlay_contract() {
        with_home_temp(|_home| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let rootfs = tmp.path().join("rootfs.ext4");
            std::fs::write(&rootfs, b"fake").expect("write rootfs");

            let start_config = VmStartConfig {
                name: "rt-start-config".to_string(),
                rootfs_path: rootfs.to_string_lossy().into_owned(),
                runtime_overlay_version: Some("0.17.0".to_string()),
                ..Default::default()
            };
            record_from_start_config("rt-start-config", StartMode::Detached, &start_config)
                .expect("record");

            let meta = read("rt-start-config").expect("read").expect("present");
            assert_eq!(meta.runtime_overlay_version.as_deref(), Some("0.17.0"));
            assert_eq!(meta.rootfs_path.as_deref(), Some(rootfs.to_str().unwrap()));
        });
    }

    /// Every sidecar field this module's admission gate reads has to survive
    /// the trip from `mkGuest` into `mvm-meta.json`, and one did not.
    ///
    /// `nix/lib/mk-guest.nix` sets `runtimeLean = true`, but
    /// `nix/images/default-tenant/flake.nix` serializes the sidecar from an
    /// explicit `inherit (mvm) …` list that omitted it. A dropped field is not
    /// a parse error — it takes serde's `false` default — so a rootfs carrying
    /// no baked agent at all reached the gate looking like one that might
    /// silently degrade to one, and was refused. That cost five release runs
    /// because the only place it shows up is a real boot.
    ///
    /// Reading the flake is the point: the gate and the serializer are in
    /// different languages and different repositories of truth, and nothing
    /// else makes them disagree loudly.
    #[test]
    fn the_default_tenant_sidecar_serializes_every_field_this_gate_reads() {
        // Grow this list whenever the gate above learns to read a new field.
        const READ_BY_THE_GATE: &[&str] = &["overlayAware", "runtimeLean"];

        let flake = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../nix/images/default-tenant/flake.nix");
        let body = std::fs::read_to_string(&flake)
            .unwrap_or_else(|e| panic!("reading {}: {e}", flake.display()));

        // The `inherit (mvm) … ;` block inside `sidecarJson`, which is the only
        // thing that decides what reaches the JSON.
        let start = body
            .find("sidecarJson = mvm:")
            .expect("default-tenant flake still defines sidecarJson");
        let inherit_start = body[start..]
            .find("inherit (mvm)")
            .map(|i| start + i)
            .expect("sidecarJson still serializes via `inherit (mvm)`");
        let inherit_end = body[inherit_start..]
            .find(';')
            .map(|i| inherit_start + i)
            .expect("the inherit list is terminated");
        let inherited = &body[inherit_start..inherit_end];

        for field in READ_BY_THE_GATE {
            assert!(
                inherited.split_whitespace().any(|w| w == *field),
                "`{field}` is read by the required-overlay admission gate but is not in \
                 default-tenant's sidecar `inherit (mvm)` list, so it serializes as its \
                 default and the gate sees the wrong answer. List was: {inherited}"
            );
        }
    }
}
