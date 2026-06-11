//! Builder-runtime backend selection.
//!
//! Picks between [`libkrun_builder::LibkrunBuilderVm`] and
//! [`vz_builder::VzBuilderVm`]. Returns `Box<dyn BuilderVm>` so
//! callers do not need to switch on the concrete type — both drivers
//! implement [`builder_vm::BuilderVm`] with byte-identical artifact
//! contracts (`finalize_flake_job` / `finalize_install_job` produce the
//! same [`builder_vm::BuilderArtifacts`] shape regardless of which
//! hypervisor booted the guest).
//!
//! ## Selection priority
//!
//! 1. **CLI flag** (`--builder <libkrun|vz>`, plumbed in by callers as
//!    a typed `Option<BuilderBackendChoice>`) — highest priority.
//! 2. **Env var** `MVM_BUILDER_BACKEND` — `vz` / `libkrun`,
//!    case-insensitive, surrounding whitespace trimmed.
//! 3. **Auto-detect** by host platform when neither override is set:
//!    macOS 26+ Apple Silicon → Vz; everywhere else → libkrun.
//!
//! An unrecognised env value (typo, removed backend) falls through to
//! auto-detect with a `tracing::warn!` so the operator sees the
//! problem without aborting the build. Empty / unset env is treated
//! the same as "no override."
//!
//! Auto-detect mirrors the runtime backend selection's Apple Container
//! tier: macOS 26+ on Apple Silicon is the deployment target Apple
//! ships first-class virtualization for, so the *builder* defaults
//! match the *runtime* default there. Older macOS and Linux contributors
//! keep libkrun as the cross-platform path they were already using.

use crate::builder_vm::{BuilderVm, BuilderVmError};
use crate::libkrun_builder::LibkrunBuilderVm;
use crate::qemu_builder::QemuBuilderVm;
use crate::vz_builder::VzBuilderVm;
use mvm_core::platform::{Platform, current};

/// Env-var name the dispatch consults. Surfaced as a constant so
/// `mvmctl doctor` can reference it without re-deriving the string.
pub const MVM_BUILDER_BACKEND_ENV: &str = "MVM_BUILDER_BACKEND";

/// `MVM_LINUX_BUILDER_VM=1` opts the host into the symmetric-builder-VM
/// rollout on Linux: replace direct-Firecracker workload execution with a
/// nested libkrun-builder-VM → Firecracker chain.
///
/// The env constant + readiness predicate + doctor probe let operators
/// validate their host ahead of the dispatch flip, and give that flip a
/// single canonical signal to consume.
///
/// Surfaced as a constant so `mvmctl doctor` can reference it
/// without re-deriving the string.
pub const MVM_LINUX_BUILDER_VM_ENV: &str = "MVM_LINUX_BUILDER_VM";

/// Recognised choices for [`MVM_BUILDER_BACKEND_ENV`]. Kept as a
/// tagged enum so a future addition (e.g. Firecracker-builder on
/// Linux) is a `match` exhaustiveness check rather than a string
/// drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderBackendChoice {
    /// libkrun-backed builder VM. Default when the env var is unset
    /// or holds a value we don't recognise.
    Libkrun,
    /// Vz-backed builder VM. Opt-in via `MVM_BUILDER_BACKEND=vz`.
    Vz,
    /// QEMU-backed builder VM (Linux dev/builder substrate). Opt-in via
    /// `MVM_BUILDER_BACKEND=qemu` / `--builder qemu`;
    /// auto-detect never picks it (the default-flip is evidence-gated).
    Qemu,
}

impl BuilderBackendChoice {
    /// Human-readable name suitable for log + error messages.
    pub fn name(self) -> &'static str {
        match self {
            BuilderBackendChoice::Libkrun => "libkrun",
            BuilderBackendChoice::Vz => "vz",
            BuilderBackendChoice::Qemu => "qemu",
        }
    }
}

/// Pure auto-detect from a single boolean: "is this host macOS 26+
/// on Apple Silicon?" Lifted out so unit tests are fully hermetic
/// — they don't have to spoof the live OS version or the
/// compile-time `cfg!(target_arch)` macro.
///
/// Decision: macOS 26+ Apple Silicon → Vz; everything else → libkrun.
/// This mirrors the runtime backend tier — Apple ships first-class
/// virtualization for that target, and the *builder* defaults match
/// the *runtime* default there.
pub fn auto_detect_default_for(is_macos_26_apple_silicon: bool) -> BuilderBackendChoice {
    if is_macos_26_apple_silicon {
        BuilderBackendChoice::Vz
    } else {
        BuilderBackendChoice::Libkrun
    }
}

/// Auto-detect using the live runtime platform + compile-time arch.
/// `has_apple_containers()` already enforces `Platform::MacOS` +
/// `is_macos_26_or_later()`; the arch check completes the "Apple
/// Silicon" half of the predicate.
pub fn auto_detect_default() -> BuilderBackendChoice {
    let is_target = current().has_apple_containers() && cfg!(target_arch = "aarch64");
    auto_detect_default_for(is_target)
}

/// Parse the env var on its own, without applying auto-detect when
/// the var is unset or empty. Returns `None` for "no override
/// present" so a caller can disambiguate "user set this to libkrun"
/// from "user set nothing."
///
/// Unrecognised values log a warning and return `None` — the caller
/// then falls through to auto-detect, matching the
/// fail-without-aborting policy.
pub fn resolve_env_override() -> Option<BuilderBackendChoice> {
    let raw = std::env::var_os(MVM_BUILDER_BACKEND_ENV)?;
    let s = raw.to_string_lossy();
    let trimmed = s.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "" => None,
        "libkrun" => Some(BuilderBackendChoice::Libkrun),
        "vz" => Some(BuilderBackendChoice::Vz),
        "qemu" => Some(BuilderBackendChoice::Qemu),
        other => {
            tracing::warn!(
                value = %other,
                "{MVM_BUILDER_BACKEND_ENV} value not recognised; falling through to auto-detect"
            );
            None
        }
    }
}

/// Apply the override priority: CLI flag > env var > auto-detect.
/// `flag` is the typed `--builder` value the CLI plumbs in (`None`
/// when the flag isn't supplied).
pub fn resolve_choice_with_override(flag: Option<BuilderBackendChoice>) -> BuilderBackendChoice {
    if let Some(c) = flag {
        return c;
    }
    if let Some(c) = resolve_env_override() {
        return c;
    }
    auto_detect_default()
}

/// Resolve the choice with no CLI flag — env var + auto-detect only.
/// Existing callers that don't yet plumb the `--builder` flag use
/// this; they migrate to `resolve_choice_with_override` once wired.
pub fn resolve_choice() -> BuilderBackendChoice {
    resolve_choice_with_override(None)
}

/// Construct the builder driver the selection resolves to. Returns
/// a boxed trait object so callers don't have to enumerate concrete
/// types at the call site.
///
/// Both drivers construct via `::default()` — neither does I/O at
/// construction time. The first I/O happens inside `run_build`
/// (image lookup, lock acquire, supervisor spawn).
pub fn resolve_builder_backend() -> Box<dyn BuilderVm> {
    resolve_builder_backend_with_override(None)
}

/// As [`resolve_builder_backend`] but accepts an explicit CLI flag
/// override at the highest priority. Used by CLI dispatch.
pub fn resolve_builder_backend_with_override(
    flag: Option<BuilderBackendChoice>,
) -> Box<dyn BuilderVm> {
    match resolve_choice_with_override(flag) {
        BuilderBackendChoice::Libkrun => Box::new(LibkrunBuilderVm::default()),
        BuilderBackendChoice::Vz => Box::new(VzBuilderVm::new()),
        BuilderBackendChoice::Qemu => Box::new(QemuBuilderVm::new()),
    }
}

/// Builder driver for the Stage 0 bootstrap.
///
/// Stage 0 is implemented for libkrun and QEMU; Vz and Firecracker
/// Stage 0 are still fail-closed gaps. So this dispatch deliberately differs
/// from [`resolve_builder_backend`]: an explicit `qemu` choice uses QEMU, but
/// everything else — including the Vz auto-detect default on macOS-26+ — falls
/// back to libkrun, preserving the long-standing "Stage 0 is libkrun even
/// on Vz-default hosts" invariant rather than hitting the Vz gap.
/// `verbose` streams the libkrun console; the QEMU path always logs to
/// `console.log`.
pub fn resolve_stage0_backend(verbose: bool) -> Box<dyn BuilderVm> {
    match resolve_choice() {
        BuilderBackendChoice::Qemu => Box::new(QemuBuilderVm::new()),
        _ => Box::new(LibkrunBuilderVm::default().with_verbose(verbose)),
    }
}

// ──────────────────────────────────────────────────────────────────
// `MVM_LINUX_BUILDER_VM` readiness gate
// ──────────────────────────────────────────────────────────────────

/// Pure predicate over an `MVM_LINUX_BUILDER_VM` env-var value.
/// Lifted out so unit tests can drive both arms without touching
/// process env. Truthy values: `1`, `true`, `yes`, `on`
/// (case-insensitive, whitespace-trimmed). Anything else (including
/// `0`, `false`, `no`, `off`, the empty string, missing) → `false`.
///
/// The "is anything but a recognised truthy false-like value false?"
/// pattern matches operators' expectations from kernel cmdline flags
/// and avoids confusing `MVM_LINUX_BUILDER_VM=disabled` accidentally
/// turning the gate on.
pub fn linux_builder_vm_requested_for(raw: Option<&str>) -> bool {
    let Some(s) = raw else {
        return false;
    };
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on",
    )
}

/// Live runtime check: is `MVM_LINUX_BUILDER_VM` set to a truthy
/// value? Consumed to decide whether the workload path nests through a
/// libkrun builder VM.
pub fn linux_builder_vm_requested() -> bool {
    let raw = std::env::var(MVM_LINUX_BUILDER_VM_ENV).ok();
    linux_builder_vm_requested_for(raw.as_deref())
}

/// Pure readiness predicate. Lifted out so unit tests can inject
/// `(platform, has_nested_kvm)` directly without spoofing the live
/// host. Returns `Ok(())` when the host is Linux with nested KVM
/// enabled; returns `Err(BuilderVmError::VmmUnavailable)` with an
/// actionable hint otherwise.
///
/// Called only when [`linux_builder_vm_requested`] is true — when
/// the env isn't set, the existing direct path stays untouched.
pub fn linux_builder_vm_readiness_for(
    plat: Platform,
    has_nested_kvm: bool,
) -> Result<(), BuilderVmError> {
    if !matches!(plat, Platform::LinuxNative) {
        return Err(BuilderVmError::VmmUnavailable {
            requested: "linux-builder-vm".into(),
            reason: format!(
                "{MVM_LINUX_BUILDER_VM_ENV} is a Linux-only opt-in (Plan 100). \
                 The current host is {plat}; unset {MVM_LINUX_BUILDER_VM_ENV} to proceed."
            ),
        });
    }
    if !has_nested_kvm {
        return Err(BuilderVmError::VmmUnavailable {
            requested: "linux-builder-vm".into(),
            reason: format!(
                "{MVM_LINUX_BUILDER_VM_ENV}=1 requires nested KVM on the host but \
                 neither /sys/module/kvm_intel/parameters/nested nor \
                 /sys/module/kvm_amd/parameters/nested reports it enabled. \
                 Enable on Intel hosts with `modprobe -r kvm_intel && modprobe kvm_intel nested=Y` \
                 (or set `options kvm_intel nested=Y` in /etc/modprobe.d/), \
                 or on AMD with `modprobe -r kvm_amd && modprobe kvm_amd nested=1`."
            ),
        });
    }
    Ok(())
}

/// Live readiness check using the runtime platform + sysfs probe.
/// `mvmctl doctor` and the future workload-nesting dispatch both call
/// this to surface clean errors before mid-build.
pub fn linux_builder_vm_readiness() -> Result<(), BuilderVmError> {
    let plat = current();
    linux_builder_vm_readiness_for(plat, plat.has_nested_kvm())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};

    /// Process-wide lock for env mutation. Same pattern the
    /// `builder_vm_timeout` tests use; serialises tests so concurrent
    /// threads don't observe each other's writes.
    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn with_env<F: FnOnce() -> R, R>(value: Option<&str>, f: F) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var_os(MVM_BUILDER_BACKEND_ENV);
        // SAFETY: tests serialise env mutation via ENV_LOCK.
        unsafe {
            match value {
                Some(v) => std::env::set_var(MVM_BUILDER_BACKEND_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_BACKEND_ENV),
            }
        }
        let result = f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var(MVM_BUILDER_BACKEND_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_BACKEND_ENV),
            }
        }
        result
    }

    // ── Auto-detect (pure, hermetic — no env / OS / arch sensitivity) ──

    #[test]
    fn auto_detect_default_for_macos_26_apple_silicon_picks_vz() {
        assert_eq!(auto_detect_default_for(true), BuilderBackendChoice::Vz);
    }

    #[test]
    fn auto_detect_default_for_everything_else_picks_libkrun() {
        // Linux, macOS Intel, macOS 13-25 Apple Silicon, Windows, WSL2 —
        // they all collapse into the same "not macOS 26 + AS" bucket,
        // which means libkrun.
        assert_eq!(
            auto_detect_default_for(false),
            BuilderBackendChoice::Libkrun
        );
    }

    // ── Env-var parsing (hermetic via ENV_LOCK + explicit values) ──

    #[test]
    fn resolve_env_override_returns_none_when_unset() {
        with_env(None, || {
            assert_eq!(resolve_env_override(), None);
        });
    }

    #[test]
    fn resolve_env_override_returns_none_for_empty_string() {
        // `MVM_BUILDER_BACKEND=` shows up in tooling that exports
        // every shell var unconditionally; treat as unset so
        // auto-detect runs.
        with_env(Some(""), || {
            assert_eq!(resolve_env_override(), None);
        });
    }

    #[test]
    fn resolve_env_override_libkrun_explicit() {
        with_env(Some("libkrun"), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Libkrun));
        });
    }

    #[test]
    fn resolve_env_override_vz_lowercase() {
        with_env(Some("vz"), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Vz));
        });
    }

    #[test]
    fn resolve_env_override_vz_uppercase() {
        // Case-insensitive matters because operators set this in
        // shell rc files and the convention varies. `Vz` is the
        // crate name; `VZ` is the entitlement string. Both should
        // work.
        with_env(Some("VZ"), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Vz));
        });
    }

    #[test]
    fn resolve_env_override_strips_whitespace() {
        with_env(Some("  vz  "), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Vz));
        });
    }

    #[test]
    fn resolve_env_override_returns_none_for_unrecognised() {
        // Typo / removed backend / accidental value: log a warning
        // and fall through to auto-detect (the caller's job).
        with_env(Some("firecracker"), || {
            assert_eq!(resolve_env_override(), None);
        });
    }

    // ── Priority: flag > env > auto-detect ──

    #[test]
    fn override_flag_beats_env_var() {
        // Flag says libkrun, env says vz → flag wins.
        with_env(Some("vz"), || {
            assert_eq!(
                resolve_choice_with_override(Some(BuilderBackendChoice::Libkrun)),
                BuilderBackendChoice::Libkrun,
            );
        });
    }

    #[test]
    fn override_flag_beats_auto_detect() {
        // No env, flag explicit → flag wins regardless of host.
        with_env(None, || {
            assert_eq!(
                resolve_choice_with_override(Some(BuilderBackendChoice::Vz)),
                BuilderBackendChoice::Vz,
            );
            assert_eq!(
                resolve_choice_with_override(Some(BuilderBackendChoice::Libkrun)),
                BuilderBackendChoice::Libkrun,
            );
        });
    }

    #[test]
    fn env_var_beats_auto_detect_when_no_flag() {
        with_env(Some("vz"), || {
            assert_eq!(resolve_choice_with_override(None), BuilderBackendChoice::Vz,);
        });
        with_env(Some("libkrun"), || {
            assert_eq!(
                resolve_choice_with_override(None),
                BuilderBackendChoice::Libkrun,
            );
        });
    }

    #[test]
    fn no_flag_no_env_falls_through_to_auto_detect() {
        // We can't assert the resulting choice without spoofing the
        // host's platform — that's covered by `auto_detect_default_for`
        // tests. Here we just pin the wiring: an unset env with no
        // flag must produce *some* choice (no panic, no crash).
        with_env(None, || {
            let _ = resolve_choice_with_override(None);
        });
    }

    // ── Naming + factory wiring ──

    #[test]
    fn backend_choice_name_round_trips() {
        assert_eq!(BuilderBackendChoice::Libkrun.name(), "libkrun");
        assert_eq!(BuilderBackendChoice::Vz.name(), "vz");
    }

    #[test]
    fn resolve_builder_backend_constructs_some_driver() {
        // The factory doesn't expose the concrete type. This test
        // pins the wiring: env override path constructs successfully
        // without panicking. The choice-mapping is covered above.
        with_env(Some("libkrun"), || {
            let _backend = resolve_builder_backend();
        });
        with_env(Some("vz"), || {
            let _backend = resolve_builder_backend();
        });
    }

    #[test]
    fn resolve_builder_backend_with_override_honours_flag() {
        with_env(Some("vz"), || {
            // Flag forces libkrun even though env says vz.
            let _backend =
                resolve_builder_backend_with_override(Some(BuilderBackendChoice::Libkrun));
        });
    }

    // ── MVM_LINUX_BUILDER_VM env predicate ──────────

    #[test]
    fn linux_builder_vm_requested_truthy_values() {
        for raw in ["1", "true", "yes", "on", "TRUE", "Yes", "On", "  1  "] {
            assert!(
                linux_builder_vm_requested_for(Some(raw)),
                "expected {raw:?} to register as truthy"
            );
        }
    }

    #[test]
    fn linux_builder_vm_requested_falsey_values() {
        for raw in [
            "0",
            "false",
            "no",
            "off",
            "FALSE",
            "No",
            "Off",
            "",
            "  ",
            "anything-else",
        ] {
            assert!(
                !linux_builder_vm_requested_for(Some(raw)),
                "expected {raw:?} to register as falsey"
            );
        }
    }

    #[test]
    fn linux_builder_vm_requested_none_is_false() {
        assert!(!linux_builder_vm_requested_for(None));
    }

    // ── readiness predicate ────────────────────────

    #[test]
    fn linux_builder_vm_readiness_ok_when_linux_native_with_nested_kvm() {
        assert!(linux_builder_vm_readiness_for(Platform::LinuxNative, true).is_ok());
    }

    #[test]
    fn linux_builder_vm_readiness_refuses_without_nested_kvm() {
        let err = linux_builder_vm_readiness_for(Platform::LinuxNative, false)
            .expect_err("nested KVM missing must refuse");
        let msg = format!("{err}");
        // Operator-actionable error names both the env-var and the
        // kernel-module fix.
        assert!(msg.contains("MVM_LINUX_BUILDER_VM"), "got: {msg}");
        assert!(
            msg.contains("kvm_intel") || msg.contains("kvm_amd"),
            "got: {msg}"
        );
        assert!(msg.contains("nested"), "got: {msg}");
    }

    #[test]
    fn linux_builder_vm_readiness_refuses_on_macos() {
        let err = linux_builder_vm_readiness_for(Platform::MacOS, true)
            .expect_err("Linux-only env on macOS must refuse");
        let msg = format!("{err}");
        assert!(msg.contains("Linux-only"), "got: {msg}");
        assert!(msg.contains("MVM_LINUX_BUILDER_VM"), "got: {msg}");
    }

    #[test]
    fn linux_builder_vm_readiness_refuses_on_wsl2() {
        // WSL2 with nested KVM still refuses — the readiness gate
        // targets LinuxNative only; WSL2 nested-KVM-builder is a future
        // backend project, out of scope here.
        let err = linux_builder_vm_readiness_for(Platform::Wsl2, true)
            .expect_err("WSL2 not Plan 100 W1 surface");
        assert!(format!("{err}").contains("Linux-only"));
    }

    #[test]
    fn linux_builder_vm_readiness_refuses_on_linux_no_kvm() {
        let err = linux_builder_vm_readiness_for(Platform::LinuxNoKvm, false)
            .expect_err("LinuxNoKvm not Plan 100 W1 surface");
        assert!(format!("{err}").contains("Linux-only"));
    }

    #[test]
    fn linux_builder_vm_env_constant_is_canonical() {
        // Pin the exact env var name so a future rename trips a
        // single visible test failure rather than a silent doctor
        // / dispatch divergence.
        assert_eq!(MVM_LINUX_BUILDER_VM_ENV, "MVM_LINUX_BUILDER_VM");
    }
}
