//! Builder-runtime backend selection.
//!
//! Picks the right [`BuilderVm`](crate::builder_vm::BuilderVm) implementation
//! for the current host. Returns `Box<dyn BuilderVm>` so callers do not need
//! to switch on the concrete type — all drivers implement the trait with
//! byte-identical artifact contracts (`finalize_flake_job` /
//! `finalize_install_job` produce the same
//! [`BuilderArtifacts`](crate::builder_vm::BuilderArtifacts) shape).
//!
//! ## Selection priority
//!
//! 1. **CLI flag** (`--builder <libkrun|hvf|qemu>`, plumbed in by
//!    callers as a typed `Option<BuilderBackendChoice>`) — highest priority.
//! 2. **Env var** `MVM_BUILDER_BACKEND` — `libkrun` / `hvf` /
//!    `qemu`, case-insensitive, surrounding whitespace trimmed.
//! 3. **Auto-detect** by host platform when neither override is set:
//!    macOS 26+ Apple Silicon → HVF builder; Linux native →
//!    QEMU builder; everywhere else → libkrun.
//!
//! An unrecognised env value (typo, removed backend) falls through to
//! auto-detect with a `tracing::warn!` so the operator sees the
//! problem without aborting the build. Empty / unset env is treated
//! the same as "no override."

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::builder_health;
use crate::builder_vm::{
    BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
};
use crate::libkrun_builder::{
    DEFAULT_VCPUS, LibkrunBuilderVm, builder_vm_cache_dir, host_arch_tag,
};
use crate::qemu_builder::QemuBuilderVm;
use mvm_core::platform::{Platform, current};

/// Resolve the optional seeded Nix store closure NAR for the live host's
/// arch, the same per-arch cache dir every libkrun/qemu builder image read
/// resolves against. `None` is the common case today (see
/// `builder_pack::closure_nar_path`'s doc); a `LibkrunBuilderVm` attaches
/// nothing and boots exactly as before this seam existed.
fn closure_nar_for_host_arch() -> Option<PathBuf> {
    crate::builder_pack::closure_nar_path(&builder_vm_cache_dir().join(host_arch_tag()))
}

/// Constructor for the hvf builder, registered by the CLI (which can name
/// `HvfBuilderVm` and resolve its image). `mvm-build` sits below
/// `mvm-backend`, so it cannot construct the hvf builder itself.
pub type HvfBuilderCtor = Box<dyn Fn() -> Result<Box<dyn BuilderVm>, BuilderVmError> + Send + Sync>;

static HVF_CTOR: OnceLock<HvfBuilderCtor> = OnceLock::new();

/// Register the hvf builder constructor (first registration wins).
pub fn register_hvf_builder(ctor: HvfBuilderCtor) {
    let _ = HVF_CTOR.set(ctor);
}

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

/// Stage 0's no-host-mkfs compatibility path builds in a tmpfs, whose default
/// capacity is half of guest RAM. The builder image closure plus its final
/// rootfs copy exceeds the steady-state builder's 8 GiB tmpfs, so Stage 0 gets
/// a larger one-shot memory budget while ordinary builder jobs retain their
/// existing resource profile.
const LIBKRUN_STAGE0_MEMORY_MIB: u32 = 24 * 1024;

/// Recognised choices for [`MVM_BUILDER_BACKEND_ENV`]. Kept as a
/// tagged enum so a future addition (e.g. Firecracker-builder on
/// Linux) is a `match` exhaustiveness check rather than a string
/// drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderBackendChoice {
    /// libkrun-backed builder VM. Default when the env var is unset
    /// or holds a value we don't recognise.
    Libkrun,
    /// QEMU-backed builder VM (Linux dev/builder substrate). Opt-in via
    /// `MVM_BUILDER_BACKEND=qemu` / `--builder qemu`;
    /// auto-detect never picks it (the default-flip is evidence-gated).
    Qemu,
    /// HVF builder VM (the destination macOS backend). The
    /// auto-detected default on macOS-26 Apple Silicon; opt-in elsewhere via
    /// `MVM_BUILDER_BACKEND=hvf` / `--builder hvf`.
    Hvf,
    /// Browser-hosted WebLinux builder VM. Native hosts never auto-detect
    /// this; it is parsed only for catalog/help parity and fails closed if
    /// a native build tries to resolve it.
    WebLinux,
}

impl BuilderBackendChoice {
    /// Human-readable name suitable for log + error messages.
    pub fn name(self) -> &'static str {
        match self {
            BuilderBackendChoice::Libkrun => "libkrun",
            BuilderBackendChoice::Qemu => "qemu",
            BuilderBackendChoice::Hvf => "hvf",
            BuilderBackendChoice::WebLinux => "web-linux",
        }
    }
}

/// Pure auto-detect from the platform and a single boolean:
/// "is this host macOS 26+ on Apple Silicon?" Lifted out so unit tests are
/// fully hermetic — they don't have to spoof the live OS version or the
/// compile-time `cfg!(target_arch)` macro.
///
/// Decision:
/// - macOS 26+ Apple Silicon → HVF builder
/// - Linux native → QEMU builder
/// - everything else → libkrun
pub fn auto_detect_default_for(
    plat: Platform,
    is_macos_26_apple_silicon: bool,
) -> BuilderBackendChoice {
    if is_macos_26_apple_silicon {
        BuilderBackendChoice::Hvf
    } else if matches!(plat, Platform::LinuxNative) {
        BuilderBackendChoice::Qemu
    } else {
        BuilderBackendChoice::Libkrun
    }
}

/// Auto-detect using the live runtime platform + compile-time arch.
/// `is_hvf_default_tier()` already enforces `Platform::MacOS` +
/// `is_macos_26_or_later()`; the arch check completes the "Apple
/// Silicon" half of the predicate.
pub fn auto_detect_default() -> BuilderBackendChoice {
    let is_target = current().is_hvf_default_tier() && cfg!(target_arch = "aarch64");
    auto_detect_default_for(current(), is_target)
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
        "qemu" => Some(BuilderBackendChoice::Qemu),
        "hvf" => Some(BuilderBackendChoice::Hvf),
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

/// Browser-only builder stub. The WebLinux builder runs inside a browser
/// Worker and has no native implementation; resolving it on a native host
/// yields a builder whose operations fail closed rather than silently
/// falling back to a different backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct WebLinuxBuilderVm;

impl BuilderVm for WebLinuxBuilderVm {
    fn run_build(
        &self,
        _job: &BuilderJob,
        _mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        Err(BuilderVmError::VmmUnavailable {
            requested: "web-linux".to_string(),
            reason: "the web-linux builder is browser-only; run it in a WebAssembly browser environment, or select libkrun/qemu/hvf on a native host".to_string(),
        })
    }

    fn run_stage0(
        &self,
        _guest_root_dir: &Path,
        _entry_path: &str,
        _workspace_dir: &Path,
        _artifact_out: &Path,
        _host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        Err(BuilderVmError::VmmUnavailable {
            requested: "stage0-bootstrap".to_string(),
            reason: "the web-linux builder is browser-only and cannot bootstrap a \
                     builder VM; select libkrun or qemu on a native host"
                .to_string(),
        })
    }

    fn capabilities(&self) -> BuilderCapabilities {
        BuilderCapabilities::default()
    }
}

/// What each builder backend can do, readable without constructing one.
///
/// Constructing a backend can do real work — the hvf builder materializes the
/// embedded Linux host binaries — so a pre-flight question ("can this host
/// bootstrap?") must not require it. Asking through construction made `doctor`
/// report hvf as *unavailable* on a machine where hvf was the working default,
/// because the answer it got back was about a missing build payload rather than
/// about capability.
///
/// `declared_capabilities_match_the_backend_impls` holds this in step with the
/// `BuilderVm::capabilities` each backend returns, so the convenience copy
/// cannot drift from the source of truth.
#[must_use]
pub fn declared_capabilities(choice: BuilderBackendChoice) -> BuilderCapabilities {
    match choice {
        BuilderBackendChoice::Libkrun | BuilderBackendChoice::Qemu => BuilderCapabilities {
            stage0_bootstrap: true,
            dependency_install: true,
        },
        BuilderBackendChoice::Hvf | BuilderBackendChoice::WebLinux => {
            BuilderCapabilities::default()
        }
    }
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
///
/// Returns the concrete builder for all backends except `Hvf`, which
/// requires a registered constructor. Callers that may receive `Hvf`
/// should use [`try_resolve_builder_backend_with_override`] instead.
pub fn resolve_builder_backend_with_override(
    flag: Option<BuilderBackendChoice>,
) -> Box<dyn BuilderVm> {
    match resolve_choice_with_override(flag) {
        BuilderBackendChoice::Libkrun => {
            Box::new(LibkrunBuilderVm::default().with_closure_nar(closure_nar_for_host_arch()))
        }
        BuilderBackendChoice::Qemu => Box::new(QemuBuilderVm::new()),
        BuilderBackendChoice::Hvf => {
            // Delegate to the registered constructor; panic if not registered
            // (only reachable when the CLI has not called register_hvf_builder,
            // which is a programming error at startup).
            HVF_CTOR.get().expect(
                "hvf builder constructor not registered — \
                     call register_hvf_builder at CLI startup before \
                     resolving an Hvf backend via the infallible path",
            )()
            .expect("registered hvf builder constructor failed")
        }
        BuilderBackendChoice::WebLinux => Box::new(WebLinuxBuilderVm),
    }
}

/// As [`resolve_builder_backend_with_override`] but fallible — the hvf arm
/// depends on a registered constructor.
pub fn try_resolve_builder_backend_with_override(
    flag: Option<BuilderBackendChoice>,
) -> Result<Box<dyn BuilderVm>, BuilderVmError> {
    match resolve_choice_with_override(flag) {
        BuilderBackendChoice::Libkrun => Ok(Box::new(
            LibkrunBuilderVm::default().with_closure_nar(closure_nar_for_host_arch()),
        )),
        BuilderBackendChoice::Qemu => Ok(Box::new(QemuBuilderVm::new())),
        BuilderBackendChoice::Hvf => match HVF_CTOR.get() {
            Some(ctor) => ctor(),
            None => Err(BuilderVmError::VmmUnavailable {
                requested: "hvf".into(),
                reason: "hvf builder constructor not registered (CLI startup did not run)".into(),
            }),
        },
        BuilderBackendChoice::WebLinux => Ok(Box::new(WebLinuxBuilderVm)),
    }
}

/// Builder driver for the Stage 0 bootstrap.
///
/// Stage 0 is implemented for libkrun and QEMU; hvf and Firecracker
/// Stage 0 are still fail-closed gaps. So this dispatch deliberately differs
/// from [`resolve_builder_backend`]: an explicit `qemu` choice uses QEMU, but
/// everything else — including the hvf auto-detect default on macOS-26+ —
/// falls back to libkrun, preserving the "Stage 0 is libkrun even on
/// hvf-default hosts" invariant rather than hitting the gap.
/// `verbose` streams the libkrun console; the QEMU path always logs to
/// `console.log`.
pub fn resolve_stage0_backend(verbose: bool) -> Box<dyn BuilderVm> {
    resolve_stage0_backend_for_choice(resolve_choice(), verbose)
}

/// Stage 0 driver for an explicit `choice` — used by the auto-fallback loop to
/// construct the next backend to try. QEMU when chosen; libkrun for everything
/// else. HVF Stage 0 remains a gap, so even the macOS auto-detect path lowers
/// to libkrun here; Linux auto libkrun stays libkrun-only and never silently
/// redirects onto qemu.
pub fn resolve_stage0_backend_for_choice(
    choice: BuilderBackendChoice,
    verbose: bool,
) -> Box<dyn BuilderVm> {
    match stage0_backend_choice(choice) {
        BuilderBackendChoice::Qemu => Box::new(QemuBuilderVm::new()),
        BuilderBackendChoice::Libkrun | BuilderBackendChoice::Hvf => {
            Box::new(libkrun_stage0_backend(verbose))
        }
        BuilderBackendChoice::WebLinux => Box::new(WebLinuxBuilderVm),
    }
}

fn libkrun_stage0_backend(verbose: bool) -> LibkrunBuilderVm {
    LibkrunBuilderVm::default()
        .with_resources(DEFAULT_VCPUS, LIBKRUN_STAGE0_MEMORY_MIB)
        .with_verbose(verbose)
        .with_closure_nar(closure_nar_for_host_arch())
}

/// Stage 0 currently has only two concrete driver targets: explicit qemu stays
/// qemu; every other selection lowers to libkrun until an hvf-specific Stage 0
/// implementation exists.
fn stage0_backend_choice(choice: BuilderBackendChoice) -> BuilderBackendChoice {
    match choice {
        BuilderBackendChoice::Qemu => BuilderBackendChoice::Qemu,
        BuilderBackendChoice::Libkrun | BuilderBackendChoice::Hvf => BuilderBackendChoice::Libkrun,
        // WebLinux has no native Stage 0; the resolved WebLinuxBuilderVm fails
        // closed when its run_stage0 is invoked.
        BuilderBackendChoice::WebLinux => BuilderBackendChoice::WebLinux,
    }
}

// ──────────────────────────────────────────────────────────────────
// Auto-fallback between builder backends on a VMM-level failure
// ──────────────────────────────────────────────────────────────────

/// Is `e` a VMM-level failure — this backend could not run the job at all —
/// rather than a genuine build error a different backend would hit
/// identically? Only these justify an auto-fallback: a real `NixBuildFailed`
/// (the build ran and failed) or a `DegradedBuilderStore` (shared Nix store)
/// must surface unchanged.
///
/// `VmmUnavailable` counts, and did not until a backend that declined an
/// operation outright was found to dead-end the auto-detected path. On macOS
/// the default builder is hvf, which serves ordinary build jobs but wires
/// neither Stage 0 nor the dependency install; libkrun wires both. Because the
/// refusal was not in this set, `deps install` stopped at "hvf does not serve
/// dependency installs" and never tried the backend that does — a fallback
/// declining to fall back, for a failure that is precisely what it exists for.
///
/// This cannot override an operator: an explicit `--builder` /
/// `MVM_BUILDER_BACKEND` makes [`builder_attempt_order`] return a single
/// element, so there is no next backend to move to whatever this returns.
///
/// [`BuilderVmError::NotYetImplemented`] is deliberately excluded.
/// `VmmUnavailable` says *not on this host*, which another backend may well
/// answer; `NotYetImplemented` says *nowhere yet*, and retrying it elsewhere
/// only trades one unimplemented path for another while making the eventual
/// error name the wrong backend.
pub fn is_builder_vm_level_failure(e: &BuilderVmError) -> bool {
    matches!(
        e,
        BuilderVmError::SupervisorExited { .. }
            | BuilderVmError::LibkrunUnavailable(_)
            | BuilderVmError::HvfVmmFailed { .. }
            | BuilderVmError::VmmUnavailable { .. }
    )
}

/// Is the live host Linux-with-KVM?
///
/// Kept as a small seam for tests and future Linux-specific selection policy.
fn is_linux_native_host() -> bool {
    matches!(current(), Platform::LinuxNative)
}

/// Backends to try, in order, for a builder job. Pure (the `is_linux_native`
/// input is injected) so the policy is unit-testable without spoofing the host.
///
/// - An **explicit** choice (CLI flag / `MVM_BUILDER_BACKEND`) is honoured with
///   no fallback — the operator asked for that backend specifically.
/// - Auto-detected **hvf** falls back to **libkrun** on macOS.
/// - Auto-detected **libkrun on Linux** no longer falls back to **qemu**.
///   The qemu builder uses user-mode networking (`-netdev user`) and is not a
///   valid substitute for the production vsock-only builder/runtime story.
///   Keep qemu as an explicit dev/test tier only (`--builder qemu` /
///   `MVM_BUILDER_BACKEND=qemu`), never a silent production escape hatch.
pub fn builder_attempt_order(
    selected: BuilderBackendChoice,
    explicit: bool,
    is_linux_native: bool,
    libkrun_unhealthy: bool,
) -> Vec<BuilderBackendChoice> {
    if explicit {
        return vec![selected];
    }
    match selected {
        BuilderBackendChoice::Hvf => vec![BuilderBackendChoice::Hvf, BuilderBackendChoice::Libkrun],
        BuilderBackendChoice::Libkrun if is_linux_native && libkrun_unhealthy => {
            vec![BuilderBackendChoice::Libkrun]
        }
        _ => vec![selected],
    }
}

/// Run `attempt` over [`builder_attempt_order`], retrying the next backend when
/// an earlier one fails with a [VMM-level error](is_builder_vm_level_failure).
/// A genuine build error (or the last backend's error) surfaces unchanged.
///
/// Centralizes the builder fallback policy so every builder-invocation site —
/// `run_build`, `run_shell_script` materialization, etc. — shares one
/// decision. `selected` is the resolved choice; `explicit` is whether it was
/// forced (CLI flag / env), which disables the fallback.
pub fn run_with_builder_fallback<T>(
    selected: BuilderBackendChoice,
    explicit: bool,
    mut attempt: impl FnMut(BuilderBackendChoice) -> Result<T, BuilderVmError>,
) -> Result<T, BuilderVmError> {
    let order = builder_attempt_order(
        selected,
        explicit,
        is_linux_native_host(),
        builder_health::libkrun_marked_unavailable(),
    );
    let last_idx = order.len() - 1;
    let mut last_err: Option<BuilderVmError> = None;
    for (idx, choice) in order.iter().copied().enumerate() {
        match attempt(choice) {
            Ok(value) => {
                builder_health::note_attempt_outcome(choice, true);
                return Ok(value);
            }
            // Not the last backend, and a VMM-level failure → try the next.
            Err(e) if idx < last_idx && is_builder_vm_level_failure(&e) => {
                builder_health::note_attempt_outcome(choice, false);
                tracing::warn!(
                    error = %e,
                    from = choice.name(),
                    to = order[idx + 1].name(),
                    "the {} builder VM could not run the build (VMM-level failure); \
                     falling back to the {} builder \
                     (re-run with `--builder {}` to disable the fallback)",
                    choice.name(),
                    order[idx + 1].name(),
                    choice.name(),
                );
                last_err = Some(e);
            }
            // Last backend, or a genuine build error → surface it unchanged.
            // Still record a VMM-level libkrun failure so a doomed sole-backend
            // libkrun isn't re-attempted next time; a build error is left alone.
            Err(e) => {
                if is_builder_vm_level_failure(&e) {
                    builder_health::note_attempt_outcome(choice, false);
                }
                return Err(e);
            }
        }
    }
    Err(last_err.expect("builder_attempt_order is never empty"))
}

/// True when `e`'s anyhow chain carries a [VMM-level
/// `BuilderVmError`](is_builder_vm_level_failure). The error must be preserved
/// in the chain (`anyhow::Error::new(e)` / `.context(...)`), not stringified.
fn anyhow_has_builder_vm_level_failure(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<BuilderVmError>()
            .is_some_and(is_builder_vm_level_failure)
    })
}

/// Like [`run_with_builder_fallback`] but for call sites whose `attempt`
/// returns `anyhow::Result<T>` (the `BuilderVmError` is wrapped in an anyhow
/// chain — e.g. the `dev_build` flake path). The fallback fires only when that
/// chain contains a VMM-level `BuilderVmError`; a genuine build error (or a
/// stringified one) surfaces unchanged with no retry.
pub fn run_with_builder_fallback_anyhow<T>(
    selected: BuilderBackendChoice,
    explicit: bool,
    mut attempt: impl FnMut(BuilderBackendChoice) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let order = builder_attempt_order(
        selected,
        explicit,
        is_linux_native_host(),
        builder_health::libkrun_marked_unavailable(),
    );
    let last_idx = order.len() - 1;
    let mut last_err: Option<anyhow::Error> = None;
    for (idx, choice) in order.iter().copied().enumerate() {
        match attempt(choice) {
            Ok(value) => {
                builder_health::note_attempt_outcome(choice, true);
                return Ok(value);
            }
            Err(e) if idx < last_idx && anyhow_has_builder_vm_level_failure(&e) => {
                builder_health::note_attempt_outcome(choice, false);
                tracing::warn!(
                    error = %e,
                    from = choice.name(),
                    to = order[idx + 1].name(),
                    "the {} builder VM could not run the build (VMM-level failure); \
                     falling back to the {} builder \
                     (re-run with `--builder {}` to disable the fallback)",
                    choice.name(),
                    order[idx + 1].name(),
                    choice.name(),
                );
                last_err = Some(e);
            }
            Err(e) => {
                if anyhow_has_builder_vm_level_failure(&e) {
                    builder_health::note_attempt_outcome(choice, false);
                }
                return Err(e);
            }
        }
    }
    Err(last_err.expect("builder_attempt_order is never empty"))
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
    /// A backend declining an operation is a reason to try the next one.
    ///
    /// The regression this pins: hvf declines the dependency install, libkrun
    /// serves it, and the auto-detected macOS order is exactly
    /// `[hvf, libkrun]` — yet the refusal was not classified as VMM-level, so
    /// the fallback stopped on the backend that could not do the job.
    #[test]
    fn a_backend_declining_an_operation_is_a_vmm_level_failure() {
        assert!(is_builder_vm_level_failure(
            &BuilderVmError::VmmUnavailable {
                requested: "hvf-dependency-install".to_string(),
                reason: "the hvf builder does not serve dependency installs".to_string(),
            }
        ));
    }

    /// "Nowhere yet" is not a reason to try somewhere else.
    #[test]
    fn a_globally_unimplemented_path_does_not_trigger_the_fallback() {
        assert!(!is_builder_vm_level_failure(
            &BuilderVmError::NotYetImplemented
        ));
    }

    /// An operator who names a backend gets that backend, including its
    /// refusals. The widened predicate must not reach past an explicit choice.
    #[test]
    fn an_explicit_choice_has_no_next_backend_whatever_the_predicate_says() {
        for choice in [
            BuilderBackendChoice::Hvf,
            BuilderBackendChoice::Libkrun,
            BuilderBackendChoice::Qemu,
            BuilderBackendChoice::WebLinux,
        ] {
            assert_eq!(
                builder_attempt_order(choice, /* explicit */ true, false, false),
                vec![choice],
                "an explicit --builder must never fall back"
            );
        }
    }

    /// The convenience copy and the trait impls must agree, or the table
    /// `doctor` prints is a decoration a reader would be wrong to trust.
    ///
    /// Covers the backends that construct without I/O. The hvf backend is
    /// asserted the same way in `mvm-runtime`, next to its impl.
    #[test]
    fn declared_capabilities_match_the_backend_impls() {
        assert_eq!(
            LibkrunBuilderVm::default().capabilities(),
            declared_capabilities(BuilderBackendChoice::Libkrun)
        );
        assert_eq!(
            QemuBuilderVm::new().capabilities(),
            declared_capabilities(BuilderBackendChoice::Qemu)
        );
        assert_eq!(
            WebLinuxBuilderVm.capabilities(),
            declared_capabilities(BuilderBackendChoice::WebLinux)
        );
    }

    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn with_env<F: FnOnce() -> R, R>(value: Option<&str>, f: F) -> R {
        // `TestEnv` serializes env-mutating tests behind a shared lock and
        // restores MVM_BUILDER_BACKEND_ENV on drop (after `f` returns).
        let mut env = TestEnv::new();
        match value {
            Some(v) => env.set(MVM_BUILDER_BACKEND_ENV, v),
            None => env.remove(MVM_BUILDER_BACKEND_ENV),
        }
        f()
    }

    // ── Auto-detect (pure, hermetic — no env / OS / arch sensitivity) ──

    #[test]
    fn auto_detect_default_for_macos_26_apple_silicon_picks_hvf() {
        assert_eq!(
            auto_detect_default_for(Platform::MacOS, true),
            BuilderBackendChoice::Hvf
        );
    }

    #[test]
    fn auto_detect_default_for_linux_native_picks_qemu() {
        assert_eq!(
            auto_detect_default_for(Platform::LinuxNative, false),
            BuilderBackendChoice::Qemu
        );
    }

    #[test]
    fn auto_detect_default_for_non_linux_non_hvf_hosts_picks_libkrun() {
        // macOS Intel, macOS 13-25 Apple Silicon, Windows, WSL2 — they all
        // collapse into the same "not macOS 26 + AS, not Linux native" bucket,
        // which means libkrun.
        assert_eq!(
            auto_detect_default_for(Platform::MacOS, false),
            BuilderBackendChoice::Libkrun
        );
        assert_eq!(
            auto_detect_default_for(Platform::Wsl2, false),
            BuilderBackendChoice::Libkrun
        );
        assert_eq!(
            auto_detect_default_for(Platform::LinuxNoKvm, false),
            BuilderBackendChoice::Libkrun
        );
    }

    // ── Env-var parsing (hermetic via the shared TestEnv guard + explicit values) ──

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
    fn resolve_env_override_strips_whitespace() {
        with_env(Some("  libkrun  "), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Libkrun));
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

    #[test]
    fn resolve_env_override_web_linux_falls_through_to_auto_detect() {
        // WebLinux is browser-only; a native env override must not
        // select it silently.
        with_env(Some("web-linux"), || {
            assert_eq!(resolve_env_override(), None);
        });
    }

    // ── Priority: flag > env > auto-detect ──

    #[test]
    fn override_flag_beats_env_var() {
        // Flag says libkrun, env says qemu → flag wins.
        with_env(Some("qemu"), || {
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
                resolve_choice_with_override(Some(BuilderBackendChoice::Qemu)),
                BuilderBackendChoice::Qemu,
            );
            assert_eq!(
                resolve_choice_with_override(Some(BuilderBackendChoice::Libkrun)),
                BuilderBackendChoice::Libkrun,
            );
        });
    }

    #[test]
    fn env_var_beats_auto_detect_when_no_flag() {
        with_env(Some("qemu"), || {
            assert_eq!(
                resolve_choice_with_override(None),
                BuilderBackendChoice::Qemu,
            );
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
        assert_eq!(BuilderBackendChoice::Qemu.name(), "qemu");
        assert_eq!(BuilderBackendChoice::WebLinux.name(), "web-linux");
    }

    #[test]
    fn closure_nar_for_host_arch_is_none_when_the_arch_cache_dir_has_no_closure() {
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        assert_eq!(closure_nar_for_host_arch(), None);
    }

    #[test]
    fn closure_nar_for_host_arch_resolves_when_the_arch_cache_dir_has_one() {
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let arch_dir = builder_vm_cache_dir().join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        std::fs::write(arch_dir.join("nix-closure.nar"), b"nar-bytes").unwrap();
        assert_eq!(
            closure_nar_for_host_arch(),
            Some(arch_dir.join("nix-closure.nar"))
        );
    }

    #[test]
    fn resolve_builder_backend_constructs_some_driver() {
        // The factory doesn't expose the concrete type. This test
        // pins the wiring: env override path constructs successfully
        // without panicking. The choice-mapping is covered above.
        with_env(Some("libkrun"), || {
            let _backend = resolve_builder_backend();
        });
        with_env(Some("qemu"), || {
            let _backend = resolve_builder_backend();
        });
    }

    #[test]
    fn resolve_builder_backend_with_override_honours_flag() {
        with_env(Some("not-a-backend"), || {
            // Flag forces libkrun even though env names an unknown backend.
            let _backend =
                resolve_builder_backend_with_override(Some(BuilderBackendChoice::Libkrun));
        });
    }

    // ── Auto-fallback policy (pure) ──────────────────────────────

    #[test]
    fn vmm_level_failures_trigger_fallback_build_errors_do_not() {
        // Supervisor died / VMM unavailable → try another backend.
        assert!(is_builder_vm_level_failure(
            &BuilderVmError::SupervisorExited {
                exit_code: 1,
                vm_state_dir: "/x".into(),
            }
        ));
        assert!(is_builder_vm_level_failure(
            &BuilderVmError::LibkrunUnavailable("no lib".into())
        ));
        // A real build error (the build ran and failed) must surface unchanged.
        assert!(!is_builder_vm_level_failure(
            &BuilderVmError::NixBuildFailed("guest cmd.sh exited 1".into())
        ));
        assert!(!is_builder_vm_level_failure(
            &BuilderVmError::DegradedBuilderStore {
                cache_dir: "/c".into(),
                log_path: "/l".into(),
                detail: "dangling".into(),
            }
        ));
    }

    #[test]
    fn attempt_order_linux_libkrun_never_silently_falls_back_to_qemu() {
        use BuilderBackendChoice::*;
        // Auto-detected libkrun on Linux stays libkrun-only. Qemu remains an
        // explicit opt-in backend.
        assert_eq!(
            builder_attempt_order(Libkrun, false, true, false),
            vec![Libkrun]
        );
        // Explicit libkrun → no fallback (operator asked for libkrun).
        assert_eq!(
            builder_attempt_order(Libkrun, true, true, false),
            vec![Libkrun]
        );
        // libkrun off-Linux (e.g. macOS 13-25) → no qemu fallback.
        assert_eq!(
            builder_attempt_order(Libkrun, false, false, false),
            vec![Libkrun]
        );
    }

    #[test]
    fn attempt_order_keeps_libkrun_even_when_marked_unhealthy_on_linux_auto() {
        use BuilderBackendChoice::*;
        // The marker remains advisory/diagnostic only now that qemu is no
        // longer an automatic fallback target.
        assert_eq!(
            builder_attempt_order(Libkrun, false, true, true),
            vec![Libkrun]
        );
        // Explicit libkrun ignores the marker — the operator forced it, so we
        // re-attempt (and a success would clear the marker).
        assert_eq!(
            builder_attempt_order(Libkrun, true, true, true),
            vec![Libkrun]
        );
        // Off-Linux libkrun ignores the marker (there is no qemu fallback there
        // to redirect to).
        assert_eq!(
            builder_attempt_order(Libkrun, false, false, true),
            vec![Libkrun]
        );
    }

    #[test]
    fn attempt_order_preserves_hvf_to_libkrun_and_explicit_qemu() {
        use BuilderBackendChoice::*;
        // macOS auto-detect: hvf → libkrun (the libkrun marker never reorders
        // this macOS path).
        assert_eq!(
            builder_attempt_order(Hvf, false, false, false),
            vec![Hvf, Libkrun]
        );
        assert_eq!(
            builder_attempt_order(Hvf, false, false, true),
            vec![Hvf, Libkrun]
        );
        assert_eq!(builder_attempt_order(Hvf, true, false, false), vec![Hvf]);
        // Explicit qemu is a single attempt.
        assert_eq!(builder_attempt_order(Qemu, false, true, false), vec![Qemu]);
    }

    #[test]
    fn stage0_choice_keeps_hvf_lowered_to_libkrun_and_qemu_explicit() {
        use BuilderBackendChoice::*;
        assert_eq!(stage0_backend_choice(Hvf), Libkrun);
        assert_eq!(stage0_backend_choice(Libkrun), Libkrun);
        assert_eq!(stage0_backend_choice(Qemu), Qemu);
    }

    #[test]
    fn libkrun_stage0_has_capacity_for_the_tmpfs_compatibility_path() {
        let backend = libkrun_stage0_backend(false);
        assert_eq!(backend.vcpus, DEFAULT_VCPUS);
        assert_eq!(backend.memory_mib, LIBKRUN_STAGE0_MEMORY_MIB);
        assert_eq!(backend.memory_mib, 24 * 1024);
    }

    #[test]
    fn run_with_fallback_surfaces_linux_libkrun_vmm_failures_without_qemu_retry() {
        use std::cell::RefCell;
        // Isolate the per-host builder-health marker the fallback now reads and
        // writes (a libkrun VMM failure records it) so it can't leak across tests.
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let calls = RefCell::new(Vec::new());
        let result: Result<(), _> =
            run_with_builder_fallback(BuilderBackendChoice::Libkrun, false, |c| {
                calls.borrow_mut().push(c);
                Err(BuilderVmError::SupervisorExited {
                    exit_code: 1,
                    vm_state_dir: "/x".into(),
                })
            });
        assert!(matches!(
            result,
            Err(BuilderVmError::SupervisorExited { .. })
        ));
        assert_eq!(*calls.borrow(), vec![BuilderBackendChoice::Libkrun]);
    }

    #[test]
    fn run_with_fallback_surfaces_real_build_errors_without_retry() {
        use std::cell::RefCell;
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let calls = RefCell::new(0u32);
        // A genuine build error must NOT trigger a fallback, even on Linux.
        let result: Result<(), _> =
            run_with_builder_fallback(BuilderBackendChoice::Libkrun, false, |_c| {
                *calls.borrow_mut() += 1;
                Err(BuilderVmError::NixBuildFailed("flake is broken".into()))
            });
        assert!(matches!(result, Err(BuilderVmError::NixBuildFailed(_))));
        // Exactly one attempt — no qemu retry for a real build failure.
        assert_eq!(*calls.borrow(), 1);
    }

    // ── anyhow-wrapped fallback (dev_build flake path) ───────────

    #[test]
    fn anyhow_chain_detects_wrapped_vmm_failure_only() {
        // A preserved (downcastable) SupervisorExited → VMM-level.
        let wrapped = anyhow::Error::new(BuilderVmError::SupervisorExited {
            exit_code: 1,
            vm_state_dir: "/x".into(),
        })
        .context("builder VM");
        assert!(anyhow_has_builder_vm_level_failure(&wrapped));
        // A real build error wrapped the same way → not VMM-level.
        let build = anyhow::Error::new(BuilderVmError::NixBuildFailed("broken".into()))
            .context("builder VM");
        assert!(!anyhow_has_builder_vm_level_failure(&build));
        // A *stringified* error (BuilderVmError lost) → not detectable, no retry.
        let stringified = anyhow::anyhow!("builder VM: supervisor exited with non-zero status (1)");
        assert!(!anyhow_has_builder_vm_level_failure(&stringified));
    }

    #[test]
    fn run_with_fallback_anyhow_surfaces_linux_libkrun_vmm_failures_without_qemu_retry() {
        use std::cell::RefCell;
        // Isolate the per-host builder-health marker (see the typed sibling test).
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let calls = RefCell::new(Vec::new());
        let result: anyhow::Result<()> =
            run_with_builder_fallback_anyhow(BuilderBackendChoice::Libkrun, false, |c| {
                calls.borrow_mut().push(c);
                Err(anyhow::Error::new(BuilderVmError::SupervisorExited {
                    exit_code: 1,
                    vm_state_dir: "/x".into(),
                })
                .context("builder VM"))
            });
        assert!(result.is_err());
        assert_eq!(*calls.borrow(), vec![BuilderBackendChoice::Libkrun]);
    }

    #[test]
    fn run_with_fallback_anyhow_surfaces_real_build_error_without_retry() {
        use std::cell::RefCell;
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let calls = RefCell::new(0u32);
        let result: anyhow::Result<()> =
            run_with_builder_fallback_anyhow(BuilderBackendChoice::Libkrun, false, |_c| {
                *calls.borrow_mut() += 1;
                Err(
                    anyhow::Error::new(BuilderVmError::NixBuildFailed("broken flake".into()))
                        .context("builder VM"),
                )
            });
        assert!(result.is_err());
        assert_eq!(*calls.borrow(), 1);
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

    // ── Hvf variant ──────────────────────────────────────────

    #[test]
    fn resolve_env_override_hvf() {
        with_env(Some("hvf"), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Hvf));
        });
    }

    #[test]
    fn resolve_env_override_hvf_case_insensitive_trimmed() {
        with_env(Some("  Hvf  "), || {
            assert_eq!(resolve_env_override(), Some(BuilderBackendChoice::Hvf));
        });
    }

    #[test]
    fn backend_choice_name_hvf() {
        assert_eq!(BuilderBackendChoice::Hvf.name(), "hvf");
    }

    // ── Hvf attempt order ─────────────────────────────────────

    #[test]
    fn attempt_order_hvf_auto_falls_back_to_libkrun() {
        use BuilderBackendChoice::*;
        assert_eq!(
            builder_attempt_order(Hvf, false, false, false),
            vec![Hvf, Libkrun]
        );
        assert_eq!(
            builder_attempt_order(Hvf, false, true, false),
            vec![Hvf, Libkrun]
        );
        // Explicit → single attempt, no fallback.
        assert_eq!(builder_attempt_order(Hvf, true, false, false), vec![Hvf]);
    }

    #[test]
    fn hvf_boot_failure_is_vmm_level_so_fallback_fires() {
        // The variant HvfBuilderVm::run_build returns for a boot/power-off
        // failure must be classified VMM-level so the auto path retries libkrun.
        assert!(is_builder_vm_level_failure(&BuilderVmError::HvfVmmFailed {
            detail: "boot failed".into(),
        }));
    }

    // ── Registration hook ─────────────────────────────────────────

    #[test]
    fn hvf_uses_registered_ctor() {
        // Registered ctor returns a stub; resolution routes Hvf to it.
        register_hvf_builder(Box::new(|| Ok(Box::new(crate::builder_vm::StubBuilderVm))));
        let _b = try_resolve_builder_backend_with_override(Some(BuilderBackendChoice::Hvf))
            .expect("registered ctor constructs a builder");
    }

    // ── Fallback safety: hvf fails → libkrun succeeds ─────────

    #[test]
    fn auto_hvf_failure_falls_back_to_libkrun_and_succeeds() {
        use std::cell::RefCell;
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join(".cache"));
        let calls = RefCell::new(Vec::new());
        // Drive the order directly (host-agnostic): hvf fails VMM-level, libkrun ok.
        let order = builder_attempt_order(BuilderBackendChoice::Hvf, false, false, false);
        assert_eq!(
            order,
            vec![BuilderBackendChoice::Hvf, BuilderBackendChoice::Libkrun]
        );
        let result = run_with_builder_fallback(BuilderBackendChoice::Hvf, false, |c| {
            calls.borrow_mut().push(c);
            match c {
                BuilderBackendChoice::Libkrun => Ok(()),
                _ => Err(BuilderVmError::SupervisorExited {
                    exit_code: 1,
                    vm_state_dir: "/x".into(),
                }),
            }
        });
        assert!(result.is_ok());
        assert_eq!(
            *calls.borrow(),
            vec![BuilderBackendChoice::Hvf, BuilderBackendChoice::Libkrun]
        );
    }

    #[test]
    #[ignore = "live: needs macOS-26 + working hvf builder (gated on the hvf vsock io-thread fix landing)"]
    fn live_hvf_builds_sleeper_flake() {
        // Manual: `mvmctl machine run --flake examples/sleeper` on macOS-26 with no
        // flags must auto-detect the hvf builder and produce artifacts.
    }
}
