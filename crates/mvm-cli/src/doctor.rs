use std::collections::BTreeMap;

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;

use crate::ui;
use mvm::config::VM_NAME;
use mvm::shell;
use mvm_backend::backend::AnyBackend;
use mvm_core::config::fc_version;
use mvm_core::platform::{self, Platform};
use mvm_core::vm_backend::ClaimStatus;

/// Audience-scoped filter for `mvmctl doctor`.
///
/// `--workflow <name>` narrows the report (and the exit-code
/// blocking set) to checks whose `category` is relevant for the
/// named workflow. Each workflow's mapping lives in
/// [`DoctorWorkflow::relevant_categories`] — adding a new check
/// category therefore implies a deliberate decision about which
/// workflows it applies to.
///
/// The default (no `--workflow` flag) runs every check and every
/// failure blocks. The flag is additive — operators relying on the
/// existing behavior see no change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorWorkflow {
    /// CLI user running an existing command (`mvmctl run`,
    /// `mvmctl up`, `mvmctl build`).
    CliRun,
    /// Python SDK consumer (`@mvm.app` decorator + `mvmctl
    /// compile` / `up` / `invoke`).
    PythonSdk,
    /// TypeScript / Node SDK consumer.
    TypescriptSdk,
    /// Operator launching a prebuilt `.mvmpkg` bundle. No host
    /// build tooling required.
    BundleRun,
    /// Builder-VM shell workflow — drops the operator into a builder-VM
    /// shell. Builder tooling + platform capabilities only;
    /// no host-side rust toolchain required.
    DevShell,
}

impl DoctorWorkflow {
    /// Check categories included for this workflow. A `Check`
    /// whose `category` is in the returned slice counts as
    /// "relevant" — irrelevant checks are dropped from both the
    /// rendered report and the `all_ok` blocking decision.
    pub fn relevant_categories(self) -> &'static [&'static str] {
        match self {
            // `cli-run` and the two SDK flows all rely on the full
            // host + build tooling stack. The differentiator vs.
            // "no flag" is mostly about the help surface and the
            // intent telemetry; the category set is identical.
            Self::CliRun | Self::PythonSdk | Self::TypescriptSdk => {
                &["prerequisites", "tools", "platform", "security", "disk"]
            }
            // Prebuilt bundles do not require host rust or
            // builder-VM tooling. Drop `prerequisites` and `tools`
            // so a bundle-running operator isn't blocked by a
            // missing `cargo` they don't need.
            Self::BundleRun => &["platform", "security", "disk"],
            // The dev-shell workflow is the bootstrap-time flow; the host
            // doesn't need rustup/cargo for it (the dev VM owns
            // the build toolchain). Drop `prerequisites`.
            Self::DevShell => &["tools", "platform", "security", "disk"],
        }
    }

    /// Stable kebab-case label for human + JSON rendering.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CliRun => "cli-run",
            Self::PythonSdk => "python-sdk",
            Self::TypescriptSdk => "typescript-sdk",
            Self::BundleRun => "bundle-run",
            Self::DevShell => "dev-shell",
        }
    }
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    category: &'static str,
    ok: bool,
    info: String,
}

/// Path of the host-side vsock proxy socket for the dev VM.
///
/// The Apple Container backend names the dev VM `mvm-dev` and writes its
/// proxy socket under `mvm_share_dir()` — its presence is doctor's signal
/// that the builder VM is reachable. The legacy `mvm-builder` constant
/// (`VM_NAME`) is the routing key for `shell::run_on_vm`, not a filesystem
/// path.
fn dev_vm_socket_path() -> String {
    format!(
        "{}/vms/mvm-dev/vsock.sock",
        mvm_core::config::mvm_share_dir()
    )
}

fn dev_vm_running() -> bool {
    std::path::Path::new(&dev_vm_socket_path()).exists()
}

/// Informational `Check` returned when a builder-tool probe can't run
/// because the dev VM is down. Doctor exits 0 in this case — builder
/// tooling lives in the dev VM, never on the host, so its absence is
/// not a host-side defect.
fn builder_tool_skipped(name: &'static str, category: &'static str) -> Check {
    Check {
        name,
        category,
        ok: true,
        info: "skipped — dev VM not running; run `mvmctl bootstrap` to verify".into(),
    }
}

/// JSON-serializable view of a backend's security profile,
/// surfaced under `security_posture` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
struct SecurityPostureReport {
    /// Backend name (e.g. "firecracker", "libkrun").
    backend: String,
    /// Tier label: "Tier 1", "Tier 2", "Tier 3".
    tier: &'static str,
    /// Layer coverage flags (L1..L5).
    layers: [bool; 5],
    /// Whether L1+L2+L3 are all enforced — i.e. this is a real microVM tier.
    is_microvm: bool,
    /// Per-claim status strings (1..7), one of "Holds", "DoesNotApply",
    /// "DoesNotHold".
    claims: [&'static str; 7],
    /// 1-indexed claim numbers that do not hold for this backend.
    dropped_claims: Vec<u8>,
    /// 1-indexed claim numbers that don't apply to this backend.
    na_claims: Vec<u8>,
    /// Per-backend rationale (`notes` field of `BackendSecurityProfile`).
    notes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    /// Workflow scope this report was filtered for, or `None` for
    /// the default "all checks" mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<&'static str>,
    checks: Vec<Check>,
    security_posture: SecurityPostureReport,
    /// Per-backend virtio-balloon capability surfaced by
    /// `VmBackend::capabilities`. Lets users predict which backend
    /// will honour `mem_initial` in their manifest before launching.
    /// Ordered by `BTreeMap`'s natural backend-name order so JSON
    /// output is deterministic.
    balloon_support: BTreeMap<String, bool>,
    /// Per-backend warm-start tier + the Linux fast-resume substrate probe.
    /// Surfaces the honest capability matrix — Firecracker live-memory, Vz
    /// save/restore, libkrun disk-only — so a user can predict which backend
    /// resumes from RAM vs. reboots from disk.
    warm_start: WarmStartReport,
    /// Per-backend capability matrix — snapshot tier, network/storage
    /// disposition, and the boot-latency (standby-pool) axis — the
    /// tradeoffs behind `--hypervisor`, aggregated from `VmBackend`.
    capability_table: Vec<BackendCapabilityRow>,
    all_ok: bool,
}

/// Per-backend warm-start capability + Linux fast-resume substrate, surfaced
/// under `warm_start` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
struct WarmStartReport {
    /// Backend name → warm-start tier label (`SnapshotCapability::label`).
    /// `BTreeMap` for deterministic JSON ordering, like `balloon_support`.
    backends: BTreeMap<String, &'static str>,
    /// The Linux-only fast-resume substrate (NBD module, HugeTLB reservation).
    /// `null` off Linux — the substrate backs Firecracker's live-memory path,
    /// which only runs on KVM; macOS reports per-backend tiers but N/A here.
    substrate: Option<WarmStartSubstrate>,
    /// Backend name → `supports_standby_pool()`. The standby pool
    /// (pre-pay spawn/codesign latency) is a *different* axis from the snapshot tier above;
    /// only libkrun implements it today.
    standby_pool: BTreeMap<String, bool>,
    /// Live count of idle standbys recorded under `~/.mvm/pool/` (best-effort; `None` if
    /// the pool dir can't be read).
    standby_pool_idle: Option<usize>,
}

/// Linux fast-resume substrate probe: the kernel pieces the
/// Firecracker UFFD/NBD/hugepages resume recipe needs.
#[derive(Debug, Serialize)]
struct WarmStartSubstrate {
    /// `/sys/module/nbd` present — the NBD module is loaded (Firecracker
    /// serves the resumed rootfs over NBD).
    nbd_module_loaded: bool,
    /// `/proc/sys/vm/nr_hugepages` > 0 — 2 MB hugepages reserved for the UFFD
    /// memfile backing a live-memory resume.
    hugetlb_reserved: bool,
}

/// Surface the last Stage 0 builder-VM bootstrap
/// outcome (and its source-fingerprint prefix, carried in the audit
/// detail) so "why did Stage 0 fire / when did it last run?" is
/// answerable without grep-ing the audit log. Informational: a stale or
/// never-run Stage 0 is not a host-side defect, so `ok` is always true.
/// Informational: which **workload** runtime backend(s) this host can run, driven
/// by a `/dev/kvm` probe. On Linux+KVM both `firecracker` (default) and `libkrun`
/// are workload backends (selectable via `--hypervisor` / `MVM_HYPERVISOR`); with
/// no `/dev/kvm` only `qemu` runs, and it is dev/test-only — claim-10 egress is
/// deliberately NOT enforced there, so the tier downgrade stays explicit.
fn runtime_backend_check(plat: platform::Platform) -> Check {
    use platform::Platform;
    let info = match plat {
        Platform::LinuxNative => "/dev/kvm present — `firecracker` (default) or \
             `--hypervisor libkrun` (MVM_HYPERVISOR=libkrun); both need /dev/kvm and \
             enforce claim-10 egress"
            .to_string(),
        Platform::LinuxNoKvm => "no /dev/kvm — only the `qemu` dev/test backend runs \
             here, which is NOT a workload backend: claim-10 egress is deliberately \
             NOT enforced (dev/test only)"
            .to_string(),
        Platform::Wsl2 => "WSL2 — a workload runtime needs nested /dev/kvm; without it \
             only `qemu` (dev/test only, no claim-10) runs"
            .to_string(),
        Platform::MacOS => "macOS — `hvf` (macOS 26+ Apple Silicon) or `libkrun` (macOS 13-25) \
             workload backends, selectable via `--hypervisor`"
            .to_string(),
        Platform::Windows => "Windows — no local microVM workload path yet".to_string(),
    };
    Check {
        name: "workload runtime backend",
        category: "platform",
        ok: true,
        info,
    }
}

fn stage0_status_check() -> Check {
    use mvm_core::policy::audit::LocalAuditKind;
    let info = match mvm_core::policy::audit::read_last_stage0_event() {
        None => "no Stage 0 recorded yet (run `mvmctl bootstrap`)".to_string(),
        Some(ev) => {
            let outcome = match ev.kind {
                LocalAuditKind::Stage0Boot => "boot (in progress or interrupted)",
                LocalAuditKind::Stage0CachePromoted => "cache promoted (clean)",
                LocalAuditKind::Stage0Failed => "failed",
                _ => "unknown",
            };
            match ev.detail {
                Some(d) => format!("last Stage 0: {outcome} at {} ({d})", ev.timestamp),
                None => format!("last Stage 0: {outcome} at {}", ev.timestamp),
            }
        }
    };
    Check {
        name: "stage 0",
        category: "tools",
        ok: true,
        info,
    }
}

/// Surface the builder VM store's on-disk presence + size. Host-side we
/// can't verify nix-store integrity (that needs booting the VM), so this is
/// informational: present/absent + size, with the `cache repair` recovery path
/// noted. `ok` is always true — an absent store just means a cold first build,
/// and a present-but-degraded store isn't host-detectable without a build.
fn builder_store_check() -> Check {
    // The repair dry-run is a pure read: it returns (existed, bytes, path)
    // without removing anything.
    let info = match mvm_build::builder_vm::clear_builder_store(true) {
        Ok(s) if s.existed => format!(
            "present ({:.1} GiB) at {} — if `mvmctl bootstrap` fails with a dangling-store \
             error, run `mvmctl cache repair`",
            s.bytes_freed as f64 / (1024.0 * 1024.0 * 1024.0),
            s.path,
        ),
        Ok(s) => format!("absent ({} — first `mvmctl bootstrap` builds it)", s.path),
        Err(e) => format!("could not stat builder store: {e}"),
    };
    Check {
        name: "builder store",
        category: "tools",
        ok: true,
        info,
    }
}

/// The builder VM's fixed egress posture, appended to every
/// builder-egress line as an affirmation. The builder VM locks egress on
/// the deps-install arm (proxy-uid-only, fail-closed) and opens it for
/// flake-build fetches — a fixed design, not a runtime decision.
#[cfg(feature = "builder-vm")]
const BUILDER_EGRESS_POSTURE: &str = "egress is locked on the deps-install arm (proxy-uid-only, fail-closed) \
     and open for flake-build fetches";

/// Map a parsed network-bootstrap outcome to its `Check` body.
/// Pure so the classification → report mapping is unit-testable without
/// touching the filesystem.
#[cfg(feature = "builder-vm")]
fn builder_egress_check_from_outcome(outcome: mvm_build::guest_net::BuilderNetBootstrap) -> Check {
    use mvm_build::guest_net::BuilderNetBootstrap;
    // The check name is already "builder egress", and the renderer prints
    // it as `builder egress: <status> (<info>)` — so the info body omits
    // the redundant prefix and leads with the outcome.
    let (ok, info) = match outcome {
        BuilderNetBootstrap::Lease { ip } => (
            true,
            format!("DHCP lease {ip} on the builder egress path; {BUILDER_EGRESS_POSTURE}"),
        ),
        BuilderNetBootstrap::StaticFallback { ip } => (
            true,
            format!(
                "static fallback {ip} (no DHCP lease — degraded but \
                 reachable); {BUILDER_EGRESS_POSTURE}"
            ),
        ),
        BuilderNetBootstrap::Failed => (
            false,
            format!(
                "net bootstrap FAILED (no DHCP lease, no static fallback \
                 — builds can't fetch); {BUILDER_EGRESS_POSTURE}"
            ),
        ),
        BuilderNetBootstrap::Unknown => (
            true,
            format!("outcome not yet recorded in console.log; {BUILDER_EGRESS_POSTURE}"),
        ),
    };
    Check {
        name: "builder egress",
        category: "platform",
        ok,
        info,
    }
}

/// Surface the persistent builder VM's last network-bootstrap outcome
/// (DHCP lease / static fallback / failure) so the failure class is
/// diagnosable without reading the guest console by hand.
///
/// Reads the libkrun dev VM's host-side `console.log` at the fixed
/// `mvm-dev` state dir. When the VM hasn't booted yet the file is absent and
/// the check reports that cleanly.
#[cfg(feature = "builder-vm")]
fn builder_egress_check() -> Check {
    let log_path = mvm_core::config::vm_state_dir("mvm-dev").join("console.log");
    let Ok(contents) = std::fs::read_to_string(&log_path) else {
        return Check {
            name: "builder egress",
            category: "platform",
            ok: true,
            info: "no builder VM yet (run `mvmctl bootstrap`)".to_string(),
        };
    };
    let outcome = mvm_build::guest_net::classify_builder_net_bootstrap(&contents);
    builder_egress_check_from_outcome(outcome)
}

/// Stub when the `builder-vm` feature is off — a CLI built without builder
/// support never boots a builder VM.
#[cfg(not(feature = "builder-vm"))]
fn builder_egress_check() -> Check {
    Check {
        name: "builder egress",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// One-line summary of a dry-run convergence report for `doctor`.
/// Pure so it's testable without touching the registry.
fn registry_drift_summary(report: &mvm::vm::reconcile::ConvergeReport) -> String {
    let n = report.reconciled_count();
    if n == 0 {
        "clean".to_string()
    } else {
        format!("{n} record(s) would be reconciled (run `mvmctl reconcile`)")
    }
}

/// Surface registry/runtime drift without
/// healing it: a dry-run convergence pass, reported as `clean` or a
/// count. Informational — drift self-heals at the next state-touching
/// command, so `ok` is always true.
fn registry_drift_check() -> Check {
    let report = mvm::vm::reconcile::converge(&mvm::vm::reconcile::ConvergeOpts { dry_run: true });
    Check {
        name: "registry drift",
        category: "platform",
        ok: true,
        info: registry_drift_summary(&report),
    }
}

/// `kill(pid, 0)` liveness: the process exists and is signalable.
fn pid_is_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 delivers nothing; it only validates the pid.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Summarize the per-tenant host-agent daemons under `root`.
/// Reports warm daemons, stale daemon artifacts, or "absent" when none exist.
fn host_agent_daemon_summary(root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(root) else {
        return "absent (no per-tenant daemon yet; an admitted workload starts one)".to_string();
    };
    let mut warm = Vec::new();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let tenant = entry.file_name().to_string_lossy().into_owned();
        let pid_file = dir.join("daemon.pid");
        let pid_file_exists = pid_file.exists();
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok());
        let sock = dir.join("control.sock").exists();
        if let Some(p) = pid.filter(|p| pid_is_alive(*p))
            && sock
        {
            warm.push(format!("{tenant}: running (pid {p})"));
        } else if sock || pid_file_exists {
            // A pid or socket left behind by a dead daemon.
            stale.push(tenant);
        }
        // Empty dirs, for example one containing only the spawn lock, are skipped.
    }
    warm.sort();
    stale.sort();
    if warm.is_empty() && stale.is_empty() {
        return "absent (no per-tenant daemon running)".to_string();
    }
    let mut parts = Vec::new();
    if !warm.is_empty() {
        parts.push(format!("{} warm - {}", warm.len(), warm.join(", ")));
    }
    if !stale.is_empty() {
        parts.push(format!("stale: {}", stale.join(", ")));
    }
    parts.join("; ")
}

/// Per-tenant host-agent daemon state. Informational.
fn host_agent_daemon_check() -> Check {
    Check {
        name: "host-agent daemon",
        category: "platform",
        ok: true,
        info: host_agent_daemon_summary(&mvm_core::config::host_agent_root()),
    }
}

/// Probe timeout for the resident builder-daemon readiness check. Short
/// so `doctor` stays responsive even when a stale socket is present.
const BUILDERD_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);

/// Summarize resident builder-daemon (`mvm-builderd`) readiness across the
/// persistent builder VMs under `vms_root`. Each builder VM exposes its
/// typed control socket at `<vm_state_dir>/vsock-<BUILDERD_CONTROL_PORT>.sock`;
/// every present socket is probed with a bounded handshake. Informational:
/// absence just means no builder VM is running, so `ok` stays true.
fn builderd_daemon_summary(vms_root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(vms_root) else {
        return "absent (no builder VM yet; run `mvmctl bootstrap`)".to_string();
    };
    let mut lines = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        // A builder VM may be libkrun (`<dir>/vsock-<port>.sock`) or Vz
        // (`<dir>/vsock/vsock-<port>.sock`); probe whichever socket the
        // backend actually created.
        let Some(sock) = mvm_build::builderd::builderd_control_socket_candidates(&dir)
            .into_iter()
            .find(|p| p.exists())
        else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let readiness =
            mvm_build::builderd::probe_builderd_readiness(&sock, BUILDERD_PROBE_TIMEOUT);
        lines.push(format!(
            "{name}: {}",
            mvm_build::builderd::readiness_summary(&readiness)
        ));
    }
    lines.sort();
    if lines.is_empty() {
        return "absent (no builder daemon; run `mvmctl bootstrap`)".to_string();
    }
    lines.join("; ")
}

/// Resident builder-daemon readiness. Informational.
fn builderd_daemon_check() -> Check {
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    Check {
        name: "builder daemon",
        category: "platform",
        ok: true,
        info: builderd_daemon_summary(&vms_root),
    }
}

/// The builder transport shape currently in effect on this host.
///
/// This makes the no-guest-NIC cutover status explicit instead of forcing an
/// operator to infer it from the backend line plus the separate egress check.
/// It also marks the remaining guest-NIC-based paths as legacy/unsupported for
/// the production vsock-only architecture.
#[cfg(feature = "builder-vm")]
fn builder_transport_check(plat: Platform) -> Check {
    use mvm_build::builder_backend_select::BuilderBackendChoice;
    let choice = mvm_build::builder_backend_select::resolve_choice();
    let info = match choice {
        BuilderBackendChoice::Hvf => {
            "vsock-only host/guest transport; no builder guest NIC, no DHCP or gateway bootstrap"
                .to_string()
        }
        BuilderBackendChoice::Libkrun => {
            if plat == Platform::Wsl2 {
                "legacy guest-network bootstrap path on libkrun (DHCP/static fallback); no-guest-NIC builder cutover not landed on WSL2"
                    .to_string()
            } else {
                "legacy guest-network bootstrap path on libkrun (DHCP/static fallback); still a builder networking exception, not the final vsock-only transport"
                    .to_string()
            }
        }
        BuilderBackendChoice::Qemu => {
            "unsupported legacy builder path: qemu dev/test fallback with guest-network bootstrap; not part of the production vsock-only architecture"
                .to_string()
        }
    };
    Check {
        name: "builder transport",
        category: "platform",
        ok: true,
        info,
    }
}

#[cfg(not(feature = "builder-vm"))]
fn builder_transport_check(_plat: Platform) -> Check {
    Check {
        name: "builder transport",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// Summarize workload packet-tunnel worker state under `vms_root`. Reports each
/// worker as active (live pid) or stale (dead/malformed pid with leftover
/// artifacts), and `absent` when nothing is staged. Informational: no tunnel
/// worker is the normal state for a workload with no admitted forwarding tunnel.
fn network_tunnel_worker_summary(vms_root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(vms_root) else {
        return "absent (no workload tunnel worker running)".to_string();
    };
    let mut running = Vec::new();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let pid_file = dir.join(mvm_backend::NETWORK_TUNNEL_WORKER_PID_FILE);
        let audit_file = dir.join(mvm_backend::NETWORK_TUNNEL_AUDIT_JSONL);
        let pid_file_exists = pid_file.exists();
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok());
        let has_artifacts = pid_file_exists || audit_file.exists();
        if let Some(pid) = pid.filter(|pid| pid_is_alive(*pid)) {
            running.push(format!("{name} (pid {pid})"));
        } else if has_artifacts {
            stale.push(name);
        }
    }
    running.sort();
    stale.sort();
    if running.is_empty() && stale.is_empty() {
        return "absent (no workload tunnel worker running)".to_string();
    }
    let mut parts = Vec::new();
    if !running.is_empty() {
        parts.push(format!("{} active - {}", running.len(), running.join(", ")));
    }
    if !stale.is_empty() {
        parts.push(format!("stale: {}", stale.join(", ")));
    }
    parts.join("; ")
}

/// Workload packet-tunnel worker state. Informational.
fn network_tunnel_worker_check() -> Check {
    Check {
        name: "network tunnel worker",
        category: "platform",
        ok: true,
        info: network_tunnel_worker_summary(
            &std::path::PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms"),
        ),
    }
}

pub fn run(json: bool, workflow: Option<DoctorWorkflow>) -> Result<()> {
    // ── Prerequisites (user must install before bootstrap) ───────
    let mut checks = vec![
        check_cmd("rustup", "prerequisites", &["--version"]),
        check_cmd("cargo", "prerequisites", &["--version"]),
    ];

    // ── Managed Tools (installed inside the dev VM) ──────────────
    //
    // Builder tooling (nix, firecracker, nix store, flakes) belongs to
    // the dev VM, never the host. When the dev VM isn't running these
    // probes return informational `Check`s and doctor exits 0 — the host
    // is not expected to own them. Routing still goes through `VM_NAME`,
    // which `shell::run_on_vm` maps to the platform's default LinuxEnv.
    let vm_up = dev_vm_running();
    checks.push(if vm_up {
        nix_version_check()
    } else {
        builder_tool_skipped("nix", "tools")
    });
    checks.push(if vm_up {
        check_vm_cmd("firecracker", "tools", "firecracker --version")
    } else {
        builder_tool_skipped("firecracker", "tools")
    });

    checks.push(Check {
        name: "fc target",
        category: "tools",
        ok: true,
        info: fc_version(),
    });

    // Nix flake support check
    checks.push(if vm_up {
        nix_flakes_check()
    } else {
        builder_tool_skipped("nix flakes", "tools")
    });

    // ── Platform ──────────────────────────────────────────────────
    let plat = platform::current();
    checks.push(Check {
        name: "platform",
        category: "platform",
        ok: true,
        info: platform_description(plat),
    });

    checks.push(kvm_check(plat, false));
    checks.push(nested_kvm_check(plat));
    checks.push(libkrun_check(plat));
    checks.push(builder_backend_check(plat));
    checks.push(runtime_backend_check(plat));
    checks.push(residency_check());
    checks.push(builder_residency_check());
    checks.push(network_backend_check(plat));
    checks.push(ts_runner_check());
    checks.push(stage0_status_check());
    checks.push(builder_store_check());
    checks.push(builder_egress_check());
    checks.push(registry_drift_check());
    checks.push(host_agent_daemon_check());
    checks.push(builderd_daemon_check());
    checks.push(builder_transport_check(plat));
    checks.push(network_tunnel_worker_check());

    checks.push(disk_space_check(false));

    // Nix store health
    checks.push(if vm_up {
        nix_store_check()
    } else {
        builder_tool_skipped("nix store", "tools")
    });
    checks.push(if vm_up {
        nix_store_size_check()
    } else {
        builder_tool_skipped("nix store size", "disk")
    });

    // ── Security posture (folded in from the old `mvmctl security`) ──
    checks.push(security_audit_log_check());
    checks.push(security_host_fde_check());
    checks.push(security_data_dir_mode_check());
    checks.push(security_proxy_socket_mode_check());
    checks.push(security_dev_image_check());
    checks.push(security_deny_config_check());
    checks.push(security_default_network_check());
    checks.push(security_network_policy_default_check());
    checks.push(security_snapshot_key_check());
    checks.push(security_snapshot_dirs_check());
    checks.push(security_signing_check());

    // ── Active backend security posture ──────
    let security_posture = collect_security_posture();

    // ── Balloon capability per backend ────────────────────────────
    let balloon_support = collect_balloon_support();

    // ── Warm-start capability per backend ───────
    let warm_start = collect_warm_start_support();

    // ── Per-backend capability matrix ─────────────────────────────
    let capability_table = collect_capability_table();

    // ── Workflow filter ──────────────────────────────
    // When `--workflow <name>` is set, drop checks whose category
    // is not in the workflow's relevant set. The filter is applied
    // before `all_ok` so an irrelevant failure (e.g. missing
    // `cargo` for a `bundle-run` operator) no longer blocks.
    let checks: Vec<Check> = match workflow {
        Some(w) => {
            let relevant = w.relevant_categories();
            checks
                .into_iter()
                .filter(|c| relevant.contains(&c.category))
                .collect()
        }
        None => checks,
    };

    // ── Render ────────────────────────────────────────────────────
    let all_ok = checks.iter().all(|c| c.ok);
    let report = DoctorReport {
        workflow: workflow.map(|w| w.as_str()),
        checks,
        security_posture,
        balloon_support,
        warm_start,
        capability_table,
        all_ok,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.all_ok {
            anyhow::bail!("doctor found issues");
        }
        return Ok(());
    }

    render_text(&report);

    if !report.all_ok {
        let missing: Vec<&Check> = report.checks.iter().filter(|c| !c.ok).collect();
        ui::warn("\nIssues found:");
        for line in issue_summary_lines(&missing) {
            ui::warn(&line);
        }

        // Provide category-specific guidance
        let has_prerequisites = missing.iter().any(|c| c.category == "prerequisites");
        let has_managed = missing.iter().any(|c| c.category == "tools");

        if has_prerequisites {
            ui::notice("\nPrerequisites missing: Install Rust from https://rustup.rs");
        }
        if has_managed {
            ui::notice("\nManaged tools missing: Run 'mvmctl bootstrap' to install");
        }

        anyhow::bail!("doctor found issues");
    }

    ui::success("\nAll checks passed.");
    Ok(())
}

fn render_text(report: &DoctorReport) {
    if let Some(w) = report.workflow {
        ui::info(&format!(
            "Scoping checks to workflow: {} (use `mvmctl doctor` for the unfiltered report)",
            w
        ));
    }
    let mut current_category = "";
    for c in &report.checks {
        if c.category != current_category {
            current_category = c.category;
            let title = match current_category {
                "prerequisites" => "Prerequisites",
                "tools" => "Tools",
                "platform" => "Platform",
                "security" => "Security posture",
                _ => current_category,
            };
            println!("\n{}", title);
            println!("{}", "-".repeat(title.len()));
        }
        let status = if c.ok { "OK" } else { "MISSING" };
        ui::status_line(
            &format!("  {}:", c.name),
            &format!("{} ({})", status, c.info),
        );
    }
    render_security_posture(&report.security_posture);
    render_balloon_support(&report.balloon_support);
    render_warm_start_support(&report.warm_start);
    render_capability_table(&report.capability_table);
}

fn issue_summary_lines(missing: &[&Check]) -> Vec<String> {
    missing
        .iter()
        .map(|check| format!("  {} — {}", check.name, check.info))
        .collect()
}

/// Enumerate every backend's `capabilities().balloon`. The doctor
/// surfaces this so a user authoring `mem_initial` in `mvm.toml`
/// can see at a glance which backend will honour the opt-in (vs.
/// which will silently ignore it because the underlying VMM doesn't
/// support virtio-balloon).
///
/// Keyed by `&str` rather than `&'static str` so JSON serialisation
/// gets a stable BTreeMap ordering. Names match `VmBackend::name`.
fn collect_balloon_support() -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for descriptor in mvm_backend::catalog::balloon_support_descriptors() {
        let backend = descriptor.instantiate_dyn();
        out.insert(backend.name().to_string(), backend.capabilities().balloon);
    }
    out
}

/// Print the balloon-support matrix in `mvmctl doctor` text mode.
/// Stays concise — one section, one line per backend.
fn render_balloon_support(support: &BTreeMap<String, bool>) {
    let title = "Memory ballooning (virtio-balloon)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    for (backend, ok) in support {
        let mark = if *ok { "yes" } else { "no" };
        ui::status_line(&format!("  {backend}:"), mark);
    }
    if !support.values().any(|v| *v) {
        ui::warn(
            "  · No backend on this host advertises virtio-balloon. \
             `mem_initial` in mvm.toml will be ignored at boot.",
        );
    }
}

// ── Warm-start capability ──────────────────────

/// One row of the per-backend capability matrix — the security/perf
/// tradeoffs a user weighs when picking `--hypervisor`. Every field is
/// read straight off `VmBackend`, so the table can never drift from
/// runtime behavior.
#[derive(Debug, Clone, Serialize)]
struct BackendCapabilityRow {
    /// Backend name, matching `VmBackend::name`.
    backend: String,
    /// `SnapshotCapability::label` — warm-start fidelity (RAM resume vs disk reboot).
    snapshot_tier: &'static str,
    /// Host TAP device (vs a userspace gateway / slirp).
    tap_networking: bool,
    /// vsock guest control channel.
    vsock: bool,
    /// virtio-balloon runtime memory reclaim.
    balloon: bool,
    /// Copy-on-write fs checkpoint (APFS `clonefile`), independent of memory snapshots.
    fs_quick_checkpoint: bool,
    /// Pre-warmed standby pool that pre-pays spawn/codesign latency — the boot-latency axis.
    standby_pool: bool,
}

/// Build the per-backend capability matrix from the catalog's real backends
/// (the Tier 3 `mock` double is excluded via the warm-start descriptor set).
/// Each row reads off `VmBackend` so doctor's table is the runtime truth, not
/// a hand-maintained copy. Sorted by name for deterministic output.
fn collect_capability_table() -> Vec<BackendCapabilityRow> {
    let mut rows: Vec<BackendCapabilityRow> =
        mvm_backend::catalog::warm_start_support_descriptors()
            .map(|descriptor| {
                let b = descriptor.instantiate_dyn();
                let caps = b.capabilities();
                BackendCapabilityRow {
                    backend: b.name().to_string(),
                    snapshot_tier: b.snapshot_capability().label(),
                    tap_networking: caps.tap_networking,
                    vsock: caps.vsock,
                    balloon: caps.balloon,
                    fs_quick_checkpoint: caps.fs_quick_checkpoint,
                    standby_pool: b.supports_standby_pool(),
                }
            })
            .collect();
    rows.sort_by(|a, b| a.backend.cmp(&b.backend));
    rows
}

/// Render the per-backend capability matrix in text mode — the at-a-glance
/// tradeoff table behind `--hypervisor`. One line per backend.
fn render_capability_table(rows: &[BackendCapabilityRow]) {
    let title = "Backend capability matrix (per backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    let yn = |b: bool| if b { "yes" } else { "—" };
    for r in rows {
        ui::status_line(
            &format!("  {}:", r.backend),
            &format!(
                "snapshot {} · tap-net {} · vsock {} · balloon {} · fs-checkpoint {} · standby-pool {}",
                r.snapshot_tier,
                yn(r.tap_networking),
                yn(r.vsock),
                yn(r.balloon),
                yn(r.fs_quick_checkpoint),
                yn(r.standby_pool),
            ),
        );
    }
}

/// Enumerate every backend's `snapshot_capability()` tier and, on Linux,
/// probe the fast-resume substrate. Surfaced so a user knows which backend
/// resumes from RAM (Firecracker live-memory, Vz save/restore) vs. reboots
/// from a disk snapshot (libkrun) before relying on a warm start.
fn collect_warm_start_support() -> WarmStartReport {
    let mut backends = BTreeMap::new();
    let mut standby_pool = BTreeMap::new();
    for descriptor in mvm_backend::catalog::warm_start_support_descriptors() {
        let b = descriptor.instantiate_dyn();
        backends.insert(b.name().to_string(), b.snapshot_capability().label());
        standby_pool.insert(b.name().to_string(), b.supports_standby_pool());
    }
    // Best-effort live idle count. A missing pool dir reads as 0.
    let standby_pool_idle = mvm_backend::standby_pool::SupervisorStandbyPool::open()
        .and_then(|p| p.list())
        .ok()
        .map(|v| {
            v.iter()
                .filter(|h| h.state == mvm_core::vm_backend::StandbyState::Idle)
                .count()
        });
    WarmStartReport {
        backends,
        substrate: collect_warm_start_substrate(),
        standby_pool,
        standby_pool_idle,
    }
}

/// `<sys_module>/nbd` exists ⇒ the NBD kernel module is loaded. Pure so it's
/// testable without `/sys`. Only `collect_warm_start_substrate` (Linux) and
/// the unit tests call it; off Linux the non-test build has no caller.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nbd_module_loaded_at(sys_module: &std::path::Path) -> bool {
    sys_module.join("nbd").exists()
}

/// Parse `/proc/sys/vm/nr_hugepages`; > 0 ⇒ hugepages reserved. Pure so it's
/// testable cross-platform; a non-numeric/empty read is "none reserved".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn hugetlb_reserved_from(nr_hugepages: &str) -> bool {
    nr_hugepages
        .trim()
        .parse::<u64>()
        .map(|n| n > 0)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn collect_warm_start_substrate() -> Option<WarmStartSubstrate> {
    let nr = std::fs::read_to_string("/proc/sys/vm/nr_hugepages").unwrap_or_default();
    Some(WarmStartSubstrate {
        nbd_module_loaded: nbd_module_loaded_at(std::path::Path::new("/sys/module")),
        hugetlb_reserved: hugetlb_reserved_from(&nr),
    })
}

#[cfg(not(target_os = "linux"))]
fn collect_warm_start_substrate() -> Option<WarmStartSubstrate> {
    None
}

/// Print the warm-start matrix in `mvmctl doctor` text mode. One line per
/// backend, then the Linux substrate (or N/A off Linux).
fn render_warm_start_support(r: &WarmStartReport) {
    let title = "Warm-start capability (per backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    for (backend, tier) in &r.backends {
        ui::status_line(&format!("  {backend}:"), tier);
    }
    match &r.substrate {
        Some(s) => {
            ui::status_line(
                "  substrate · NBD module",
                if s.nbd_module_loaded {
                    "loaded"
                } else {
                    "not loaded"
                },
            );
            ui::status_line(
                "  substrate · HugeTLB",
                if s.hugetlb_reserved {
                    "reserved"
                } else {
                    "none reserved"
                },
            );
        }
        None => ui::status_line("  substrate (Linux fast-resume)", "N/A (Linux-only)"),
    }

    // The standby pool (pre-pay spawn latency), a separate axis from
    // the snapshot tiers above. Only libkrun implements it today.
    let pool_title = "Standby pool (per backend)";
    println!("\n{}", pool_title);
    println!("{}", "-".repeat(pool_title.len()));
    for (backend, supported) in &r.standby_pool {
        ui::status_line(
            &format!("  {backend}:"),
            if *supported { "supported" } else { "—" },
        );
    }
    ui::status_line(
        "  idle standbys",
        &match r.standby_pool_idle {
            Some(n) => n.to_string(),
            None => "unknown".to_string(),
        },
    );
}

// ── Active backend security posture ──────

/// Build the [`SecurityPostureReport`] for the backend that `mvmctl run`
/// would auto-select on this host. Pure data — no I/O beyond reading
/// the platform detection (which is already cached).
fn collect_security_posture() -> SecurityPostureReport {
    let backend = AnyBackend::auto_select();
    let profile = backend.security_profile();
    let layers = [
        profile.layer_coverage.l1_host_hypervisor,
        profile.layer_coverage.l2_vmm,
        profile.layer_coverage.l3_guest_kernel,
        profile.layer_coverage.l4_guest_agent,
        profile.layer_coverage.l5_workload,
    ];
    let claims = [
        claim_status_label(profile.claims[0]),
        claim_status_label(profile.claims[1]),
        claim_status_label(profile.claims[2]),
        claim_status_label(profile.claims[3]),
        claim_status_label(profile.claims[4]),
        claim_status_label(profile.claims[5]),
        claim_status_label(profile.claims[6]),
    ];
    SecurityPostureReport {
        backend: backend.name().to_string(),
        tier: profile.tier,
        layers,
        is_microvm: profile.layer_coverage.is_microvm(),
        claims,
        dropped_claims: profile.dropped_claims(),
        na_claims: profile.na_claims(),
        notes: profile.notes.to_vec(),
    }
}

const fn claim_status_label(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::Holds => "Holds",
        ClaimStatus::DoesNotApply => "DoesNotApply",
        ClaimStatus::DoesNotHold => "DoesNotHold",
    }
}

/// Render the per-backend security posture in `mvmctl doctor` text mode.
///
/// Always prints the active backend, tier, layer coverage, and per-claim
/// status. Warns if the active backend is not a hardware-isolated microVM
/// tier.
fn render_security_posture(p: &SecurityPostureReport) {
    let title = "Security posture (active backend)";
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
    println!("  Active backend: {}", p.backend);
    println!("  Tier: {}", p.tier);

    let layer_marks: String = p
        .layers
        .iter()
        .enumerate()
        .map(|(i, ok)| format!("L{}{}", i + 1, if *ok { " ✓" } else { " ✗" }))
        .collect::<Vec<_>>()
        .join("  ");
    println!("  Layer coverage: {layer_marks}");

    if !p.dropped_claims.is_empty() {
        let list = p
            .dropped_claims
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Claims that do NOT hold: {list}");
    } else {
        println!("  Claims: all seven hold ✓");
    }
    if !p.na_claims.is_empty() {
        let list = p
            .na_claims
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Claims that do not apply: {list}");
    }
    for note in &p.notes {
        println!("  · {note}");
    }

    if !p.is_microvm {
        ui::warn(
            "\n  ⚠ This backend is not a hardware-isolated microVM. The L1-L3\n   \
             layers collapse to the host kernel; ADR-002 claims 1, 2, 3 do NOT\n   \
             hold. See https://docs.mvm.dev/security/matryoshka.",
        );
    }
}

// ── Tool checks ───────────────────────────────────────────────────────────

fn check_cmd(name: &'static str, category: &'static str, args: &[&str]) -> Check {
    match shell::run_host(name, args) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: e.to_string(),
        },
    }
}

fn check_vm_cmd(name: &'static str, category: &'static str, cmd: &'static str) -> Check {
    match shell::run_on_vm(VM_NAME, cmd) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: e.to_string(),
        },
    }
}

// ── Platform checks ───────────────────────────────────────────────────────

fn platform_description(plat: Platform) -> String {
    match plat {
        Platform::MacOS => "macOS".to_string(),
        Platform::LinuxNative => "Linux with KVM".to_string(),
        Platform::LinuxNoKvm => "Linux without KVM".to_string(),
        Platform::Wsl2 => {
            if plat.has_kvm() {
                "WSL2 (nested KVM present; experimental/unsupported)".to_string()
            } else {
                "WSL2 (no nested KVM; unsupported)".to_string()
            }
        }
        Platform::Windows => "Windows".to_string(),
    }
}

/// Surface nested-KVM availability on Linux. Required for the
/// dispatch flip from a libkrun builder VM to a nested Firecracker
/// workload. Linux-only: macOS and Windows hosts get a clean "n/a"
/// line so the doctor output isn't noisy on the platforms the
/// question doesn't apply to.
///
/// Two states matter to operators:
///   1. `MVM_LINUX_BUILDER_VM` is unset → informational only (this
///      is the default today; nested-KVM either ready or a future
///      enablement step).
///   2. `MVM_LINUX_BUILDER_VM=1` is set → the operator has opted in;
///      nested-KVM missing is now a hard "fix this before the nested
///      dispatch ships" error.
fn nested_kvm_check(plat: Platform) -> Check {
    if !matches!(plat, Platform::LinuxNative) {
        return Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "n/a (Linux-only — macOS hosts use libkrun/Vz; Plan 100 W6 affects Linux only)"
                .to_string(),
        };
    }
    let has_nested = plat.has_nested_kvm();
    let env_requested = linux_builder_vm_requested_for_doctor();
    match (has_nested, env_requested) {
        (true, true) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "available — MVM_LINUX_BUILDER_VM=1 is set; Plan 100 W6 nesting ready".to_string(),
        },
        (true, false) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true,
            info: "available (informational — set MVM_LINUX_BUILDER_VM=1 to opt into Plan 100 W6 nesting once it lands)"
                .to_string(),
        },
        (false, true) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: false,
            info: "MVM_LINUX_BUILDER_VM=1 but nested KVM not enabled. \
                   Enable on Intel: `modprobe -r kvm_intel && modprobe kvm_intel nested=Y` \
                   (or `options kvm_intel nested=Y` in /etc/modprobe.d/). \
                   AMD: `modprobe -r kvm_amd && modprobe kvm_amd nested=1`. \
                   Confirm via /sys/module/kvm_intel/parameters/nested or \
                   /sys/module/kvm_amd/parameters/nested."
                .to_string(),
        },
        (false, false) => Check {
            name: "nested-kvm",
            category: "platform",
            ok: true, // Not a failure unless the operator opts in.
            info: "not enabled (informational — enable kvm_intel/kvm_amd nested=1 before \
                   setting MVM_LINUX_BUILDER_VM=1 ahead of Plan 100 W6)"
                .to_string(),
        },
    }
}

#[cfg(feature = "builder-vm")]
fn linux_builder_vm_requested_for_doctor() -> bool {
    mvm_build::builder_backend_select::linux_builder_vm_requested()
}

#[cfg(not(feature = "builder-vm"))]
fn linux_builder_vm_requested_for_doctor() -> bool {
    false
}

fn kvm_check(plat: Platform, in_vm: bool) -> Check {
    // Inside Lima VM or native Linux: check /dev/kvm locally
    if in_vm
        || plat == Platform::LinuxNative
        || plat == Platform::LinuxNoKvm
        || plat == Platform::Wsl2
    {
        // Use test -c (character device exists) rather than test -r (readable),
        // because KVM access may be via group membership which doesn't imply -r.
        return match shell::run_host("bash", &["-c", "test -c /dev/kvm && echo ok"]) {
            Ok(out) if out.status.success() => {
                let context = if in_vm {
                    "available (inside Lima VM)"
                } else {
                    "available"
                };
                Check {
                    name: "kvm",
                    category: "platform",
                    ok: true,
                    info: context.to_string(),
                }
            }
            _ => Check {
                name: "kvm",
                category: "platform",
                ok: false,
                info: if in_vm {
                    "/dev/kvm not accessible inside Lima VM".to_string()
                } else {
                    "not available. Enable virtualization in BIOS or check permissions on /dev/kvm."
                        .to_string()
                },
            },
        };
    }

    // macOS host: /dev/kvm doesn't exist anywhere in the stack — the
    // backend is Apple Container / libkrun driven by
    // Hypervisor.framework. Lima is gone; reporting KVM as missing on
    // macOS would be a stale artifact from that era.
    Check {
        name: "kvm",
        category: "platform",
        ok: true,
        info: "n/a on macOS (Hypervisor.framework via libkrun / Apple Container)".to_string(),
    }
}

/// Surface the active transport contract for the non-KVM backends.
///
/// The current workload and builder directions are direct-vsock only:
/// no guest-NIC helper binary is required on the host for the active
/// libkrun/HVF lanes, and stale gateway expectations should not fail
/// `mvmctl doctor`.
#[cfg(target_family = "unix")]
fn network_backend_check(plat: Platform) -> Check {
    if plat.is_windows() {
        return Check {
            name: "network-backend",
            category: "platform",
            ok: true,
            info: "n/a (no native Windows port)".to_string(),
        };
    }
    Check {
        name: "network-backend",
        category: "platform",
        ok: true,
        info: "direct vsock only; no host gateway binary is part of the active runtime contract"
            .to_string(),
    }
}

/// Windows stub — keeps the call site cfg-free.
#[cfg(not(target_family = "unix"))]
fn network_backend_check(_plat: Platform) -> Check {
    Check {
        name: "network-backend",
        category: "platform",
        ok: true,
        info: "n/a (no Unix libkrun port on this OS)".to_string(),
    }
}

/// libkrun availability. Probes the host for the
/// libkrun shared library at the standard install paths. `ok: true`
/// regardless of presence (libkrun is optional); the `info` field
/// surfaces the install hint when missing so users see exactly what
/// to run.
fn libkrun_check(plat: Platform) -> Check {
    if plat.is_windows() {
        return Check {
            name: "libkrun",
            category: "platform",
            ok: true,
            info: "n/a (no native Windows port; WSL2 is future/experimental)".to_string(),
        };
    }
    if plat.has_libkrun() {
        Check {
            name: "libkrun",
            category: "platform",
            ok: true,
            info: "available".to_string(),
        }
    } else {
        Check {
            name: "libkrun",
            category: "platform",
            ok: true, // Optional; not a failure.
            info: format!("not available ({})", libkrun_sys::install_hint()),
        }
    }
}

/// Surface which builder-VM backend the selection layer resolves to
/// on this host, plus the override source if any.
///
/// `mvm_build::builder_backend_select` enforces priority
/// `--builder` flag > `MVM_BUILDER_BACKEND` env > platform default
/// (macOS 26+ Apple Silicon → hvf; Linux native → qemu; everywhere else →
/// libkrun). The
/// flag is folded into the env at startup (`commands::run`), so by
/// the time doctor runs every override is observable via env.
///
/// The check is informational — it never fails. A missing libkrun
/// prereq is reported by the platform-level `libkrun_check` already in
/// the report; this check is about the *selection*, not the availability.
#[cfg(feature = "builder-vm")]
fn builder_backend_check(plat: Platform) -> Check {
    use mvm_build::builder_backend_select::{
        BuilderBackendChoice, MVM_BUILDER_BACKEND_ENV, MVM_LINUX_BUILDER_VM_ENV,
        auto_detect_default, linux_builder_vm_requested, resolve_env_override,
    };

    let env_override = resolve_env_override();
    let auto = auto_detect_default();
    let resolved = env_override.unwrap_or(auto);

    // Best-effort: detect whether the override came from the
    // `--builder` flag or the env var. The flag is folded into the
    // env at startup, so we can't distinguish them after the fact;
    // surface both possibilities so an operator reading the report
    // knows where to look.
    let mut source = match env_override {
        Some(_) => format!("override via --builder / ${MVM_BUILDER_BACKEND_ENV}"),
        None => format!("auto-detected (default: {})", auto.name()),
    };
    // Surface the Linux-only rollout signal alongside the backend
    // selection. The env does not participate in choosing the builder backend;
    // it changes how the workload path will dispatch once nested Firecracker
    // lands. Operators who set it should see it acknowledged in `doctor`
    // output.
    if linux_builder_vm_requested() {
        source = format!("{source}; ${MVM_LINUX_BUILDER_VM_ENV}=1 (Plan 100 W6 opt-in)");
    }

    let availability = match resolved {
        BuilderBackendChoice::Libkrun => {
            if plat.has_libkrun() {
                "libkrun available".to_string()
            } else {
                format!("libkrun NOT available ({})", libkrun_sys::install_hint())
            }
        }
        BuilderBackendChoice::Qemu => {
            // Linux dev/builder backend. KVM-accelerated
            // where /dev/kvm is present, TCG fallback otherwise.
            if which::which("qemu-system-x86_64").is_ok()
                || which::which("qemu-system-aarch64").is_ok()
            {
                let accel = if std::path::Path::new("/dev/kvm").exists() {
                    "KVM"
                } else {
                    "TCG (unaccelerated)"
                };
                format!("QEMU available ({accel})")
            } else {
                "QEMU NOT available (apt install qemu-system-x86 qemu-utils)".to_string()
            }
        }
        BuilderBackendChoice::Hvf => {
            "HVF builder (constructor registered at CLI startup)".to_string()
        }
    };

    Check {
        name: "builder backend",
        category: "platform",
        ok: true,
        info: format!("{} — {} — {}", resolved.name(), source, availability),
    }
}

/// Stub when `builder-vm` feature is off (CLI built without the
/// builder support — e.g. dependency-light packaging).
#[cfg(not(feature = "builder-vm"))]
fn builder_backend_check(_plat: Platform) -> Check {
    Check {
        name: "builder backend",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// Report the resolved residency policy, its source, the warm target, and the
/// idle timeout. The check is informational and never fails — every override is
/// observable via the `MVM_RESIDENCY` env var at the time doctor runs.
fn residency_check() -> Check {
    use mvm_core::residency::{MVM_RESIDENCY_ENV, ResidencySource, resolve_residency};

    let (policy, source) = resolve_residency();
    let source_str = match source {
        ResidencySource::EnvOverride => format!("override via ${MVM_RESIDENCY_ENV}"),
        ResidencySource::AutoDetect => "auto-detected".to_string(),
    };
    let idle = match policy.idle_timeout() {
        Some(d) => format!(", idle={}m", d.as_secs() / 60),
        None => String::new(),
    };
    Check {
        name: "residency",
        category: "platform",
        ok: true,
        info: format!(
            "{} — {} — warm_target={}{}",
            policy.label(),
            source_str,
            policy.warm_target(),
            idle
        ),
    }
}

/// Informational check: the residency policy's effect on builder routing
/// and whether a persistent builder session is currently live.
///
/// The check never fails — the routing choice is always observable via
/// `MVM_RESIDENCY` and the session state is a best-effort filesystem probe.
/// The two axes together let an operator understand what `mvmctl build image`
/// will do before invoking it.
#[cfg(feature = "builder-vm")]
fn builder_residency_check() -> Check {
    let (policy, _source) = mvm_core::residency::resolve_residency();
    let routing = if policy.allows_persistent_builder() {
        "uses persistent when active"
    } else {
        "ephemeral per build (cold)"
    };
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    let session = builder_residency_session_summary(
        policy.kind(),
        mvm_build::persistent_builder::read_active_session().is_some(),
        builder_vz_snapshot_present(&vms_root),
    );
    Check {
        name: "builder residency",
        category: "platform",
        ok: true,
        info: format!("{} — builds {} — {}", policy.label(), routing, session),
    }
}

/// The persistent-builder snapshot/park mechanism belonged to the removed Vz
/// builder; the libkrun builder has no memory snapshot, so no builder VM
/// carries a resumable snapshot today.
#[cfg(feature = "builder-vm")]
fn builder_vz_snapshot_present(_vms_root: &std::path::Path) -> bool {
    false
}

#[cfg(feature = "builder-vm")]
fn builder_residency_session_summary(
    kind: mvm_core::residency::ResidencyKind,
    persistent_active: bool,
    vz_snapshot_present: bool,
) -> &'static str {
    match kind {
        mvm_core::residency::ResidencyKind::Parked if vz_snapshot_present => {
            "parked (snapshot present)"
        }
        mvm_core::residency::ResidencyKind::Parked => "parked (no snapshot)",
        _ if persistent_active => "persistent builder active",
        _ if vz_snapshot_present => "parked snapshot present",
        _ => "no persistent builder",
    }
}

/// Stub when the `builder-vm` feature is off.
#[cfg(not(feature = "builder-vm"))]
fn builder_residency_check() -> Check {
    Check {
        name: "builder residency",
        category: "platform",
        ok: true,
        info: "n/a (mvm-cli built without `builder-vm` feature)".to_string(),
    }
}

/// TypeScript runner probe — `mvmctl compile <script.ts>` auto-runs
/// the script on the host with `MVM_SDK_MODE=record` and lowers the
/// emitted recording into a Workload. That path needs a TS-aware
/// runner (`tsx`, `bun`, or `deno`); plain `node` can't execute `.ts`
/// in mvm's supported Node range.
///
/// **WARN (not FAIL) when missing.** A TS runner is only required if
/// the user actually runs `mvmctl compile` on a `.ts` script — most
/// mvm workflows (Python, IR-JSON, decorator-only TS) don't need one.
/// Doctor surfaces the install hint so the gap is discoverable, but
/// `mvmctl doctor` still exits 0 to avoid breaking CI on hosts that
/// genuinely don't want a Node toolchain.
///
/// Probe is cheap: at most three `which::which` lookups plus one
/// cwd-relative `is_file` per runner — no subprocesses.
fn ts_runner_check() -> Check {
    // Project-local resolution wins over PATH — see
    // `crate::ts_runner` module docs for the full order.
    if let Some(p) = crate::ts_runner::project_local() {
        return Check {
            name: "TypeScript runner",
            category: "tools",
            ok: true,
            info: format!(
                "project-local at {} (used by `mvmctl compile <script.ts>`)",
                p.display()
            ),
        };
    }
    if let Some(p) = crate::ts_runner::on_path() {
        return Check {
            name: "TypeScript runner",
            category: "tools",
            ok: true,
            info: format!(
                "{} on PATH ({})",
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("<unknown>"),
                p.display()
            ),
        };
    }
    Check {
        name: "TypeScript runner",
        category: "tools",
        // `ok: true` is the WARN posture — doctor reports the gap in
        // the `info` field but does not exit nonzero. The install
        // hint is verbose on purpose; this is the one place users
        // discover the project-local + global recipes.
        ok: true,
        info: format!(
            "not found — {} (only required if you run `mvmctl compile <script.ts>`)",
            crate::ts_runner::install_hint()
        ),
    }
}

fn disk_space_check(in_vm: bool) -> Check {
    let result = if in_vm {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    } else if cfg!(target_os = "macos") {
        parse_disk_space("df -g ~ 2>/dev/null")
    } else {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    };

    match result {
        Some(gib) if gib >= 10 => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: format!("{} GiB free", gib),
        },
        Some(gib) => Check {
            name: "disk space",
            category: "platform",
            ok: false,
            info: format!("only {} GiB free (10 GiB recommended)", gib),
        },
        None => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: "unable to determine (skipped)".to_string(),
        },
    }
}

/// Parse free disk space in GiB from `df` output.
/// Expects the 4th column of the 2nd line to be the available space with a G suffix.
fn parse_disk_space(cmd: &str) -> Option<u64> {
    let output = shell::run_host("bash", &["-c", cmd]).ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let avail = line.split_whitespace().nth(3)?;
    let num_str = avail.trim_end_matches('G').trim_end_matches('i');
    num_str.parse().ok()
}

// ── Nix checks ────────────────────────────────────────────────────────────

/// Minimum Nix version for flake support (nix build with flakes).
const NIX_MIN_VERSION: (u64, u64) = (2, 4);
/// Recommended Nix version for best flake support.
const NIX_RECOMMENDED_VERSION: (u64, u64) = (2, 13);

/// Check Nix version and validate it meets minimum requirements.
///
/// Always probes the dev VM — nix is never expected on the host. The
/// caller in `run()` gates this on [`dev_vm_running`]; calling it when
/// the dev VM is down will return an error `Check`.
fn nix_version_check() -> Check {
    let output_result = shell::run_on_vm(VM_NAME, "nix --version");

    match output_result {
        Ok(out) if out.status.success() => {
            let version_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match parse_nix_version(&version_str) {
                Some((major, minor, patch)) => {
                    if (major, minor) < NIX_MIN_VERSION {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: false,
                            info: format!(
                                "{}.{}.{} (requires >= {}.{}+ for flakes)",
                                major, minor, patch, NIX_MIN_VERSION.0, NIX_MIN_VERSION.1
                            ),
                        }
                    } else if (major, minor) < NIX_RECOMMENDED_VERSION {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: true,
                            info: format!(
                                "{}.{}.{} (OK, but >= {}.{} recommended)",
                                major,
                                minor,
                                patch,
                                NIX_RECOMMENDED_VERSION.0,
                                NIX_RECOMMENDED_VERSION.1
                            ),
                        }
                    } else {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: true,
                            info: format!("{}.{}.{}", major, minor, patch),
                        }
                    }
                }
                None => Check {
                    name: "nix",
                    category: "tools",
                    ok: true,
                    info: format!("{} (version not parsed)", version_str),
                },
            }
        }
        Ok(out) => Check {
            name: "nix",
            category: "tools",
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name: "nix",
            category: "tools",
            ok: false,
            info: e.to_string(),
        },
    }
}

/// Parse "nix (Nix) 2.18.1" or "nix (Nix) 2.24.12 pre-20241211_dirty" into (major, minor, patch).
fn parse_nix_version(output: &str) -> Option<(u64, u64, u64)> {
    // Find the version number after "Nix) " or just the last space-separated token
    let version_part = output
        .split_whitespace()
        .find(|s| s.chars().next().is_some_and(|c| c.is_ascii_digit()))?;

    let mut parts = version_part.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // Patch may have suffix like "12pre-20241211_dirty"
    let patch_str = parts.next().unwrap_or("0");
    let patch = patch_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Check that Nix flake support is enabled (experimental-features includes
/// nix-command and flakes). Always probes the dev VM; gated on
/// [`dev_vm_running`] by the caller.
fn nix_flakes_check() -> Check {
    let cmd = "nix show-config 2>/dev/null | grep -i experimental-features || echo 'not found'";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let has_flakes = stdout.contains("flakes");
            let has_nix_command = stdout.contains("nix-command");
            if has_flakes && has_nix_command {
                Check {
                    name: "nix flakes",
                    category: "tools",
                    ok: true,
                    info: "enabled".to_string(),
                }
            } else {
                let mut missing = Vec::new();
                if !has_nix_command {
                    missing.push("nix-command");
                }
                if !has_flakes {
                    missing.push("flakes");
                }
                Check {
                    name: "nix flakes",
                    category: "tools",
                    ok: false,
                    info: format!(
                        "missing experimental-features: {}. Add to ~/.config/nix/nix.conf",
                        missing.join(", ")
                    ),
                }
            }
        }
        _ => Check {
            name: "nix flakes",
            category: "tools",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

// ── Nix store health ──────────────────────────────────────────────────────

/// Check Nix store accessibility via `nix store ping`. Always probes the
/// dev VM; gated on [`dev_vm_running`] by the caller.
fn nix_store_check() -> Check {
    let cmd = "nix store ping 2>&1";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // nix store ping outputs "Store URL: daemon" or similar
            let store_url = stdout
                .lines()
                .find(|l| l.contains("Store URL"))
                .map(|l| l.trim().to_string())
                .unwrap_or_else(|| "accessible".to_string());
            Check {
                name: "nix store",
                category: "tools",
                ok: true,
                info: store_url,
            }
        }
        Ok(_) => Check {
            name: "nix store",
            category: "tools",
            ok: false,
            info: "Nix store not accessible. Is the Nix daemon running?".to_string(),
        },
        _ => Check {
            name: "nix store",
            category: "tools",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

/// Check Nix store size and warn if it exceeds 20 GiB. Always probes the
/// dev VM; gated on [`dev_vm_running`] by the caller.
fn nix_store_size_check() -> Check {
    let cmd = "du -sb /nix/store 2>/dev/null | awk '{print $1}'";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let bytes: u64 = stdout.trim().parse().unwrap_or(0);
            let threshold: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
            let human = mvm_core::pool::format_bytes(bytes);
            if bytes > threshold {
                Check {
                    name: "nix store size",
                    category: "disk",
                    ok: false,
                    info: format!(
                        "{} — exceeds 20 GiB. Run 'nix-collect-garbage -d' to reclaim space.",
                        human
                    ),
                }
            } else {
                Check {
                    name: "nix store size",
                    category: "disk",
                    ok: true,
                    info: human,
                }
            }
        }
        _ => Check {
            name: "nix store size",
            category: "disk",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

// ── Security posture (folded in from the old `mvmctl security`) ─────

fn security_audit_log_check() -> Check {
    let path = mvm_core::audit::default_audit_log();
    let exists = std::path::Path::new(&path).exists();
    Check {
        name: "audit log",
        category: "security",
        ok: true, // informational
        info: if exists {
            format!("present at {path}")
        } else {
            format!("not yet created at {path}")
        },
    }
}

/// Host full-disk-encryption check for encryption at rest.
///
/// `LocalBackend` volumes rely on host FDE for at-rest protection (we
/// deliberately don't roll our own per-volume crypto on dev boxes).
/// On a dev host this check is **informational/warning-only** — the
/// `ok` flag stays `true` so a non-FDE laptop can still run mvmctl,
/// but the report surfaces the gap so users can enable FileVault /
/// LUKS before relying on local volumes for sensitive data.
///
/// On mvmd workers the analogous check is **enforced** (refuses
/// `LocalVirtiofs` bucket creation when FDE is absent).
fn security_host_fde_check() -> Check {
    let detection = detect_host_fde_status();
    Check {
        name: "host FDE (volumes at-rest)",
        category: "security",
        ok: true, // warn-only on a dev box
        info: detection.info,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostFdeStatus {
    pub(crate) enabled: bool,
    pub(crate) info: String,
}

impl HostFdeStatus {
    fn enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: true,
            info: info.into(),
        }
    }

    fn not_enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: false,
            info: info.into(),
        }
    }
}

/// Enforce encrypted backing for a LocalBackend volume mount.
///
/// Local virtio-fs volumes are plaintext while mounted in the guest, so the
/// backing directory itself must live on an encrypted filesystem or encrypted
/// device. Unknown detection fails closed here because mounting the volume is
/// the point where mvm would otherwise expose sensitive local data without the
/// documented at-rest guarantee.
pub(crate) fn require_local_volume_host_path_encrypted(path: &std::path::Path) -> Result<()> {
    let status = detect_host_path_encryption_status(path);
    if status.enabled {
        return Ok(());
    }
    anyhow::bail!(
        "LocalBackend volume mounts require the mounted host directory to live \
         on encrypted backing storage. {}",
        status.info
    )
}

pub(crate) fn detect_host_path_encryption_status(path: &std::path::Path) -> HostFdeStatus {
    let plat = platform::current();
    if matches!(plat, Platform::MacOS) {
        match std::process::Command::new("diskutil")
            .arg("info")
            .arg(path)
            .output()
        {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_macos_diskutil_encryption_status(path, &stdout)
            }
            _ => HostFdeStatus::not_enabled(format!(
                "could not determine encryption state for {} (diskutil unavailable)",
                path.display()
            )),
        }
    } else if matches!(plat, Platform::LinuxNative | Platform::LinuxNoKvm) {
        match std::process::Command::new("findmnt")
            .args(["-no", "SOURCE", "-T"])
            .arg(path)
            .output()
        {
            Ok(out) if out.status.success() => {
                let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match std::process::Command::new("lsblk")
                    .args(["-no", "TYPE", &dev])
                    .output()
                {
                    Ok(types) if types.status.success() => {
                        let s = String::from_utf8_lossy(&types.stdout);
                        parse_linux_volume_backing_types(path, &dev, &s)
                    }
                    _ => HostFdeStatus::not_enabled(format!(
                        "could not inspect block-device type chain for {} ({dev})",
                        path.display()
                    )),
                }
            }
            _ => HostFdeStatus::not_enabled(format!(
                "could not determine backing device for {} (findmnt unavailable)",
                path.display()
            )),
        }
    } else {
        HostFdeStatus::not_enabled("unsupported platform for encrypted-volume detection")
    }
}

/// Best-effort detection of host full-disk encryption.
///
/// macOS: `fdesetup status` returns "FileVault is On." when enabled.
/// Linux: `lsblk -no TYPE / 2>&1 | grep crypt` succeeds when the root
/// FS sits on a dm-crypt mapping. Both checks fail closed (return
/// "unknown") if the underlying tool is missing.
pub(crate) fn detect_host_fde_status() -> HostFdeStatus {
    let plat = platform::current();
    if matches!(plat, Platform::MacOS) {
        match std::process::Command::new("fdesetup")
            .arg("status")
            .output()
        {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_filevault_status(&stdout)
            }
            Ok(_) | Err(_) => HostFdeStatus::not_enabled(
                "could not determine FileVault state (fdesetup unavailable)",
            ),
        }
    } else if matches!(plat, Platform::LinuxNative | Platform::LinuxNoKvm) {
        match std::process::Command::new("findmnt")
            .args(["-no", "SOURCE", "/"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match std::process::Command::new("lsblk")
                    .args(["-no", "TYPE", &dev])
                    .output()
                {
                    Ok(types) if types.status.success() => {
                        let s = String::from_utf8_lossy(&types.stdout);
                        parse_linux_block_types(&dev, &s)
                    }
                    _ => HostFdeStatus::not_enabled(format!(
                        "could not inspect type chain for {dev}"
                    )),
                }
            }
            _ => {
                HostFdeStatus::not_enabled("could not determine root device (findmnt unavailable)")
            }
        }
    } else {
        HostFdeStatus::not_enabled("unsupported platform for FDE detection")
    }
}

fn parse_filevault_status(stdout: &str) -> HostFdeStatus {
    if stdout.contains("FileVault is On") {
        HostFdeStatus::enabled("FileVault enabled (LocalBackend volumes encrypted at rest)")
    } else {
        HostFdeStatus::not_enabled(format!(
            "FileVault appears OFF — run `sudo fdesetup enable` before storing \
             sensitive data in LocalBackend volumes ({})",
            stdout.trim()
        ))
    }
}

fn parse_linux_block_types(dev: &str, types: &str) -> HostFdeStatus {
    if types.lines().any(|l| l.trim() == "crypt") {
        HostFdeStatus::enabled(format!(
            "root device {dev} sits on a dm-crypt mapping (LUKS enabled; \
             LocalBackend volumes encrypted at rest)"
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "root device {dev} does NOT appear to be encrypted — enable LUKS \
             on root before storing sensitive data in LocalBackend volumes"
        ))
    }
}

fn parse_linux_volume_backing_types(
    path: &std::path::Path,
    dev: &str,
    types: &str,
) -> HostFdeStatus {
    if types.lines().any(|l| l.trim() == "crypt") {
        HostFdeStatus::enabled(format!(
            "{} is backed by {dev}, which sits on a dm-crypt/LUKS mapping",
            path.display()
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "{} is backed by {dev}, which does NOT appear to sit on a \
             dm-crypt/LUKS mapping",
            path.display()
        ))
    }
}

fn parse_macos_diskutil_encryption_status(
    path: &std::path::Path,
    diskutil_output: &str,
) -> HostFdeStatus {
    for line in diskutil_output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().to_ascii_lowercase();
        let encrypted = value.starts_with("yes") || value.starts_with("encrypted");
        if matches!(key, "FileVault" | "Encrypted") && encrypted {
            return HostFdeStatus::enabled(format!(
                "{} is on a macOS volume reported as encrypted ({key}: {})",
                path.display(),
                value
            ));
        }
    }
    HostFdeStatus::not_enabled(format!(
        "{} is not on a macOS volume reported as encrypted by diskutil",
        path.display()
    ))
}

/// `~/.mvm` should be mode 0700. The XDG share directory
/// (`mvm_share_dir`) lands at the OS default mode (0755 on macOS Tahoe);
/// the data dir (`mvm_data_dir`) is the one the security model owns.
fn security_data_dir_mode_check() -> Check {
    let dir = mvm_core::config::mvm_data_dir();
    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        return Check {
            name: "data dir mode",
            category: "security",
            ok: false,
            info: format!("not present at {dir} — run `mvmctl bootstrap`"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        Check {
            name: "data dir mode",
            category: "security",
            ok: mode == expected,
            info: if mode == expected {
                format!("0{mode:o} at {dir}")
            } else {
                format!("expected 0{expected:o}, got 0{mode:o} at {dir}")
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "data dir mode",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// Dev VM vsock proxy socket should be mode 0700.
fn security_proxy_socket_mode_check() -> Check {
    let path = format!(
        "{}/vms/mvm-dev/vsock.sock",
        mvm_core::config::mvm_share_dir()
    );
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Check {
            name: "vsock socket mode",
            category: "security",
            ok: true,
            info: format!("dev VM not running (no socket at {path})"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        Check {
            name: "vsock socket mode",
            category: "security",
            ok: mode == expected,
            info: if mode == expected {
                format!("0{mode:o}")
            } else {
                format!(
                    "expected 0{expected:o}, got 0{mode:o} — same-host other users may have access"
                )
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "vsock socket mode",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// Cached pre-built dev image presence (informational; absence triggers
/// a hash-verified download).
fn security_dev_image_check() -> Check {
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_dir = format!("{}/prebuilt/v{version}", mvm_core::config::mvm_share_dir());
    let kernel = format!("{prebuilt_dir}/vmlinux");
    let rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    let cached = std::path::Path::new(&kernel).exists() && std::path::Path::new(&rootfs).exists();
    Check {
        name: "pre-built dev image",
        category: "security",
        ok: true,
        info: if cached {
            format!("cached at {prebuilt_dir}")
        } else {
            "not cached; next `mvmctl bootstrap` will download + hash-verify".to_string()
        },
    }
}

/// `deny.toml` at the workspace root (supply-chain policy).
fn security_deny_config_check() -> Check {
    let cwd = std::env::current_dir().ok();
    let found = cwd.as_deref().and_then(|start| {
        let mut cur: Option<&std::path::Path> = Some(start);
        while let Some(p) = cur {
            if p.join("deny.toml").exists() && p.join("Cargo.toml").exists() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
        None
    });
    Check {
        name: "cargo-deny policy",
        category: "security",
        ok: true,
        info: match found {
            Some(p) => format!("deny.toml at {}", p.display()),
            None => "deny.toml not found from cwd (expected only in source checkouts)".to_string(),
        },
    }
}

fn security_default_network_check() -> Check {
    let path = mvm_core::dev_network::network_path("default");
    let exists = std::path::Path::new(&path).exists();
    Check {
        name: "default dev network",
        category: "security",
        ok: true,
        info: if exists {
            "configured".to_string()
        } else {
            "not configured — run `mvmctl network create default`".to_string()
        },
    }
}

/// Claim 10: *no untrusted workload reaches the network unless
/// explicitly admitted by policy.* `NetworkPolicy::default()` is
/// `deny_all()` rather than `unrestricted()`, so the safe posture is
/// the one workloads get without opting in. This check makes the
/// runtime default visible in `mvmctl doctor` so the claim is
/// observably enforced rather than implicit in the codepath.
///
/// Pure read of the policy default — no I/O, no platform branching.
/// A future regression that flipped the default back to `unrestricted`
/// would surface here loudly.
fn security_network_policy_default_check() -> Check {
    use mvm_core::policy::network_policy::NetworkPolicy;
    let default = NetworkPolicy::default();
    // `NetworkPolicy::deny_all()` constructs the canonical deny-all
    // shape; equality against that is the load-bearing assertion.
    // Comparing against the constructor rather than introspecting
    // variants keeps this check resilient to future variant adds.
    let is_deny_all = default == NetworkPolicy::deny_all();
    Check {
        name: "network policy default (claim 10)",
        category: "security",
        ok: is_deny_all,
        info: if is_deny_all {
            "deny_all (claim 10 holds — egress refused unless explicitly admitted)".to_string()
        } else {
            "unrestricted — claim 10 does NOT hold; ADR-002 §10 regression. \
             Workloads boot with open egress unless --network-preset is set explicitly."
                .to_string()
        },
    }
}

/// `~/.mvm/snapshot.key` should be mode 0600.
///
/// Absence is informational — the file is created lazily on first
/// snapshot seal. Existence with looser perms is a security finding:
/// any local user could read the key and forge sidecars.
fn security_snapshot_key_check() -> Check {
    let path = mvm_core::crypto::snapshot_hmac::default_key_path(std::path::Path::new(
        &mvm_core::config::mvm_data_dir(),
    ));
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: true,
            info: format!(
                "not yet created at {} (lazy — created on first snapshot seal)",
                path.display()
            ),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o600;
        let len_ok = meta.len() == mvm_core::crypto::snapshot_hmac::HMAC_KEY_BYTES as u64;
        Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: mode == expected && len_ok,
            info: if mode != expected {
                format!(
                    "expected mode 0{expected:o}, got 0{mode:o} at {} — \
                     a local-user-readable HMAC key can be used to forge sidecars",
                    path.display()
                )
            } else if !len_ok {
                format!(
                    "key file at {} is {} bytes (expected {}) — corrupt; rotate by deleting the file",
                    path.display(),
                    meta.len(),
                    mvm_core::crypto::snapshot_hmac::HMAC_KEY_BYTES
                )
            } else {
                format!("0{mode:o} at {}", path.display())
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// All template snapshot directories should be mode 0700.
/// Walks `~/.mvm/templates/*/artifacts/*/snapshot/`,
/// reports the first looser-perm directory found (or "all OK" /
/// "none built yet" otherwise).
fn security_snapshot_dirs_check() -> Check {
    let templates_dir = mvm_core::domain::template::templates_base_dir();
    let templates_path = std::path::Path::new(&templates_dir);
    if !templates_path.exists() {
        return Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!("no templates directory at {templates_dir}"),
        };
    }

    let mut total = 0u32;
    let mut bad: Option<(std::path::PathBuf, u32)> = None;
    if let Ok(entries) = std::fs::read_dir(templates_path) {
        for tpl in entries.flatten() {
            let artifacts = tpl.path().join("artifacts");
            let Ok(rev_entries) = std::fs::read_dir(&artifacts) else {
                continue;
            };
            for rev in rev_entries.flatten() {
                let snap = rev.path().join("snapshot");
                if !snap.is_dir() {
                    continue;
                }
                total += 1;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::symlink_metadata(&snap) {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode != 0o700 && bad.is_none() {
                            bad = Some((snap, mode));
                        }
                    }
                }
            }
        }
    }

    if total == 0 {
        return Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!("no snapshots built yet under {templates_dir}"),
        };
    }
    match bad {
        Some((path, mode)) => Check {
            name: "snapshot dir mode",
            category: "security",
            ok: false,
            info: format!(
                "expected 0700, got 0{mode:o} at {} (1 of {total} snapshot dir{}; \
                 looser perms let local users tamper with snapshots)",
                path.display(),
                if total == 1 { "" } else { "s" }
            ),
        },
        None => Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!(
                "0700 across {total} snapshot dir{}",
                if total == 1 { "" } else { "s" }
            ),
        },
    }
}

/// macOS-only: every sign target (mvmctl plus the supervisor binaries) needs
/// the VZ and Hypervisor entitlements. Probes all paths from
/// `collect_sign_targets` so an unsigned supervisor is not left unreported.
/// Off macOS the check is n/a (returns the early-exit n/a `Check`).
fn security_signing_check() -> Check {
    use mvm_backend::codesign::{collect_sign_targets, entitlements_present};
    let targets = collect_sign_targets();
    // `entitlements_present` returns `None` off macOS for every path, so if
    // the first target gives `None` the whole check is n/a.
    let probed: Vec<(std::path::PathBuf, Option<bool>)> = targets
        .into_iter()
        .map(|p| {
            let r = entitlements_present(&p);
            (p, r)
        })
        .collect();
    signing_check_from_probes(&probed)
}

/// Pure mapping: per-target probe results → Check. Separate so tests can
/// drive it with fixture data without invoking codesign or the filesystem.
fn signing_check_from_probes(probes: &[(std::path::PathBuf, Option<bool>)]) -> Check {
    // All None → not on macOS; the question is n/a.
    if probes.iter().all(|(_, r)| r.is_none()) {
        return Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "n/a (macOS only)".to_string(),
        };
    }
    // Collect names of targets that are verifiably unsigned (Some(false)).
    let unsigned: Vec<String> = probes
        .iter()
        .filter_map(|(p, r)| {
            if *r == Some(false) {
                Some(
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>")
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect();
    if unsigned.is_empty() {
        Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "VZ + Hypervisor entitlements present on all sign targets".to_string(),
        }
    } else {
        Check {
            name: "signing",
            category: "security",
            ok: false,
            info: format!(
                "entitlements missing on: {} — run `mvmctl sign`",
                unsigned.join(", ")
            ),
        }
    }
}

/// Pinned cross-compile toolchain versions, parsed at build time from
/// the workspace's [workspace.metadata.mvm.toolchain] block.
pub struct ZigbuildProbe {
    pub pinned_zig: String,
    pub pinned_cargo_zigbuild: String,
    pub pinned_target: String,
    pub installed_zig: Option<String>,
    pub installed_cargo_zigbuild: Option<String>,
}

/// Read the pinned versions baked in at compile time and probe the
/// installed versions on the host. Used by `mvmctl doctor` to warn
/// when contributor toolchain drifts from the pin.
pub fn probe_zigbuild() -> ZigbuildProbe {
    ZigbuildProbe {
        pinned_zig: env!("MVM_PINNED_ZIG").to_string(),
        pinned_cargo_zigbuild: env!("MVM_PINNED_CARGO_ZIGBUILD").to_string(),
        pinned_target: env!("MVM_PINNED_TARGET").to_string(),
        installed_zig: which_version("zig", &["version"]),
        installed_cargo_zigbuild: which_version("cargo-zigbuild", &["--version"]),
    }
}

/// Returns the trimmed stdout of `cmd <args...>` when the process
/// runs and exits 0; returns `None` for any failure mode (binary
/// not found, non-zero exit, non-UTF-8 output). Used by tool-presence
/// probes where "I couldn't ask the tool its version" is reported
/// as "not usefully installed" — the caller surfaces that to the
/// doctor output, not as a hard error.
fn which_version(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_struct_reports_ok() {
        let c = Check {
            name: "test-tool",
            category: "tools",
            ok: true,
            info: "1.0.0".to_string(),
        };
        assert!(c.ok);
        assert_eq!(c.name, "test-tool");
    }

    #[test]
    fn check_struct_reports_missing() {
        let c = Check {
            name: "missing-tool",
            category: "tools",
            ok: false,
            info: "not found".to_string(),
        };
        assert!(!c.ok);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_lease_is_ok_and_names_ip() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Lease {
            ip: "192.168.127.3".to_string(),
        });
        assert_eq!(c.name, "builder egress");
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(c.info.contains("DHCP lease 192.168.127.3"));
        assert!(c.info.contains("builder egress path"));
        assert!(c.info.contains("fail-closed"), "posture appended");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_static_fallback_is_ok_but_degraded() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::StaticFallback {
            ip: "192.168.127.3".to_string(),
        });
        assert!(c.ok);
        assert!(c.info.contains("static fallback 192.168.127.3"));
        assert!(c.info.contains("degraded but reachable"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_failed_is_not_ok() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Failed);
        assert!(!c.ok);
        assert!(c.info.contains("FAILED"));
        assert!(c.info.contains("can't fetch"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_unknown_is_ok() {
        use mvm_build::guest_net::BuilderNetBootstrap;
        let c = builder_egress_check_from_outcome(BuilderNetBootstrap::Unknown);
        assert!(c.ok);
        assert!(c.info.contains("not yet recorded"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_check_reports_no_vm_when_console_log_absent() {
        use mvm_core::util::test_env::TestEnv;
        // With MVM_CACHE_DIR pointed at an empty dir there is no
        // persistent builder console.log, so the check reports the
        // no-VM-yet info and exits ok.
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", scratch.path());
        let c = builder_egress_check();
        assert!(c.ok);
        assert!(c.info.contains("no builder VM yet"));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_egress_check_classifies_a_fixture_console_log() {
        use mvm_core::util::test_env::TestEnv;
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", scratch.path());
        // Materialize a fixture console.log at the exact path the helper
        // resolves, then assert the lease is read end-to-end.
        let log = mvm_core::config::vm_state_dir("mvm-dev").join("console.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(
            &log,
            "udhcpc: lease of 192.168.127.3 obtained from 192.168.127.1, lease time 3600\n",
        )
        .unwrap();
        let c = builder_egress_check();
        assert!(c.ok);
        assert!(c.info.contains("DHCP lease 192.168.127.3"));
    }

    #[test]
    fn check_cmd_rustup_on_host() {
        let c = check_cmd("rustup", "tools", &["--version"]);
        assert!(c.ok, "rustup should be available: {}", c.info);
        assert!(
            c.info.contains("rustup"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_cargo_on_host() {
        let c = check_cmd("cargo", "tools", &["--version"]);
        assert!(c.ok, "cargo should be available: {}", c.info);
        assert!(
            c.info.contains("cargo"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_missing_tool() {
        let c = check_cmd("nonexistent-mvm-tool-xyz", "tools", &["--version"]);
        assert!(!c.ok, "nonexistent tool should fail");
    }

    #[test]
    fn fc_target_version_is_nonempty() {
        let v = mvm_core::config::fc_version();
        assert!(!v.is_empty(), "FC version should be configured");
        assert!(
            v.starts_with('v'),
            "FC version should start with 'v': {}",
            v
        );
    }

    #[test]
    fn platform_description_covers_all_variants() {
        assert!(platform_description(Platform::MacOS).contains("macOS"));
        assert!(platform_description(Platform::LinuxNative).contains("KVM"));
        assert!(platform_description(Platform::LinuxNoKvm).contains("without KVM"));
    }

    // ── signing_check_from_probes unit tests ────────────────────────

    #[test]
    fn signing_check_all_none_is_na() {
        // Off macOS every probe returns None → n/a, ok: true.
        let probes = vec![(std::path::PathBuf::from("/usr/local/bin/mvmctl"), None)];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok);
        assert!(c.info.contains("n/a"), "expected n/a, got: {}", c.info);
    }

    #[test]
    fn signing_check_all_signed_is_ok() {
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(true),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok, "all signed → ok; got: {}", c.info);
        assert!(
            c.info.contains("all sign targets"),
            "expected 'all sign targets', got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_one_unsigned_supervisor_is_not_ok() {
        // mvmctl signed, supervisor unsigned — doctor must NOT report OK.
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(false),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(!c.ok, "unsigned supervisor must fail; got: {}", c.info);
        assert!(
            c.info.contains("mvm-hvf-supervisor"),
            "info must name the unsigned target; got: {}",
            c.info
        );
        assert!(
            c.info.contains("mvmctl sign"),
            "info must carry the remediation hint; got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_mixed_none_and_false_treats_false_as_unsigned() {
        // Some targets return None (probe failed / tooling unavailable),
        // others return Some(false) (verifiably unsigned). The None ones
        // must not be counted as "unsigned" — only confirmed Some(false)
        // targets appear in the remediation list.
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-libkrun-supervisor"),
                None,
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(false),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(!c.ok, "at least one Some(false) → not ok; got: {}", c.info);
        assert!(
            c.info.contains("mvm-hvf-supervisor"),
            "must name the unsigned binary; got: {}",
            c.info
        );
        assert!(
            !c.info.contains("mvm-libkrun-supervisor"),
            "None probe must not be listed as unsigned; got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_all_unknown_probes_is_ok() {
        // All probes return None → on macOS this means codesign wasn't
        // available for every target (treated as "unknown, not a failure").
        // The n/a branch fires only when ALL are None.
        let probes = vec![
            (std::path::PathBuf::from("/usr/local/bin/mvmctl"), None),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                None,
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok, "all None → n/a, ok; got: {}", c.info);
    }

    #[test]
    fn parse_disk_space_typical_output() {
        let result = parse_disk_space(
            "printf 'Filesystem     1G-blocks  Used Available Use%% Mounted on\n/dev/sda1           100G   55G       45G  55%% /\n'",
        );
        assert_eq!(result, Some(45));
    }

    #[test]
    fn parse_nix_version_standard() {
        assert_eq!(parse_nix_version("nix (Nix) 2.18.1"), Some((2, 18, 1)));
    }

    #[test]
    fn parse_nix_version_with_suffix() {
        assert_eq!(
            parse_nix_version("nix (Nix) 2.24.12pre-20241211_dirty"),
            Some((2, 24, 12))
        );
    }

    #[test]
    fn parse_nix_version_old() {
        assert_eq!(parse_nix_version("nix (Nix) 2.3.16"), Some((2, 3, 16)));
    }

    #[test]
    fn parse_nix_version_garbage() {
        assert_eq!(parse_nix_version("not a version"), None);
    }

    #[test]
    fn parse_nix_version_empty() {
        assert_eq!(parse_nix_version(""), None);
    }

    #[test]
    fn nix_version_too_old_is_not_ok() {
        // Version 2.3.x is below minimum 2.4
        let (major, minor, _patch) = (2, 3, 16);
        assert!((major, minor) < NIX_MIN_VERSION);
        // Verify the logic matches what nix_version_check would produce
        assert!(
            (major, minor) < NIX_MIN_VERSION,
            "2.3 should be below minimum"
        );
    }

    #[test]
    fn nix_version_at_minimum_is_ok() {
        let (major, minor) = (2, 4);
        assert!((major, minor) >= NIX_MIN_VERSION);
    }

    #[test]
    fn nix_version_at_recommended_is_ok() {
        let (major, minor) = (2, 13);
        assert!((major, minor) >= NIX_RECOMMENDED_VERSION);
    }

    #[test]
    fn collect_balloon_support_advertises_firecracker() {
        let support = collect_balloon_support();
        // The backend catalog must include Firecracker in the balloon
        // support matrix. If a future refactor drops it, this fails
        // loudly.
        assert_eq!(support.get("firecracker"), Some(&true));
        // And honestly-`false` backends should not be silently dropped.
        assert_eq!(support.get("qemu"), Some(&false));
    }

    #[test]
    fn collect_balloon_support_keeps_catalog_backends_in_stable_order() {
        let support = collect_balloon_support();
        let ordered: Vec<_> = support.into_iter().collect();
        assert_eq!(
            ordered,
            vec![
                ("firecracker".to_string(), true),
                ("libkrun".to_string(), false),
                ("qemu".to_string(), false),
            ]
        );
    }

    #[test]
    fn collect_warm_start_support_reports_per_backend_tier() {
        let r = collect_warm_start_support();
        // The honest per-backend warm-start matrix.
        assert_eq!(r.backends.get("firecracker"), Some(&"live-memory"));
        assert_eq!(r.backends.get("libkrun"), Some(&"disk-only"));
        assert_eq!(r.backends.get("qemu"), Some(&"disk-only"));
    }

    #[test]
    fn collect_warm_start_support_keeps_catalog_backends_in_stable_order() {
        let r = collect_warm_start_support();
        let ordered_backends: Vec<_> = r.backends.into_iter().collect();
        let ordered_standby_pool: Vec<_> = r.standby_pool.into_iter().collect();

        assert_eq!(
            ordered_backends,
            vec![
                ("firecracker".to_string(), "live-memory"),
                ("libkrun".to_string(), "disk-only"),
                ("qemu".to_string(), "disk-only"),
            ]
        );
        assert_eq!(
            ordered_standby_pool,
            vec![
                ("firecracker".to_string(), true),
                ("libkrun".to_string(), true),
                ("qemu".to_string(), false),
            ]
        );
    }

    #[test]
    fn collect_warm_start_support_reports_standby_pool_per_backend() {
        let r = collect_warm_start_support();
        // Firecracker and libkrun implement the standby pool; QEMU does not.
        // Report honest values for every backend; none may be silently dropped.
        assert_eq!(r.standby_pool.get("firecracker"), Some(&true));
        assert_eq!(r.standby_pool.get("libkrun"), Some(&true));
        assert_eq!(r.standby_pool.get("qemu"), Some(&false));
    }

    #[test]
    fn collect_capability_table_reports_per_backend_dispositions() {
        let rows = collect_capability_table();
        let by = |name: &str| rows.iter().find(|r| r.backend == name).cloned();

        // The Tier 3 `mock` test double is excluded; the three real
        // backends are present, in stable name order.
        let names: Vec<_> = rows.iter().map(|r| r.backend.as_str()).collect();
        assert_eq!(names, vec!["firecracker", "libkrun", "qemu"]);

        let fc = by("firecracker").unwrap();
        assert_eq!(fc.snapshot_tier, "live-memory");
        assert!(fc.tap_networking, "firecracker uses a host TAP device");
        assert!(fc.vsock);
        assert!(fc.balloon);
        assert!(
            fc.standby_pool,
            "Firecracker implements live standby warm-spawn"
        );

        let krun = by("libkrun").unwrap();
        assert_eq!(krun.snapshot_tier, "disk-only");
        assert!(
            !krun.tap_networking,
            "libkrun uses a userspace gateway, not a host TAP"
        );
        assert!(krun.vsock);
        assert!(
            krun.standby_pool,
            "libkrun still pre-pays spawn latency through the supervisor pool"
        );

        let qemu = by("qemu").unwrap();
        assert_eq!(qemu.snapshot_tier, "disk-only");
        assert!(
            !qemu.tap_networking,
            "qemu uses user-mode slirp, not a host TAP"
        );
        assert!(qemu.vsock);
    }

    #[test]
    fn doctor_report_serializes_capability_table() {
        let json = serde_json::to_string(&DoctorReport {
            workflow: None,
            checks: vec![],
            security_posture: collect_security_posture(),
            balloon_support: collect_balloon_support(),
            warm_start: collect_warm_start_support(),
            capability_table: collect_capability_table(),
            all_ok: true,
        })
        .unwrap();
        assert!(json.contains("\"capability_table\""), "{json}");
        assert!(json.contains("\"snapshot_tier\""), "{json}");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn warm_start_substrate_is_none_off_linux() {
        // The NBD/HugeTLB fast-resume substrate is Linux-only; macOS reports
        // the per-backend tier but N/A for the substrate.
        assert!(collect_warm_start_support().substrate.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn warm_start_substrate_is_probed_on_linux() {
        // On Linux the substrate is probed (values depend on the host; we only
        // assert it's present, not loaded).
        assert!(collect_warm_start_support().substrate.is_some());
    }

    #[test]
    fn hugetlb_reserved_from_parses_count() {
        assert!(!hugetlb_reserved_from("0\n"));
        assert!(hugetlb_reserved_from("128\n"));
        assert!(!hugetlb_reserved_from("garbage"));
        assert!(!hugetlb_reserved_from(""));
    }

    #[test]
    fn nbd_module_loaded_at_detects_presence() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!nbd_module_loaded_at(tmp.path()));
        std::fs::create_dir(tmp.path().join("nbd")).unwrap();
        assert!(nbd_module_loaded_at(tmp.path()));
    }

    #[test]
    fn doctor_report_serializes_warm_start() {
        let json = serde_json::to_string(&DoctorReport {
            workflow: None,
            checks: vec![],
            security_posture: collect_security_posture(),
            balloon_support: collect_balloon_support(),
            warm_start: collect_warm_start_support(),
            capability_table: collect_capability_table(),
            all_ok: true,
        })
        .unwrap();
        assert!(json.contains("\"warm_start\""), "{json}");
        assert!(json.contains("\"live-memory\""), "{json}");
    }

    #[test]
    fn registry_drift_summary_reports_clean_and_counts() {
        use mvm::vm::reconcile::ConvergeReport;
        let clean = ConvergeReport::default();
        assert_eq!(registry_drift_summary(&clean), "clean");

        let mut drifted = ConvergeReport::default();
        drifted.dead_process_reaped.push("vm1".to_string());
        drifted.orphan_state_reaped.push("ghost".to_string());
        let s = registry_drift_summary(&drifted);
        assert!(s.starts_with("2 record(s) would be reconciled"), "{s}");
        assert!(s.contains("mvmctl reconcile"));
    }

    #[test]
    fn doctor_report_serializes_to_json() {
        let report = DoctorReport {
            workflow: None,
            checks: vec![Check {
                name: "test",
                category: "tools",
                ok: true,
                info: "v1.0".to_string(),
            }],
            security_posture: collect_security_posture(),
            balloon_support: collect_balloon_support(),
            warm_start: collect_warm_start_support(),
            capability_table: collect_capability_table(),
            all_ok: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"all_ok\":true"));
        assert!(json.contains("\"security_posture\""));
        assert!(json.contains("\"tier\""));
        // Default (no --workflow) omits the field entirely thanks to
        // `#[serde(skip_serializing_if = …)]`.
        assert!(
            !json.contains("\"workflow\""),
            "default report must not serialize the workflow field; got: {json}"
        );
    }

    #[test]
    fn doctor_report_serializes_workflow_when_set() {
        let report = DoctorReport {
            workflow: Some("bundle-run"),
            checks: vec![],
            security_posture: collect_security_posture(),
            balloon_support: collect_balloon_support(),
            warm_start: collect_warm_start_support(),
            capability_table: collect_capability_table(),
            all_ok: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"workflow\":\"bundle-run\""),
            "workflow-scoped report must serialize the field; got: {json}"
        );
    }

    #[test]
    fn collect_security_posture_returns_a_real_tier() {
        let posture = collect_security_posture();
        assert!(
            posture.tier == "Tier 1" || posture.tier == "Tier 2" || posture.tier == "Tier 3",
            "unexpected tier: {}",
            posture.tier
        );
        assert_eq!(posture.claims.len(), 7);
    }

    // ── Dev-VM gating + data-dir-mode routing tests ─────────────────
    //
    // These tests mutate `MVM_DATA_DIR` / `MVM_SHARE_DIR` (and the ts-runner
    // tests below, PATH / MVM_TSX) to redirect doctor's probes at a tempdir.
    // Env-var mutation is process-wide, so they all go through the shared
    // `TestEnv` guard, which serializes them behind one lock and restores the
    // prior values on drop.

    use mvm_core::util::test_env::TestEnv;

    struct EnvGuard {
        _env: mvm_core::util::test_env::TestEnv,
        _tmp_data: Option<tempfile::TempDir>,
        _tmp_share: Option<tempfile::TempDir>,
    }

    impl EnvGuard {
        fn new(data: Option<tempfile::TempDir>, share: Option<tempfile::TempDir>) -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            if let Some(d) = data.as_ref() {
                env.set("MVM_DATA_DIR", d.path());
            }
            if let Some(s) = share.as_ref() {
                env.set("MVM_SHARE_DIR", s.path());
            }
            EnvGuard {
                _env: env,
                _tmp_data: data,
                _tmp_share: share,
            }
        }
    }

    #[test]
    fn dev_vm_socket_path_uses_share_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let expected = format!("{}/vms/mvm-dev/vsock.sock", tmp.path().display());
        let _g = EnvGuard::new(None, Some(tmp));
        assert_eq!(dev_vm_socket_path(), expected);
    }

    #[test]
    fn dev_vm_running_is_false_when_no_socket() {
        let _g = EnvGuard::new(None, Some(tempfile::tempdir().unwrap()));
        assert!(
            !dev_vm_running(),
            "fresh tempdir has no vsock socket; dev_vm_running must be false"
        );
    }

    #[test]
    fn builder_tool_skipped_reports_ok_with_skip_marker() {
        let c = builder_tool_skipped("nix", "tools");
        assert!(c.ok, "skip is informational, not a failure");
        assert_eq!(c.name, "nix");
        assert_eq!(c.category, "tools");
        assert!(
            c.info.contains("dev VM not running"),
            "expected skip marker, got: {}",
            c.info
        );
    }

    #[test]
    fn kvm_check_on_macos_is_informational() {
        let c = kvm_check(Platform::MacOS, false);
        assert!(c.ok, "macOS kvm check must not fail: {}", c.info);
        assert!(
            c.info.contains("Hypervisor.framework"),
            "expected Hypervisor.framework rationale, got: {}",
            c.info
        );
    }

    #[cfg(unix)]
    #[test]
    fn security_data_dir_mode_check_reads_data_dir_not_share_dir() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        let share = tempfile::tempdir().unwrap();
        // data dir 0700 (the one we want checked), share dir 0755 (decoy).
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(share.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let _g = EnvGuard::new(Some(data), Some(share));
        let c = security_data_dir_mode_check();
        assert!(
            c.ok,
            "expected ok because data dir is 0700, got: {}",
            c.info
        );
        assert!(
            c.info.contains("0700"),
            "info should report the data dir's mode, got: {}",
            c.info
        );
    }

    #[test]
    fn ts_runner_check_reports_warn_posture_with_install_hint_when_missing() {
        // Force a clean lookup: no MVM_TSX pin, no project-local
        // ./node_modules/.bin, and (most critically) an empty PATH
        // so the host's own `tsx`/`bun`/`deno` can't make this test
        // flaky. The probe must still return `ok: true` (WARN, not
        // FAIL) so `mvmctl doctor` exits 0 on a host without a TS
        // runner.
        let mut env = TestEnv::new();
        let prev_cwd = std::env::current_dir().expect("cwd");
        let tmp = tempfile::tempdir().unwrap();
        env.set("PATH", "");
        env.remove("MVM_TSX");
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        // Restore cwd before any assert can fail (TestEnv restores PATH /
        // MVM_TSX on drop; cwd is restored manually).
        let _ = std::env::set_current_dir(&prev_cwd);
        drop(env);

        assert_eq!(c.name, "TypeScript runner");
        assert_eq!(c.category, "tools");
        assert!(
            c.ok,
            "TS-runner probe is WARN-only (informational), not FAIL: info={}",
            c.info
        );
        assert!(
            c.info.contains("not found"),
            "expected 'not found' marker, got: {}",
            c.info
        );
        // Install hint must be inlined so `mvmctl doctor` users
        // don't need to re-discover the per-OS recipe elsewhere.
        for s in ["tsx", "bun", "deno", "MVM_TSX"] {
            assert!(c.info.contains(s), "info missing {s:?}: {}", c.info);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ts_runner_check_reports_pass_when_project_local_present() {
        use std::os::unix::fs::PermissionsExt;
        let mut env = TestEnv::new();
        let prev_cwd = std::env::current_dir().expect("cwd");
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tsx = bin.join("tsx");
        std::fs::write(&tsx, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tsx, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.remove("MVM_TSX");
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        let _ = std::env::set_current_dir(&prev_cwd);
        drop(env);

        assert!(c.ok);
        assert!(
            c.info.contains("project-local"),
            "expected 'project-local' marker, got: {}",
            c.info
        );
    }

    #[test]
    fn security_network_policy_default_check_reports_claim_10_holding() {
        // Invariant: `NetworkPolicy::default()` returns
        // `deny_all`. If a future regression flips it back to
        // `unrestricted`, this check fails loudly in doctor — pinning
        // claim 10 against silent drift.
        let c = security_network_policy_default_check();
        assert_eq!(c.category, "security");
        assert!(c.ok, "claim 10 must hold; doctor saw: {}", c.info);
        assert!(
            c.info.contains("deny_all"),
            "info should call out deny_all; got: {}",
            c.info
        );
        assert!(
            c.info.contains("claim 10 holds"),
            "info should name claim 10 so operators searching the doctor \
             output for the claim find it; got: {}",
            c.info
        );
    }

    #[test]
    fn filevault_parser_accepts_on_status() {
        let status = parse_filevault_status("FileVault is On.\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("encrypted at rest"),
            "info should state the at-rest guarantee, got: {}",
            status.info
        );
    }

    #[test]
    fn filevault_parser_rejects_off_status() {
        let status = parse_filevault_status("FileVault is Off.\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("FileVault appears OFF"),
            "expected FileVault remediation, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_fde_parser_accepts_crypt_in_device_chain() {
        let status = parse_linux_block_types("/dev/mapper/cryptroot", "disk\npart\ncrypt\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("LUKS enabled"),
            "expected LUKS marker, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_fde_parser_rejects_plain_device_chain() {
        let status = parse_linux_block_types("/dev/nvme0n1p2", "disk\npart\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("does NOT appear to be encrypted"),
            "expected LUKS remediation, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_volume_backing_parser_accepts_crypt_chain() {
        let path = std::path::Path::new("/volumes/work");
        let status =
            parse_linux_volume_backing_types(path, "/dev/mapper/mvm-volume-work", "crypt\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("dm-crypt/LUKS"),
            "expected dm-crypt marker, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_volume_backing_parser_rejects_plain_chain() {
        let path = std::path::Path::new("/volumes/work");
        let status = parse_linux_volume_backing_types(path, "/dev/sda2", "disk\npart\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("does NOT appear"),
            "expected encrypted-backing refusal, got: {}",
            status.info
        );
    }

    #[test]
    fn macos_diskutil_parser_accepts_filevault_volume() {
        let path = std::path::Path::new("/Users/alice/volumes/work");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk3s1\nFileVault: Yes (Unlocked)\n",
        );
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("reported as encrypted"),
            "expected encrypted marker, got: {}",
            status.info
        );
    }

    #[test]
    fn macos_diskutil_parser_accepts_encrypted_volume() {
        let path = std::path::Path::new("/Volumes/secure-work");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk4s1\nEncrypted: Yes\n",
        );
        assert!(status.enabled, "expected enabled: {}", status.info);
    }

    #[test]
    fn macos_diskutil_parser_rejects_unencrypted_volume() {
        let path = std::path::Path::new("/Volumes/plain");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk4s1\nEncrypted: No\nFileVault: No\n",
        );
        assert!(!status.enabled, "expected disabled");
        assert!(
            status
                .info
                .contains("not on a macOS volume reported as encrypted"),
            "expected encrypted-backing refusal, got: {}",
            status.info
        );
    }

    // ---------------- Workflow scoping ----------------

    #[test]
    fn workflow_cli_run_includes_all_categories() {
        let cats = DoctorWorkflow::CliRun.relevant_categories();
        for expected in ["prerequisites", "tools", "platform", "security", "disk"] {
            assert!(
                cats.contains(&expected),
                "cli-run missing category {expected}"
            );
        }
    }

    #[test]
    fn workflow_python_and_typescript_sdk_match_cli_run() {
        // The SDK flows share the host requirements with `cli-run` —
        // both ultimately call `mvmctl up` / `mvmctl build` under the
        // hood. If this assertion ever drifts, that's a deliberate
        // workflow-specific check change that needs review.
        assert_eq!(
            DoctorWorkflow::CliRun.relevant_categories(),
            DoctorWorkflow::PythonSdk.relevant_categories()
        );
        assert_eq!(
            DoctorWorkflow::CliRun.relevant_categories(),
            DoctorWorkflow::TypescriptSdk.relevant_categories()
        );
    }

    #[test]
    fn workflow_bundle_run_drops_prerequisites_and_tools() {
        let cats = DoctorWorkflow::BundleRun.relevant_categories();
        assert!(
            !cats.contains(&"prerequisites"),
            "bundle-run must not gate on host rust"
        );
        assert!(
            !cats.contains(&"tools"),
            "bundle-run must not gate on builder VM tools"
        );
        for required in ["platform", "security", "disk"] {
            assert!(cats.contains(&required), "bundle-run needs {required}");
        }
    }

    #[test]
    fn workflow_dev_shell_drops_prerequisites_only() {
        let cats = DoctorWorkflow::DevShell.relevant_categories();
        assert!(
            !cats.contains(&"prerequisites"),
            "dev-shell must not gate on host rustup/cargo — the dev VM owns the toolchain"
        );
        // Dev shell DOES need builder-VM tools.
        assert!(cats.contains(&"tools"));
        assert!(cats.contains(&"platform"));
    }

    #[test]
    fn workflow_as_str_kebab_case() {
        assert_eq!(DoctorWorkflow::CliRun.as_str(), "cli-run");
        assert_eq!(DoctorWorkflow::PythonSdk.as_str(), "python-sdk");
        assert_eq!(DoctorWorkflow::TypescriptSdk.as_str(), "typescript-sdk");
        assert_eq!(DoctorWorkflow::BundleRun.as_str(), "bundle-run");
        assert_eq!(DoctorWorkflow::DevShell.as_str(), "dev-shell");
    }

    #[test]
    fn workflow_serde_renders_kebab_case() {
        // The `--workflow` flag and the JSON output need the same
        // kebab-case string, so the `Serialize` derive must match
        // the clap ValueEnum form. Pin both.
        let json = serde_json::to_string(&DoctorWorkflow::BundleRun).unwrap();
        assert_eq!(json, "\"bundle-run\"");
        let json = serde_json::to_string(&DoctorWorkflow::DevShell).unwrap();
        assert_eq!(json, "\"dev-shell\"");
    }

    /// Demonstrates the filter behavior: an irrelevant failed
    /// check is dropped from the workflow-scoped report.
    /// `BundleRun` skips `prerequisites`, so a failed `cargo`
    /// check shouldn't appear in a bundle-run-scoped run.
    #[test]
    fn workflow_filter_drops_irrelevant_failed_checks() {
        let all_checks = [
            Check {
                name: "cargo",
                category: "prerequisites",
                ok: false,
                info: "missing".into(),
            },
            Check {
                name: "platform",
                category: "platform",
                ok: true,
                info: "macOS".into(),
            },
        ];

        let workflow = DoctorWorkflow::BundleRun;
        let relevant = workflow.relevant_categories();
        let filtered: Vec<&Check> = all_checks
            .iter()
            .filter(|c| relevant.contains(&c.category))
            .collect();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "platform");
        // The previously-failing `cargo` check is now invisible, so
        // `all_ok` over the filtered set is `true`.
        let all_ok_filtered = filtered.iter().all(|c| c.ok);
        assert!(all_ok_filtered);
    }

    #[test]
    fn issue_summary_lines_include_every_failed_check() {
        let missing = [
            Check {
                name: "cargo",
                category: "prerequisites",
                ok: false,
                info: "missing".into(),
            },
            Check {
                name: "disk space",
                category: "platform",
                ok: false,
                info: "only 2 GiB free".into(),
            },
        ];
        let refs: Vec<&Check> = missing.iter().collect();

        let lines = issue_summary_lines(&refs);

        assert_eq!(
            lines,
            vec![
                "  cargo — missing".to_string(),
                "  disk space — only 2 GiB free".to_string(),
            ]
        );
    }

    #[test]
    fn runtime_backend_check_macos_reports_hvf_not_vz() {
        let c = runtime_backend_check(Platform::MacOS);
        assert!(c.ok);
        assert!(c.info.contains("`hvf`"), "got: {}", c.info);
        assert!(
            c.info.contains("`libkrun`"),
            "expected libkrun fallback in macOS summary; got: {}",
            c.info
        );
        assert!(
            !c.info.contains("`vz`"),
            "stale Vz wording must not remain in runtime backend summary: {}",
            c.info
        );
    }

    // ── builder-backend check format on Linux ──
    //
    // The selection layer's `auto_detect_default()` queries the real
    // host platform (not the `Platform` enum passed to the check). On
    // Linux CI runners it always returns Qemu. macOS contributor
    // hosts get covered by the existing `vz_check_macos_reports_*`
    // tests above; this Linux-only test pins the format of the new
    // `builder backend` line so the doctor report stays readable for
    // operators on the supported Linux path.
    //
    // The test serialises with itself by clearing `MVM_BUILDER_BACKEND`
    // for the duration; other tests in this crate don't touch this
    // env var so cross-test interference is bounded.
    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_reports_qemu_auto_detected() {
        // SAFETY: single-threaded test phase per crate; this env var
        // isn't read elsewhere in this test binary.
        let prev = std::env::var_os("MVM_BUILDER_BACKEND");
        unsafe {
            std::env::remove_var("MVM_BUILDER_BACKEND");
        }

        let c = builder_backend_check(Platform::LinuxNative);

        // Restore before any assertion so a panic doesn't strand the
        // env var.
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("MVM_BUILDER_BACKEND", v);
            }
        }

        assert!(c.ok, "builder backend check must not fail informational");
        assert_eq!(c.name, "builder backend");
        assert_eq!(c.category, "platform");
        // Format: `<backend> — <source> — <availability>`
        assert!(
            c.info.starts_with("qemu — "),
            "expected qemu-resolved line; got: {}",
            c.info
        );
        assert!(
            c.info.contains("auto-detected"),
            "expected `auto-detected` source label when env unset; got: {}",
            c.info
        );
        assert!(
            c.info.contains("QEMU available") || c.info.contains("QEMU NOT available"),
            "expected per-VMM availability segment; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_honors_env_override() {
        let prev = std::env::var_os("MVM_BUILDER_BACKEND");
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "qemu");
        }

        let c = builder_backend_check(Platform::LinuxNative);

        unsafe {
            match prev {
                Some(v) => std::env::set_var("MVM_BUILDER_BACKEND", v),
                None => std::env::remove_var("MVM_BUILDER_BACKEND"),
            }
        }

        assert!(c.ok);
        // Env override flips the resolved backend even when
        // `auto_detect_default()` would have picked qemu.
        assert!(
            c.info.starts_with("qemu — "),
            "expected qemu-resolved line under env override; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via"),
            "expected `override via` source label; got: {}",
            c.info
        );
        assert!(
            c.info.contains("QEMU available") || c.info.contains("QEMU NOT available"),
            "expected per-VMM availability segment; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_libkrun_override_no_longer_reports_a_rootfs_gap() {
        let prev = std::env::var_os("MVM_BUILDER_BACKEND");
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "libkrun");
        }

        let c = builder_backend_check(Platform::LinuxNative);

        unsafe {
            match prev {
                Some(v) => std::env::set_var("MVM_BUILDER_BACKEND", v),
                None => std::env::remove_var("MVM_BUILDER_BACKEND"),
            }
        }

        assert!(
            c.info.starts_with("libkrun — "),
            "expected libkrun-resolved line under env override; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via"),
            "expected `override via` source label; got: {}",
            c.info
        );
        // The Linux/KVM steady-state guard is lifted, so doctor reports libkrun
        // availability from host capability alone and no longer surfaces a
        // rootfs-builder-unsupported gap for an explicit libkrun override.
        assert!(
            !c.info.contains("not supported on Linux/KVM"),
            "guard is lifted; expected no unsupported-rootfs gap; got: {}",
            c.info
        );
    }

    // ── nested-kvm check + MVM_LINUX_BUILDER_VM line ──

    #[test]
    fn nested_kvm_check_macos_reports_na() {
        let c = nested_kvm_check(Platform::MacOS);
        assert!(c.ok, "macOS host must not fail on Linux-only probe");
        assert_eq!(c.name, "nested-kvm");
        assert_eq!(c.category, "platform");
        assert!(c.info.contains("n/a"), "got: {}", c.info);
        assert!(c.info.contains("Linux-only"), "got: {}", c.info);
    }

    #[test]
    fn nested_kvm_check_windows_reports_na() {
        let c = nested_kvm_check(Platform::Windows);
        assert!(c.ok);
        assert!(c.info.contains("n/a"));
    }

    #[test]
    fn nested_kvm_check_wsl2_reports_na() {
        let c = nested_kvm_check(Platform::Wsl2);
        assert!(c.ok);
        assert!(c.info.contains("n/a"));
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn nested_kvm_check_linux_native_reports_actionable_text() {
        // Without spoofing the sysfs probe we can't pin the (ok/!ok)
        // outcome — different CI runners report different nested-KVM
        // states. What we CAN pin: the line is "nested-kvm", category
        // "platform", and the info text covers one of the four
        // documented branches (env-set + ready, env-set + missing,
        // env-unset + ready, env-unset + missing).
        let prev = std::env::var_os("MVM_LINUX_BUILDER_VM");
        unsafe {
            std::env::remove_var("MVM_LINUX_BUILDER_VM");
        }
        let c = nested_kvm_check(Platform::LinuxNative);
        unsafe {
            if let Some(v) = prev {
                std::env::set_var("MVM_LINUX_BUILDER_VM", v);
            }
        }
        assert_eq!(c.name, "nested-kvm");
        assert_eq!(c.category, "platform");
        let info = &c.info;
        // Env-unset branch — one of two truthy paths.
        assert!(
            info.contains("informational")
                || info.contains("not enabled (informational")
                || info.contains("available (informational"),
            "expected informational env-unset text; got: {info}"
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_surfaces_linux_builder_vm_env() {
        // When MVM_LINUX_BUILDER_VM=1 is set, the builder-backend line
        // adds the rollout-opt-in annotation alongside the resolved
        // backend + availability.
        let prev_bb = std::env::var_os("MVM_BUILDER_BACKEND");
        let prev_lbvm = std::env::var_os("MVM_LINUX_BUILDER_VM");
        unsafe {
            std::env::remove_var("MVM_BUILDER_BACKEND");
            std::env::set_var("MVM_LINUX_BUILDER_VM", "1");
        }

        let c = builder_backend_check(Platform::LinuxNative);

        unsafe {
            match prev_bb {
                Some(v) => std::env::set_var("MVM_BUILDER_BACKEND", v),
                None => std::env::remove_var("MVM_BUILDER_BACKEND"),
            }
            match prev_lbvm {
                Some(v) => std::env::set_var("MVM_LINUX_BUILDER_VM", v),
                None => std::env::remove_var("MVM_LINUX_BUILDER_VM"),
            }
        }

        assert!(c.ok);
        assert!(
            c.info.contains("MVM_LINUX_BUILDER_VM"),
            "expected Plan 100 W6 opt-in annotation; got: {}",
            c.info
        );
        assert!(
            c.info.contains("Plan 100 W6 opt-in"),
            "expected `Plan 100 W6 opt-in` annotation; got: {}",
            c.info
        );
    }

    #[cfg(not(feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_stub_when_feature_off() {
        let c = builder_backend_check(Platform::LinuxNative);
        assert!(c.ok);
        assert_eq!(c.name, "builder backend");
        assert!(
            c.info.contains("n/a"),
            "stub should mention n/a; got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_is_in_security_category() {
        let c = security_signing_check();
        assert_eq!(c.category, "security");
        assert_eq!(c.name, "signing");
    }

    #[test]
    fn host_agent_daemon_summary_reports_absent_warm_and_stale() {
        let root = tempfile::tempdir().unwrap();
        assert!(host_agent_daemon_summary(&root.path().join("missing")).starts_with("absent"));

        // No dirs yet means absent.
        assert!(host_agent_daemon_summary(root.path()).starts_with("absent"));

        // A "running" tenant: live pid (this process) + control.sock.
        let live = root.path().join("local");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("daemon.pid"), std::process::id().to_string()).unwrap();
        std::fs::write(live.join("control.sock"), "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("1 warm"), "got {s:?}");
        assert!(s.contains("local: running"), "got {s:?}");

        // A "stale" tenant: a dead pid + a leftover socket.
        let dead = root.path().join("acme");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("daemon.pid"), "2147483647").unwrap();
        std::fs::write(dead.join("control.sock"), "").unwrap();
        let s = host_agent_daemon_summary(root.path());
        assert!(s.contains("stale: acme"), "got {s:?}");
    }

    #[test]
    fn builderd_daemon_check_is_informational_platform_check() {
        let c = builderd_daemon_check();
        assert_eq!(c.name, "builder daemon");
        assert_eq!(c.category, "platform");
        assert!(
            c.ok,
            "builder-daemon readiness is informational, never blocking"
        );
    }

    #[test]
    fn builderd_daemon_summary_absent_when_root_missing_or_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(builderd_daemon_summary(&root.path().join("missing")).starts_with("absent"));
        // An empty vms root, and a builder-VM dir with no control socket,
        // both read as absent (nothing to probe).
        assert!(builderd_daemon_summary(root.path()).starts_with("absent"));
        std::fs::create_dir_all(root.path().join("mvm-persistent-builder-vm-x")).unwrap();
        assert!(builderd_daemon_summary(root.path()).starts_with("absent"));
    }

    #[test]
    fn builderd_daemon_summary_reports_ready_for_a_live_daemon() {
        use std::os::unix::net::UnixListener;
        // A builder-VM state dir whose control socket is served by the
        // real `serve_connection` loop reports "ready". Bind under a short
        // /tmp root with a short dir name — the full socket path must fit
        // under the AF_UNIX SUN_LEN limit (~104 bytes on macOS).
        let root = tempfile::Builder::new()
            .prefix("mvmbd")
            .tempdir_in("/tmp")
            .unwrap();
        let vm_dir = root.path().join("bv");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let sock = mvm_build::builderd::builderd_control_socket_path(&vm_dir);
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping builderd daemon summary unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            mvm_build::builderd::serve_connection(&mut conn).expect("serve");
        });

        let s = builderd_daemon_summary(root.path());
        assert!(s.contains("bv: ready"), "got {s:?}");
        handle.join().expect("server thread");
    }

    #[test]
    fn builderd_daemon_summary_finds_a_vz_shaped_socket() {
        use std::os::unix::net::UnixListener;
        // Regression for the live Vz boot: the Vz supervisor nests the
        // control socket under `<vm_state_dir>/vsock/`. The scan must find
        // it there, not only at the libkrun `<vm_state_dir>/vsock-*.sock`.
        let root = tempfile::Builder::new()
            .prefix("mvmbd")
            .tempdir_in("/tmp")
            .unwrap();
        let vm_dir = root.path().join("bvz");
        let sock = mvm_build::builderd::builderd_vz_control_socket_path(&vm_dir);
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping builderd daemon summary unix listener test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            mvm_build::builderd::serve_connection(&mut conn).expect("serve");
        });

        let s = builderd_daemon_summary(root.path());
        assert!(s.contains("bvz: ready"), "got {s:?}");
        handle.join().expect("server thread");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_reports_hvf_as_vsock_only() {
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "hvf");
        }
        let c = builder_transport_check(Platform::MacOS);
        unsafe {
            std::env::remove_var("MVM_BUILDER_BACKEND");
        }
        assert_eq!(c.name, "builder transport");
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(c.info.contains("vsock-only"), "got {:?}", c.info);
        assert!(c.info.contains("no builder guest NIC"), "got {:?}", c.info);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_reports_libkrun_as_legacy_guest_network() {
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "libkrun");
        }
        let c = builder_transport_check(Platform::MacOS);
        unsafe {
            std::env::remove_var("MVM_BUILDER_BACKEND");
        }
        assert_eq!(c.name, "builder transport");
        assert!(
            c.info.contains("legacy guest-network bootstrap"),
            "got {:?}",
            c.info
        );
        assert!(c.info.contains("libkrun"), "got {:?}", c.info);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_transport_check_marks_qemu_as_unsupported_legacy() {
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "qemu");
        }
        let c = builder_transport_check(Platform::LinuxNoKvm);
        unsafe {
            std::env::remove_var("MVM_BUILDER_BACKEND");
        }
        assert_eq!(c.name, "builder transport");
        assert!(c.info.contains("unsupported legacy"), "got {:?}", c.info);
        assert!(c.info.contains("qemu"), "got {:?}", c.info);
    }

    #[test]
    fn network_tunnel_worker_check_is_informational_platform_check() {
        let c = network_tunnel_worker_check();
        assert_eq!(c.name, "network tunnel worker");
        assert_eq!(c.category, "platform");
        assert!(c.ok, "tunnel worker state is informational, never blocking");
    }

    #[test]
    fn network_tunnel_worker_summary_absent_when_root_missing_or_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(network_tunnel_worker_summary(&root.path().join("missing")).starts_with("absent"));
        assert!(network_tunnel_worker_summary(root.path()).starts_with("absent"));
        std::fs::create_dir_all(root.path().join("vm-no-tunnel")).unwrap();
        assert!(network_tunnel_worker_summary(root.path()).starts_with("absent"));
    }

    #[test]
    fn network_tunnel_worker_summary_reports_live_workers() {
        let root = tempfile::tempdir().unwrap();
        for name in ["vm-a", "vm-b"] {
            let dir = root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(mvm_backend::NETWORK_TUNNEL_WORKER_PID_FILE),
                format!("{}\n", std::process::id()),
            )
            .unwrap();
        }

        let s = network_tunnel_worker_summary(root.path());
        assert!(s.contains("2 active"), "got {s:?}");
        assert!(s.contains("vm-a (pid"), "got {s:?}");
        assert!(s.contains("vm-b (pid"), "got {s:?}");
    }

    #[test]
    fn network_tunnel_worker_summary_reports_stale_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let stale = root.path().join("vm-stale");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(
            stale.join(mvm_backend::NETWORK_TUNNEL_WORKER_PID_FILE),
            "2147483646\n",
        )
        .unwrap();
        std::fs::write(stale.join(mvm_backend::NETWORK_TUNNEL_AUDIT_JSONL), "").unwrap();

        let s = network_tunnel_worker_summary(root.path());
        assert!(s.contains("stale: vm-stale"), "got {s:?}");
    }

    #[test]
    fn residency_check_reports_policy_and_source() {
        let c = residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        // label — source — warm_target=N
        assert!(c.info.contains("warm_target="), "info was {:?}", c.info);
        assert!(
            c.info.contains("auto-detected") || c.info.contains("override"),
            "info was {:?}",
            c.info
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_residency_check_reports_policy_and_session_state() {
        let c = builder_residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(
            c.info.contains("persistent builder")
                || c.info.contains("parked")
                || c.info.contains("no persistent builder"),
            "info was {:?}",
            c.info
        );
        // names the builder routing effect
        assert!(
            c.info.contains("uses persistent") || c.info.contains("ephemeral"),
            "info was {:?}",
            c.info
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_residency_session_summary_names_parked_snapshot_state() {
        use mvm_core::residency::ResidencyKind;

        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Parked, false, true),
            "parked (snapshot present)"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Parked, false, false),
            "parked (no snapshot)"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Warm, true, false),
            "persistent builder active"
        );
        assert_eq!(
            builder_residency_session_summary(ResidencyKind::Warm, false, true),
            "parked snapshot present"
        );
    }
}
