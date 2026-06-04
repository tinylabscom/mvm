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

/// Audience-scoped filter for `mvmctl doctor` (plan 74 W5).
///
/// `--workflow <name>` narrows the report (and the exit-code
/// blocking set) to checks whose `category` is relevant for the
/// named workflow. Each workflow's mapping lives in
/// [`DoctorWorkflow::relevant_categories`] — adding a new check
/// category therefore implies a deliberate decision about which
/// workflows it applies to.
///
/// The default (no `--workflow` flag) is unchanged from
/// pre-plan-74: every check runs and every failure blocks. The
/// flag is additive — operators relying on the existing behavior
/// see no change.
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
    /// `mvmctl dev` flow — drops the operator into a builder-VM
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
            // `mvmctl dev` is the bootstrap-time flow; the host
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
        info: "skipped — dev VM not running; run `mvmctl dev up` to verify".into(),
    }
}

/// JSON-serializable view of a backend's ADR-002 security profile,
/// surfaced under `security_posture` in `mvmctl doctor --json`.
#[derive(Debug, Serialize)]
struct SecurityPostureReport {
    /// Backend name (e.g. "firecracker", "docker").
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
    /// the default "all checks" mode (plan 74 W5).
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
    all_ok: bool,
}

/// Plan 93 Phase 3 — surface the last Stage 0 builder-VM bootstrap
/// outcome (and its source-fingerprint prefix, carried in the audit
/// detail) so "why did Stage 0 fire / when did it last run?" is
/// answerable without grep-ing the audit log. Informational: a stale or
/// never-run Stage 0 is not a host-side defect, so `ok` is always true.
fn stage0_status_check() -> Check {
    use mvm_core::policy::audit::LocalAuditKind;
    let info = match mvm_core::policy::audit::read_last_stage0_event() {
        None => "no Stage 0 recorded yet (run `mvmctl dev up`)".to_string(),
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

pub fn run(json: bool, workflow: Option<DoctorWorkflow>) -> Result<()> {
    // ── Prerequisites (user must install before bootstrap) ───────
    let mut checks = vec![
        check_cmd("rustup", "prerequisites", "rustup --version"),
        check_cmd("cargo", "prerequisites", "cargo --version"),
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
    checks.push(apple_container_check(plat));
    checks.push(vz_check(plat));
    checks.push(libkrun_check(plat));
    checks.push(builder_backend_check(plat));
    checks.push(network_backend_check(plat));
    checks.push(docker_check(plat));
    checks.push(ts_runner_check());
    checks.push(stage0_status_check());

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

    // ── Security posture (plan 40 folded `mvmctl security` here) ──
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

    // ── Active backend security posture (ADR-002 / plan 53) ──────
    let security_posture = collect_security_posture();

    // ── Balloon capability per backend ────────────────────────────
    let balloon_support = collect_balloon_support();

    // ── Workflow filter (plan 74 W5) ──────────────────────────────
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
        for m in &missing {
            ui::info(&format!("  {} — {}", m.name, m.info));
        }

        // Provide category-specific guidance
        let has_prerequisites = missing.iter().any(|c| c.category == "prerequisites");
        let has_managed = missing.iter().any(|c| c.category == "tools");

        if has_prerequisites {
            ui::info("\nPrerequisites missing: Install Rust from https://rustup.rs");
        }
        if has_managed {
            ui::info("\nManaged tools missing: Run 'mvmctl bootstrap' to install");
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
    // Hypervisor selectors mirror `AnyBackend::from_hypervisor`. The
    // list is hand-maintained because there's no general "iterate
    // every backend" helper today; adding a new backend means
    // adding it here so doctor surfaces it without lying.
    let names = [
        "firecracker",
        "cloud-hypervisor",
        "apple-container",
        "docker",
        "libkrun",
        "qemu",
    ];
    let mut out = BTreeMap::new();
    for name in names {
        let backend = AnyBackend::from_hypervisor(name);
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

// ── Active backend security posture (ADR-002 / plan 53) ──────

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
/// status. When the backend is not a microVM tier (Docker today), prints
/// a loud warning banner with the recent container-escape CVEs.
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
             hold. Recent container-escape CVEs (2024-2025): CVE-2024-21626,\n   \
             CVE-2024-1753, CVE-2025-9074, CVE-2025-23266, CVE-2025-31133,\n   \
             CVE-2025-52565. Set MVM_ACK_DOCKER_TIER=1 (or [security]\n   \
             ack_docker_tier = true in ~/.mvm/config.toml) to suppress the\n   \
             per-run banner. See https://docs.mvm.dev/security/matryoshka.",
        );
    }
}

// ── Tool checks ───────────────────────────────────────────────────────────

fn check_cmd(name: &'static str, category: &'static str, cmd: &'static str) -> Check {
    match shell::run_host("bash", &["-lc", cmd]) {
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

/// Plan 105 W1 / Plan 100 W3 — surface nested-KVM availability on
/// Linux. Required for the Plan 100 W6 dispatch flip (libkrun
/// builder VM → nested Firecracker workload). Linux-only: macOS and
/// Windows hosts get a clean "n/a" line so the doctor output isn't
/// noisy on the platforms the question doesn't apply to.
///
/// Two states matter to operators:
///   1. `MVM_LINUX_BUILDER_VM` is unset → informational only (this
///      is the default today; nested-KVM either ready or a future
///      enablement step).
///   2. `MVM_LINUX_BUILDER_VM=1` is set → the operator has opted in;
///      nested-KVM missing is now a hard "fix this before Plan 100
///      W6 ships" error.
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
    // Hypervisor.framework. Plan-60 / ADR-013 retired Lima; reporting
    // KVM as missing on macOS is a pre-Plan-60 artifact.
    Check {
        name: "kvm",
        category: "platform",
        ok: true,
        info: "n/a on macOS (Hypervisor.framework via libkrun / Apple Container)".to_string(),
    }
}

fn apple_container_check(plat: Platform) -> Check {
    if plat != Platform::MacOS {
        return Check {
            name: "apple containers",
            category: "platform",
            ok: true,
            info: "n/a (not macOS)".to_string(),
        };
    }

    if plat.has_apple_containers() {
        Check {
            name: "apple containers",
            category: "platform",
            ok: true,
            info: "available (macOS 26+ on Apple Silicon)".to_string(),
        }
    } else {
        Check {
            name: "apple containers",
            category: "platform",
            ok: true, // Not a failure — just unavailable
            info: "not available (requires macOS 26+ on Apple Silicon)".to_string(),
        }
    }
}

/// Apple Virtualization.framework probe. Plan 97 / ADR-056.
///
/// Vz is built into macOS 13+; nothing to install at the framework
/// layer. The supervisor *binary* (`mvm-vz-supervisor`) is a separate
/// concern — we probe its presence so operators don't hit a
/// mid-`mvmctl up --backend vz` failure. Both paths the
/// `VzBackend::resolve_supervisor_path` resolver consults are
/// reported when relevant.
fn vz_check(plat: Platform) -> Check {
    if plat != Platform::MacOS {
        return Check {
            name: "Apple Virtualization.framework",
            category: "platform",
            ok: true,
            info: "n/a (not macOS)".to_string(),
        };
    }
    if !plat.has_vz() {
        return Check {
            name: "Apple Virtualization.framework",
            category: "platform",
            ok: true, // Not a failure — Vz is optional.
            info: "not available (requires macOS 13+; macOS 11–12 fall back to libkrun)"
                .to_string(),
        };
    }
    // Vz framework available. Probe for the supervisor binary in the
    // two locations the backend's resolver checks (source-checkout
    // build output, release-installed `~/.mvm/bin/`). Surface either
    // a found path or the build hint so the operator can act.
    let (supervisor_path, supervisor_info) = locate_vz_supervisor();

    let Some(path) = supervisor_path else {
        return Check {
            name: "Apple Virtualization.framework",
            category: "platform",
            ok: true,
            info: format!("available (macOS 13+); {supervisor_info}"),
        };
    };

    // Sub-probes — Plan 97 §13: entitlement check + MDM-policy probe.
    // Each surfaces a brief tag in the info string; `ok` drops to false
    // if either probe affirmatively reports the supervisor cannot run.
    let entitlement = vz_entitlement_probe(&path);
    let runtime = vz_runtime_probe(&path);

    let entitlement_tag = match entitlement {
        Some(true) => "entitlement ✓",
        Some(false) => "entitlement MISSING",
        None => "entitlement ?",
    };
    let runtime_tag = match &runtime {
        Some(r) if r.is_supported => "probe ✓",
        Some(_) => "probe: VZ NOT SUPPORTED (MDM lockdown? unsupported hardware?)",
        None => "probe ?",
    };
    let macos_tag = runtime
        .as_ref()
        .map(|r| format!(" on macOS {}", r.macos_version))
        .unwrap_or_default();

    // An entitlement that's verifiably MISSING or a probe that
    // affirmatively says NOT SUPPORTED means the operator will hit a
    // real failure on `mvmctl up --backend vz`. Surface as not-ok so
    // doctor flags it. `?` (probe failed to run, codesign missing,
    // etc.) leaves ok=true — we don't want a broken probe to mask the
    // real "supervisor present, framework available" signal.
    let probes_ok =
        !matches!(entitlement, Some(false)) && !matches!(&runtime, Some(r) if !r.is_supported);

    Check {
        name: "Apple Virtualization.framework",
        category: "platform",
        ok: probes_ok,
        info: format!(
            "available (macOS 13+); {supervisor_info}; {entitlement_tag}; {runtime_tag}{macos_tag}"
        ),
    }
}

/// Locate the `mvm-vz-supervisor` binary using the same chain the
/// `VzBackend` resolver applies. Returns `(path, label)`: `path` is
/// `Some` when the binary was found (so sub-probes have something to
/// inspect); `label` is the doctor-friendly description either way.
/// Order:
///
/// 1. `MVM_VZ_SUPERVISOR_PATH` (explicit override)
/// 2. Source-checkout `crates/mvm-vz-supervisor/.build/<arch>-apple-macosx/debug/`
/// 3. Release-installed `~/.mvm/bin/mvm-vz-supervisor-<mvmctl-version>`
fn locate_vz_supervisor() -> (Option<std::path::PathBuf>, String) {
    if let Some(p) = std::env::var_os("MVM_VZ_SUPERVISOR_PATH") {
        let path = std::path::PathBuf::from(p);
        if path.is_file() {
            let info = format!(
                "supervisor at {} (via MVM_VZ_SUPERVISOR_PATH)",
                path.display()
            );
            return (Some(path), info);
        }
        let info = format!(
            "MVM_VZ_SUPERVISOR_PATH set to {} but the path is not a file",
            path.display()
        );
        return (None, info);
    }
    // Source-checkout path — workspace root is wherever `mvmctl`'s
    // build manifest sits; we can't introspect that from a doctor
    // function compiled into the binary, but we can probe the path
    // relative to the workspace inferred from `current_exe` when
    // the binary is running from `target/.../mvmctl`.
    if let Ok(exe) = std::env::current_exe()
        && let Some(workspace_root) = workspace_root_from_target_layout(&exe)
    {
        let candidate = workspace_root
            .join("crates/mvm-vz-supervisor/.build")
            .join(arch_apple_macosx())
            .join("debug")
            .join("mvm-vz-supervisor");
        if candidate.is_file() {
            let info = format!(
                "supervisor at {} (source-checkout build)",
                candidate.display()
            );
            return (Some(candidate), info);
        }
    }
    // Release-installed path under `~/.mvm/bin/`.
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = std::path::PathBuf::from(home)
            .join(".mvm/bin")
            .join(format!("mvm-vz-supervisor-{}", env!("CARGO_PKG_VERSION")));
        if candidate.is_file() {
            let info = format!("supervisor at {} (installed)", candidate.display());
            return (Some(candidate), info);
        }
    }
    (
        None,
        "supervisor binary NOT FOUND — build via `crates/mvm-vz-supervisor/tools/build.sh` \
         before `mvmctl up --backend vz`"
            .to_string(),
    )
}

/// Probe whether the supervisor binary carries the
/// `com.apple.security.virtualization` entitlement. Plan 97 §13.
///
/// Returns:
/// - `Some(true)`  — the entitlement is present (binary will be
///   permitted to use Virtualization.framework).
/// - `Some(false)` — codesign ran successfully but the entitlement is
///   absent from the binary. `mvmctl up --backend vz` will fail with
///   an opaque framework error; rebuilding via `tools/build.sh` fixes
///   it.
/// - `None` — codesign couldn't be invoked (not on PATH, or the
///   binary path is wrong). Surfaced as `entitlement ?` in doctor; not
///   a hard failure because we can't distinguish "tooling unavailable"
///   from "binary actually unsigned" without the tool itself.
fn vz_entitlement_probe(supervisor_path: &std::path::Path) -> Option<bool> {
    // `codesign --display --entitlements :- <path>` writes the
    // entitlement plist to stdout. The LEADING colon selects the XML
    // plist format and the `-` means stdout. The colon must be first:
    // `-:-` does not start with `:`, so codesign treats it as a literal
    // output-file path and silently writes a file named `-:-` into the
    // CWD instead of streaming to stdout. We grep for the entitlement
    // key rather than parse the plist — the key is a long well-known
    // identifier, false positives are vanishingly unlikely.
    let output = std::process::Command::new("codesign")
        .args(["--display", "--entitlements", ":-", "--"])
        .arg(supervisor_path)
        .output()
        .ok()?;
    Some(entitlement_present_in_codesign_output(&output.stdout))
}

/// Pure helper for parsing `codesign --display --entitlements`
/// output. Split out so unit tests can drive it with fixture bytes
/// without invoking codesign.
fn entitlement_present_in_codesign_output(stdout: &[u8]) -> bool {
    // The entitlement key always appears as `<key>...</key>` in plist
    // output; matching the raw key text avoids depending on a plist
    // parser and works against both XML and (older) hybrid formats.
    let needle = b"com.apple.security.virtualization";
    stdout.windows(needle.len()).any(|w| w == needle)
}

/// Result of running the supervisor in `--probe` mode. Mirrors the
/// JSON the Swift side emits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct VzProbeResult {
    is_supported: bool,
    macos_version: String,
}

/// Run the supervisor with `--probe` to learn whether VZ is actually
/// usable on this host (Plan 97 §13 MDM-policy detection). The Swift
/// side calls `VZVirtualMachine.isSupported`, which returns false
/// under MDM virtualization lockdown, on unsupported hardware, and on
/// macOS <11.
///
/// Returns `None` when the supervisor itself failed to run (codesign
/// rejection, arch mismatch, file-not-executable). Returns `Some(_)`
/// when the probe ran to completion and emitted parseable JSON. A
/// `None` here surfaces as `probe ?` — same posture as the
/// entitlement probe: we don't infer worst-case from a broken tool.
fn vz_runtime_probe(supervisor_path: &std::path::Path) -> Option<VzProbeResult> {
    let output = std::process::Command::new(supervisor_path)
        .arg("--probe")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_vz_probe_output(&output.stdout)
}

/// Pure parser for the `--probe` JSON payload. Separate so tests can
/// drive it without invoking the supervisor.
fn parse_vz_probe_output(stdout: &[u8]) -> Option<VzProbeResult> {
    serde_json::from_slice::<VzProbeResult>(stdout).ok()
}

/// Walk up from `target/<profile>/<exe>` to the workspace root.
/// Returns `None` when the exe is not running from a cargo target
/// layout (e.g. `cargo install` placed it under `~/.cargo/bin/`),
/// which is correct — in that case there is no source checkout to
/// probe.
fn workspace_root_from_target_layout(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let parent = exe.parent()?; // target/<profile>
    let target = parent.parent()?; // target
    if target.file_name().and_then(|n| n.to_str()) != Some("target") {
        return None;
    }
    target.parent().map(std::path::Path::to_path_buf)
}

fn arch_apple_macosx() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64-apple-macosx"
    } else {
        "x86_64-apple-macosx"
    }
}

fn docker_check(plat: Platform) -> Check {
    if plat.has_docker() {
        Check {
            name: "docker",
            category: "platform",
            ok: true,
            info: "available".to_string(),
        }
    } else {
        Check {
            name: "docker",
            category: "platform",
            ok: true, // Not a failure — just unavailable
            info: "not available (install Docker Desktop or Docker Engine)".to_string(),
        }
    }
}

/// Userspace network-gateway host-side availability — Plan 87 W5 +
/// Plan 88 W4. Probes `$PATH` for the gateway binary the host's
/// libkrun build defaults to: `passt` on Linux, `gvproxy` on macOS
/// (passt does not build on macOS — see ADR-055 §"Cross-platform
/// backends"). Surfaces the version when present and emits a
/// **failing** check when missing — Plan 102 W6.A removed TSI, so
/// the host needs a gateway binary to run any libkrun-backed VM
/// (no-bypass invariant, ADR-058).
///
/// Skipped on Windows (no native libkrun port either; the whole
/// libkrun + virtio-net stack is macOS / Linux).
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
    if cfg!(target_os = "macos") {
        return gateway_check(
            "gvproxy",
            libkrun_sys::gvproxy::locate_gvproxy(),
            libkrun_sys::gvproxy::install_hint(),
        );
    }
    gateway_check(
        "passt",
        libkrun_sys::passt::locate_passt(),
        libkrun_sys::passt::install_hint(),
    )
}

/// Shared probe body for the per-OS userspace gateway. Returns a
/// `Check` row with the version (when the binary supports
/// `--version`) or the install hint (when missing). Missing now
/// fails the check — Plan 102 W6.A removed the TSI escape hatch,
/// so a libkrun host without a gateway can't boot any VM.
#[cfg(target_family = "unix")]
fn gateway_check(
    name: &'static str,
    located: Option<std::path::PathBuf>,
    install_hint: &str,
) -> Check {
    match located {
        Some(path) => {
            // Best-effort version probe. passt prints to stdout;
            // gvproxy 0.7+ recognises `--version` (older builds
            // exit nonzero, which we silently fall through on).
            let version = std::process::Command::new(&path)
                .arg("--version")
                .output()
                .ok()
                .and_then(|out| {
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if s.is_empty() { None } else { Some(s) }
                    } else {
                        None
                    }
                });
            let info = match version {
                Some(v) => format!("available — {v}"),
                None => format!("available at {}", path.display()),
            };
            Check {
                name,
                category: "platform",
                ok: true,
                info,
            }
        }
        None => Check {
            name,
            category: "platform",
            ok: false, // Plan 102 W6.A: no TSI escape; gateway is mandatory.
            info: format!(
                "not available ({install_hint}) — required for libkrun \
                 virtio-net; TSI escape hatch was removed in Plan 102 W6.A \
                 (claim-10 no-bypass invariant, ADR-058)"
            ),
        },
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

/// libkrun availability — plan 53 §"Plan E". Probes the host for the
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

/// Plan 98 — surface which builder-VM backend the selection layer
/// resolves to on this host, plus the override source if any.
///
/// `mvm_build::builder_backend_select` enforces priority
/// `--builder` flag > `MVM_BUILDER_BACKEND` env > platform default
/// (macOS 26+ Apple Silicon → vz; everywhere else → libkrun). The
/// flag is folded into the env at startup (`commands::run`), so by
/// the time doctor runs every override is observable via env.
///
/// The check is informational — it never fails. A missing libkrun
/// or Vz prereq is reported by the platform-level `libkrun_check`
/// / `vz_check` already in the report; this check is about the
/// *selection*, not the availability.
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
    // Plan 105 W1 — surface the Linux-only rollout signal alongside
    // the backend selection. The env doesn't change *which* backend
    // wins (libkrun stays the Linux default); it changes how the
    // workload path will dispatch once Plan 100 W6 lands. Operators
    // who set it should see it acknowledged in `doctor` output.
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
        BuilderBackendChoice::Vz => {
            if plat.has_vz() {
                "Vz available".to_string()
            } else {
                "Vz NOT available (requires macOS 13+)".to_string()
            }
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

// ── Security posture (folded in from `mvmctl security` per plan 40) ─────

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

/// Host full-disk-encryption check — plan 45 §"Encryption at rest".
///
/// `LocalBackend` volumes rely on host FDE for at-rest protection (we
/// deliberately don't roll our own per-volume crypto on dev boxes).
/// On a dev host this check is **informational/warning-only** — the
/// `ok` flag stays `true` so a non-FDE laptop can still run mvmctl,
/// but the report surfaces the gap so users can enable FileVault /
/// LUKS before relying on local volumes for sensitive data.
///
/// On mvmd workers the analogous check is **enforced** (refuses
/// `LocalVirtiofs` bucket creation when FDE is absent). That lives
/// in mvmd Sprint 137 W6.
fn security_host_fde_check() -> Check {
    let detection = detect_host_fde_status();
    Check {
        name: "host FDE (volumes at-rest)",
        category: "security",
        ok: true, // warn-only on dev box per plan 45 §D5
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

/// `~/.mvm` should be mode 0700 (ADR-002 §W1.5). The XDG share directory
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

/// Dev VM vsock proxy socket should be mode 0700 (ADR-002 §W1.2).
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
/// hash-verified download per ADR-002 §W5.1).
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
            "not cached; next `mvmctl dev up` will download + hash-verify".to_string()
        },
    }
}

/// `deny.toml` at the workspace root (ADR-002 §W5.2 supply-chain policy).
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

/// ADR-002 claim 10: *no untrusted workload reaches the network unless
/// explicitly admitted by policy.* Sprint 52 W3 flipped
/// `NetworkPolicy::default()` from `unrestricted()` to `deny_all()` so
/// the safe posture is the one workloads get without opting in. This
/// check makes the runtime default visible in `mvmctl doctor` so the
/// claim is observably enforced rather than implicit in the codepath.
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

/// `~/.mvm/snapshot.key` should be mode 0600 (ADR-007 §W4 / M9).
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

/// All template snapshot directories should be mode 0700 (ADR-007
/// §W4 / M9). Walks `~/.mvm/templates/*/artifacts/*/snapshot/`,
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

    #[test]
    fn check_cmd_rustup_on_host() {
        let c = check_cmd("rustup", "tools", "rustup --version");
        assert!(c.ok, "rustup should be available: {}", c.info);
        assert!(
            c.info.contains("rustup"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_cargo_on_host() {
        let c = check_cmd("cargo", "tools", "cargo --version");
        assert!(c.ok, "cargo should be available: {}", c.info);
        assert!(
            c.info.contains("cargo"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_missing_tool() {
        let c = check_cmd(
            "nonexistent-mvm-tool-xyz",
            "tools",
            "nonexistent-mvm-tool-xyz --version",
        );
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

    #[test]
    fn vz_check_is_na_on_non_macos() {
        for plat in [
            Platform::LinuxNative,
            Platform::LinuxNoKvm,
            Platform::Wsl2,
            Platform::Windows,
        ] {
            let c = vz_check(plat);
            assert!(c.ok, "non-macOS vz check must not fail: {c:?}");
            assert!(
                c.info.contains("n/a"),
                "non-macOS vz check info should say n/a: {}",
                c.info
            );
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn vz_check_macos_reports_availability() {
        let c = vz_check(Platform::MacOS);
        // Either "available" (macOS 13+) or "not available" (macOS 11–12)
        // — the variant depends on the contributor host's version.
        // We deliberately do NOT assert `c.ok` here: under the Plan 97 §13
        // sub-probes, `ok` flips to false when codesign reports a missing
        // entitlement or the supervisor probe affirmatively says VZ is not
        // supported. Both are legitimate signals for a real CI host where
        // the supervisor binary was built without the entitlement step or
        // where MDM blocks Vz. The new probe-specific tests below pin the
        // per-probe behaviour against fixture input.
        assert!(
            c.info.contains("available") || c.info.contains("not available"),
            "macOS vz check should mention availability: {}",
            c.info
        );
    }

    #[test]
    fn entitlement_probe_parses_xml_plist_with_entitlement() {
        // Real `codesign --display --entitlements :-` XML plist output
        // shape captured from a build.sh-signed mvm-vz-supervisor.
        let stdout = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
</dict>
</plist>
"#;
        assert!(entitlement_present_in_codesign_output(stdout));
    }

    #[test]
    fn entitlement_probe_parses_plist_without_entitlement() {
        // A binary that codesign succeeds against but carries no entitlements
        // (or carries a different set) — operator needs to rebuild via
        // tools/build.sh.
        let stdout = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
</dict>
</plist>
"#;
        assert!(!entitlement_present_in_codesign_output(stdout));
    }

    #[test]
    fn entitlement_probe_handles_empty_output() {
        // codesign on an unsigned binary may emit empty output (varies by
        // macOS version). Treat as "no entitlement" rather than "tooling
        // broken" — the doctor's None-path is reserved for "couldn't run
        // codesign at all".
        assert!(!entitlement_present_in_codesign_output(b""));
    }

    #[test]
    fn vz_runtime_probe_parses_supported_payload() {
        let stdout = br#"{"is_supported":true,"macos_version":"26.3.1"}
"#;
        let parsed = parse_vz_probe_output(stdout).expect("valid probe output");
        assert!(parsed.is_supported);
        assert_eq!(parsed.macos_version, "26.3.1");
    }

    #[test]
    fn vz_runtime_probe_parses_unsupported_payload() {
        // Coarse "MDM lockdown or unsupported hardware" signal — the doctor
        // surfaces this as the "VZ NOT SUPPORTED" tag and flips ok to false.
        let stdout = br#"{"is_supported":false,"macos_version":"13.0.0"}"#;
        let parsed = parse_vz_probe_output(stdout).expect("valid probe output");
        assert!(!parsed.is_supported);
        assert_eq!(parsed.macos_version, "13.0.0");
    }

    #[test]
    fn vz_runtime_probe_rejects_malformed_json() {
        assert!(parse_vz_probe_output(b"{not json").is_none());
        assert!(parse_vz_probe_output(b"").is_none());
        // Missing required field — serde_json must reject rather than fill
        // a default, otherwise a partially-broken probe would silently
        // claim is_supported=false.
        assert!(parse_vz_probe_output(br#"{"macos_version":"13.0.0"}"#).is_none());
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
    fn collect_balloon_support_advertises_fc_and_ch() {
        let support = collect_balloon_support();
        // The hand-maintained list in collect_balloon_support must
        // include both rust-vmm backends. If a future refactor drops
        // one, this fails loudly.
        assert_eq!(support.get("firecracker"), Some(&true));
        assert_eq!(support.get("cloud-hypervisor"), Some(&true));
        // And honestly-`false` backends should not be silently dropped.
        assert_eq!(support.get("docker"), Some(&false));
        assert_eq!(support.get("apple-container"), Some(&false));
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
            all_ok: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"all_ok\":true"));
        assert!(json.contains("\"security_posture\""));
        assert!(json.contains("\"tier\""));
        // Plan 74 W5: default (no --workflow) omits the field
        // entirely thanks to `#[serde(skip_serializing_if = …)]`.
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
    // These tests mutate `MVM_DATA_DIR` / `MVM_SHARE_DIR` to redirect
    // doctor's filesystem probes at a tempdir. Env-var mutation is
    // process-wide, so a `Mutex` serializes them.

    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev_data: Option<String>,
        prev_share: Option<String>,
        _tmp_data: Option<tempfile::TempDir>,
        _tmp_share: Option<tempfile::TempDir>,
    }

    impl EnvGuard {
        fn new(data: Option<tempfile::TempDir>, share: Option<tempfile::TempDir>) -> Self {
            let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev_data = std::env::var("MVM_DATA_DIR").ok();
            let prev_share = std::env::var("MVM_SHARE_DIR").ok();
            unsafe {
                if let Some(d) = data.as_ref() {
                    std::env::set_var("MVM_DATA_DIR", d.path());
                }
                if let Some(s) = share.as_ref() {
                    std::env::set_var("MVM_SHARE_DIR", s.path());
                }
            }
            EnvGuard {
                _guard: g,
                prev_data,
                prev_share,
                _tmp_data: data,
                _tmp_share: share,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev_data {
                    Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
                match &self.prev_share {
                    Some(v) => std::env::set_var("MVM_SHARE_DIR", v),
                    None => std::env::remove_var("MVM_SHARE_DIR"),
                }
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
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_path = std::env::var("PATH").ok();
        let prev_tsx = std::env::var("MVM_TSX").ok();
        let prev_cwd = std::env::current_dir().expect("cwd");
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("PATH", "");
            std::env::remove_var("MVM_TSX");
        }
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        // Restore before any assert can fail the test.
        let _ = std::env::set_current_dir(&prev_cwd);
        unsafe {
            match prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
            match prev_tsx {
                Some(v) => std::env::set_var("MVM_TSX", v),
                None => std::env::remove_var("MVM_TSX"),
            }
        }
        drop(g);

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
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_cwd = std::env::current_dir().expect("cwd");
        let prev_tsx = std::env::var("MVM_TSX").ok();
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tsx = bin.join("tsx");
        std::fs::write(&tsx, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tsx, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::remove_var("MVM_TSX");
        }
        std::env::set_current_dir(tmp.path()).expect("chdir");

        let c = ts_runner_check();

        let _ = std::env::set_current_dir(&prev_cwd);
        unsafe {
            match prev_tsx {
                Some(v) => std::env::set_var("MVM_TSX", v),
                None => std::env::remove_var("MVM_TSX"),
            }
        }
        drop(g);

        assert!(c.ok);
        assert!(
            c.info.contains("project-local"),
            "expected 'project-local' marker, got: {}",
            c.info
        );
    }

    #[test]
    fn security_network_policy_default_check_reports_claim_10_holding() {
        // Sprint 52 W3 invariant: `NetworkPolicy::default()` returns
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

    // ---------------- Workflow scoping (plan 74 W5) ----------------

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

    // ── Plan 98 §0.3 — builder-backend check format on Linux ──
    //
    // The selection layer's `auto_detect_default()` queries the real
    // host platform (not the `Platform` enum passed to the check). On
    // Linux CI runners it always returns Libkrun. macOS contributor
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
    fn builder_backend_check_linux_reports_libkrun_auto_detected() {
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
            c.info.starts_with("libkrun — "),
            "expected libkrun-resolved line; got: {}",
            c.info
        );
        assert!(
            c.info.contains("auto-detected"),
            "expected `auto-detected` source label when env unset; got: {}",
            c.info
        );
        assert!(
            c.info.contains("libkrun available") || c.info.contains("libkrun NOT available"),
            "expected per-VMM availability segment; got: {}",
            c.info
        );
    }

    #[cfg(all(target_os = "linux", feature = "builder-vm"))]
    #[test]
    fn builder_backend_check_linux_honors_env_override() {
        let prev = std::env::var_os("MVM_BUILDER_BACKEND");
        unsafe {
            std::env::set_var("MVM_BUILDER_BACKEND", "vz");
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
        // `auto_detect_default()` would have picked libkrun.
        assert!(
            c.info.starts_with("vz — "),
            "expected vz-resolved line under env override; got: {}",
            c.info
        );
        assert!(
            c.info.contains("override via"),
            "expected `override via` source label; got: {}",
            c.info
        );
        // On Linux Vz is never available; line must communicate that.
        assert!(
            c.info.contains("Vz NOT available"),
            "expected `Vz NOT available` segment on Linux; got: {}",
            c.info
        );
    }

    // ── Plan 105 W1 — nested-kvm check + MVM_LINUX_BUILDER_VM line ──

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
}
