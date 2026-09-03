use std::collections::BTreeMap;

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;

use crate::ui;
use mvm_core::config::fc_version;
use mvm_core::platform;

mod builder;
mod daemons;
mod nix_checks;
mod platform_checks;
mod registry;
mod runtime;
mod security;
mod security_checks;
mod toolchain;
mod warm_start;

#[cfg(test)]
mod tests;

// `HostFdeStatus`, `detect_host_fde_status`, and `detect_host_path_encryption_status`
// stay `pub(crate)` on their definitions in `security_checks` (crate-wide
// reachable) but have no caller outside that module today, so they are not
// re-exported here — doing so would trip the unused-import lint.
pub(crate) use security_checks::require_local_volume_host_path_encrypted;
pub use toolchain::{ZigbuildProbe, probe_zigbuild};

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

#[derive(Debug, Serialize)]
struct DoctorReport {
    /// Workflow scope this report was filtered for, or `None` for
    /// the default "all checks" mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<&'static str>,
    checks: Vec<Check>,
    security_posture: security::SecurityPostureReport,
    /// Per-backend virtio-balloon capability surfaced by
    /// `VmBackend::capabilities`. Lets users predict which backend
    /// will honour `mem_initial` in their manifest before launching.
    /// Ordered by `BTreeMap`'s natural backend-name order so JSON
    /// output is deterministic.
    balloon_support: BTreeMap<String, bool>,
    /// Per-backend warm-start tier + the Linux fast-resume substrate probe.
    /// Surfaces the honest capability matrix so a user can predict which
    /// backend resumes from RAM, reboots from disk, or refuses recovery.
    warm_start: warm_start::WarmStartReport,
    /// Per-backend capability matrix — snapshot tier, network/storage
    /// disposition, and the boot-latency (standby-pool) axis — the
    /// tradeoffs behind `--hypervisor`, aggregated from `VmBackend`.
    capability_table: Vec<warm_start::BackendCapabilityRow>,
    all_ok: bool,
}

pub fn run(json: bool, workflow: Option<DoctorWorkflow>) -> Result<()> {
    // ── Prerequisites (user must install before bootstrap) ───────
    let mut checks = vec![
        toolchain::check_cmd("rustup", "prerequisites", &["--version"]),
        toolchain::check_cmd("cargo", "prerequisites", &["--version"]),
    ];

    // ── Managed Tools (installed inside the dev VM) ──────────────
    //
    // Builder tooling (nix, firecracker, nix store, flakes) belongs to
    // the dev VM, never the host. When the dev VM isn't running these
    // probes return informational `Check`s and doctor exits 0 — the host
    // is not expected to own them. Routing still goes through `VM_NAME`,
    // which `shell::run_on_vm` maps to the platform's default LinuxEnv.
    let vm_up = builder::dev_vm_running();
    checks.push(if vm_up {
        nix_checks::nix_version_check()
    } else {
        builder::builder_tool_skipped("nix", "tools")
    });
    checks.push(if vm_up {
        toolchain::check_vm_cmd("firecracker", "tools", "firecracker --version")
    } else {
        builder::builder_tool_skipped("firecracker", "tools")
    });

    checks.push(Check {
        name: "fc target",
        category: "tools",
        ok: true,
        info: fc_version(),
    });

    // Nix flake support check
    checks.push(if vm_up {
        nix_checks::nix_flakes_check()
    } else {
        builder::builder_tool_skipped("nix flakes", "tools")
    });

    // ── Platform ──────────────────────────────────────────────────
    let plat = platform::current();
    checks.push(Check {
        name: "platform",
        category: "platform",
        ok: true,
        info: platform_checks::platform_description(plat),
    });

    checks.push(platform_checks::kvm_check(plat, false));
    checks.push(platform_checks::nested_kvm_check(plat));
    checks.push(platform_checks::libkrun_check(plat));
    checks.push(builder::builder_backend_check(plat));
    checks.push(builder::builder_capabilities_check());
    checks.push(builder::boot_image_acquisition_check());
    checks.push(runtime::runtime_backend_check(plat));
    checks.push(platform_checks::residency_check());
    checks.push(builder::builder_residency_check());
    checks.push(platform_checks::network_backend_check(plat));
    checks.push(platform_checks::egress_proxy_check());
    checks.push(platform_checks::ts_runner_check());
    checks.push(builder::stage0_status_check());
    checks.push(builder::builder_store_check());
    checks.push(builder::builder_egress_check());
    checks.push(registry::registry_drift_check());
    checks.push(daemons::host_agent_daemon_check());
    checks.push(builder::builderd_daemon_check());
    checks.push(builder::builder_transport_check(plat));

    checks.push(platform_checks::disk_space_check(false));

    // Nix store health
    checks.push(if vm_up {
        nix_checks::nix_store_check()
    } else {
        builder::builder_tool_skipped("nix store", "tools")
    });
    checks.push(if vm_up {
        nix_checks::nix_store_size_check()
    } else {
        builder::builder_tool_skipped("nix store size", "disk")
    });

    // ── Security posture (folded in from the old `mvmctl security`) ──
    checks.push(security_checks::security_audit_log_check());
    checks.push(security_checks::security_audit_chain_check());
    checks.push(security_checks::security_host_fde_check());
    checks.push(security_checks::security_data_dir_mode_check());
    checks.push(security_checks::security_proxy_socket_mode_check());
    checks.push(security_checks::security_dev_image_check());
    checks.push(security_checks::security_deny_config_check());
    checks.push(security_checks::security_default_network_check());
    checks.push(security_checks::security_network_policy_default_check());
    checks.push(security_checks::security_default_run_profile_check());
    checks.push(security_checks::security_snapshot_key_check());
    checks.push(security_checks::security_snapshot_dirs_check());
    checks.push(security_checks::security_signing_check());

    // ── Active backend security posture ──────
    let security_posture = security::collect_security_posture();

    // ── Balloon capability per backend ────────────────────────────
    let balloon_support = security::collect_balloon_support();

    // ── Warm-start capability per backend ───────
    let warm_start = warm_start::collect_warm_start_support();

    // ── Per-backend capability matrix ─────────────────────────────
    let capability_table = warm_start::collect_capability_table();

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
    security::render_security_posture(&report.security_posture);
    security::render_balloon_support(&report.balloon_support);
    warm_start::render_warm_start_support(&report.warm_start);
    warm_start::render_capability_table(&report.capability_table);
}

fn issue_summary_lines(missing: &[&Check]) -> Vec<String> {
    missing
        .iter()
        .map(|check| format!("  {} — {}", check.name, check.info))
        .collect()
}
