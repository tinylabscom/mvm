//! `mvmctl ls` / `mvmctl ps` — list running VMs.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_backend::backend::AnyBackend;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Show all VMs (including stopped)
    #[arg(short, long)]
    pub all: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Filter by sandbox tag (`KEY=VALUE`). Repeatable; all must match.
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Include VMs whose TTL has expired but the reaper has not yet
    /// torn down. By default these are hidden from the listing.
    #[arg(long)]
    pub show_expired: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use anyhow::Context;
    use mvm_core::vm_backend::VmInfo;

    // Parse the tag filter early so an invalid `--tag` errors out before
    // we go talk to backends. Validation is shared with `mvmctl up`,
    // which keeps charset/length invariants consistent.
    let mut tag_filter: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for raw in &args.tags {
        let (k, v) = mvm_core::crypto::policy::InputValidator::parse_tag_arg(raw)
            .with_context(|| format!("Invalid --tag value: {:?}", raw))?;
        tag_filter.insert(k, v);
    }

    let mut all_vms: Vec<VmInfo> = Vec::new();

    // Collect from Apple Container backend
    let ac_backend = AnyBackend::from_hypervisor("apple-container");
    if let Ok(vms) = ac_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Docker backend
    let docker_backend = AnyBackend::from_hypervisor("docker");
    if let Ok(vms) = docker_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Firecracker backend. Lima is gone (ADR-013) — Firecracker
    // runs directly on Linux+KVM hosts.
    let fc_backend = AnyBackend::from_hypervisor("firecracker");
    if let Ok(vms) = fc_backend.list() {
        all_vms.extend(vms);
    }

    let _ = args.all;

    // Cross-reference the backend listing with the persistent name
    // registry so tags / TTLs / auto-resume can flow through `mvmctl
    // ls` without changing the `VmInfo` shape every backend produces.
    // If the registry can't be loaded we fall through to "no metadata"
    // and only the backend listing is shown.
    let registry_path = mvm::vm::name_registry::registry_path();
    let registry = mvm::vm::name_registry::VmNameRegistry::load(&registry_path).unwrap_or_default();

    let now = chrono::Utc::now();
    let is_expired = |reg: &mvm::vm::name_registry::VmRegistration| -> bool {
        reg.expires_at
            .as_deref()
            .and_then(mvm_core::util::time::parse_iso8601)
            .map(|t| t < now)
            .unwrap_or(false)
    };

    all_vms.retain(|vm| {
        let reg_entry = registry.lookup(&vm.name);
        // Tag filter: every key/value in `tag_filter` must be present.
        if !tag_filter.is_empty() {
            let Some(reg) = reg_entry else { return false };
            for (k, v) in &tag_filter {
                if reg.tags.get(k).map(String::as_str) != Some(v.as_str()) {
                    return false;
                }
            }
        }
        // Expiry filter: hide VMs past their TTL unless asked.
        if !args.show_expired
            && let Some(reg) = reg_entry
            && is_expired(reg)
        {
            return false;
        }
        true
    });

    if args.json {
        // JSON output augments the backend `VmInfo` with the metadata
        // we just looked up, so SDK callers (Phase B1) get tags and
        // expiry without a second registry round-trip.
        // ADR-053 §3 / plan 74 W2: `readiness` and
        // `last_readiness_change_at` thread through here from the
        // registry, populated by `mvmctl up`'s launch milestones.
        // Legacy registry entries that pre-date W2 serialize as
        // `null` for both fields.
        #[derive(serde::Serialize)]
        struct LsRow<'a> {
            #[serde(flatten)]
            info: &'a VmInfo,
            tags: &'a std::collections::BTreeMap<String, String>,
            expires_at: Option<&'a str>,
            auto_resume: bool,
            expired: bool,
            readiness: Option<&'a mvm_core::domain::instance::InstanceReadiness>,
            last_readiness_change_at: Option<&'a str>,
        }
        let empty_tags: std::collections::BTreeMap<String, String> = Default::default();
        let rows: Vec<LsRow<'_>> = all_vms
            .iter()
            .map(|vm| {
                let reg = registry.lookup(&vm.name);
                LsRow {
                    info: vm,
                    tags: reg.map(|r| &r.tags).unwrap_or(&empty_tags),
                    expires_at: reg.and_then(|r| r.expires_at.as_deref()),
                    auto_resume: reg.map(|r| r.auto_resume).unwrap_or(true),
                    expired: reg.map(is_expired).unwrap_or(false),
                    readiness: reg.and_then(|r| r.readiness.as_ref()),
                    last_readiness_change_at: reg
                        .and_then(|r| r.last_readiness_change_at.as_deref()),
                }
            })
            .collect();
        crate::json_out::emit_json(&rows)?;
        return Ok(());
    }

    if all_vms.is_empty() {
        println!("No running VMs.");
        return Ok(());
    }

    // Docker-style table output
    println!(
        "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} IMAGE",
        "NAME", "BACKEND", "STATUS", "CPUS", "MEMORY", "PORTS"
    );
    for vm in &all_vms {
        let backend_name = if vm.flake_ref.as_deref().is_some() {
            // Determine backend from context
            if mvm_core::platform::current().has_apple_containers() {
                "apple-container"
            } else {
                "firecracker"
            }
        } else {
            "unknown"
        };
        let status = format!("{:?}", vm.status);
        let mem = if vm.memory_mib > 0 {
            format!("{}Mi", vm.memory_mib)
        } else {
            "-".to_string()
        };
        let image = vm
            .flake_ref
            .as_deref()
            .or(vm.profile.as_deref())
            .unwrap_or("-");
        let ports = if vm.ports.is_empty() {
            "-".to_string()
        } else {
            vm.ports
                .iter()
                .map(|p| format!("{}→{}", p.host, p.guest))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} {}",
            vm.name,
            backend_name,
            status,
            if vm.cpus > 0 {
                vm.cpus.to_string()
            } else {
                "-".to_string()
            },
            mem,
            ports,
            image,
        );
    }

    Ok(())
}
