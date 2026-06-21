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

impl Args {
    pub(in crate::commands) fn touches_vm_state(&self) -> bool {
        // `ls --all` is the historical listing surface. It must render
        // registry-only stopped rows before any convergence pass can sweep them.
        !self.all
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use anyhow::Context;
    use mvm_core::vm_backend::{VmInfo, VmStatus};

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

    // Aggregate across every backend (QEMU, libkrun, Firecracker, Apple
    // Container, Docker) so a VM started under any VMM is listed — not just
    // the platform default. Single source of truth in `AnyBackend::list_all`.
    // Cross-reference the backend listing with the persistent name
    // registry so tags / TTLs / auto-resume can flow through `mvmctl
    // ls` without changing the `VmInfo` shape every backend produces.
    // If the registry can't be loaded we fall through to "no metadata"
    // and only the backend listing is shown.
    let registry_path = mvm::vm::name_registry::registry_path();
    let registry = mvm::vm::name_registry::VmNameRegistry::load(&registry_path).unwrap_or_default();

    let mut all_vms: Vec<VmInfo> = AnyBackend::list_all();
    merge_registry_only_stopped_rows(&mut all_vms, &registry, args.all);
    if !args.all {
        all_vms.retain(|vm| !matches!(vm.status, VmStatus::Stopped));
    }

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
        // we just looked up, so SDK callers get tags and expiry
        // without a second registry round-trip. `readiness` and
        // `last_readiness_change_at` thread through here from the
        // registry, populated by `mvmctl up`'s launch milestones.
        // Legacy registry entries that pre-date the readiness fields
        // serialize as `null` for both.
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
        // Prefer the VM's actual owning backend (resolved from its
        // state-dir pid marker — qemu/libkrun/firecracker); fall back to a
        // platform guess for the marker-less vz supervisor so the column
        // is accurate for pid-file VMMs.
        let backend_name: String = AnyBackend::for_started_vm(&vm.name)
            .map(|b| b.name().to_string())
            .unwrap_or_else(|| {
                if mvm_core::platform::current().is_vz_default_tier() {
                    "vz".to_string()
                } else {
                    "firecracker".to_string()
                }
            });
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

fn merge_registry_only_stopped_rows(
    all_vms: &mut Vec<mvm_core::vm_backend::VmInfo>,
    registry: &mvm::vm::name_registry::VmNameRegistry,
    include_stopped: bool,
) {
    if !include_stopped {
        return;
    }

    let listed: std::collections::BTreeSet<String> =
        all_vms.iter().map(|vm| vm.name.clone()).collect();
    for (name, reg) in &registry.vms {
        if listed.contains(name.as_str()) {
            continue;
        }
        all_vms.push(mvm_core::vm_backend::VmInfo {
            id: mvm_core::vm_backend::VmId(name.clone()),
            name: name.clone(),
            status: mvm_core::vm_backend::VmStatus::Stopped,
            guest_ip: reg.guest_ip.clone(),
            cpus: 0,
            memory_mib: 0,
            profile: None,
            revision: None,
            flake_ref: None,
            ports: Vec::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered(name: &str) -> mvm::vm::name_registry::VmNameRegistry {
        let mut registry = mvm::vm::name_registry::VmNameRegistry::default();
        registry
            .register_with_metadata(mvm::vm::name_registry::RegisterParams::minimal(
                name,
                "/tmp/mvm-test-vm",
                "default",
            ))
            .unwrap();
        registry
    }

    fn running_vm(name: &str) -> mvm_core::vm_backend::VmInfo {
        mvm_core::vm_backend::VmInfo {
            id: mvm_core::vm_backend::VmId(name.to_string()),
            name: name.to_string(),
            status: mvm_core::vm_backend::VmStatus::Running,
            guest_ip: None,
            cpus: 1,
            memory_mib: 256,
            profile: None,
            revision: None,
            flake_ref: None,
            ports: Vec::new(),
        }
    }

    #[test]
    fn registry_only_rows_appear_when_all_requested() {
        let registry = registered("detached-vz");
        let mut rows = Vec::new();

        merge_registry_only_stopped_rows(&mut rows, &registry, true);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "detached-vz");
        assert!(matches!(
            rows[0].status,
            mvm_core::vm_backend::VmStatus::Stopped
        ));
    }

    #[test]
    fn registry_only_rows_are_hidden_without_all() {
        let registry = registered("detached-vz");
        let mut rows = Vec::new();

        merge_registry_only_stopped_rows(&mut rows, &registry, false);

        assert!(rows.is_empty());
    }

    #[test]
    fn registry_merge_does_not_duplicate_backend_rows() {
        let registry = registered("running-vz");
        let mut rows = vec![running_vm("running-vz")];

        merge_registry_only_stopped_rows(&mut rows, &registry, true);

        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows[0].status,
            mvm_core::vm_backend::VmStatus::Running
        ));
    }
}
