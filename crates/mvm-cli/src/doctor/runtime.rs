//! Workload runtime backend availability.

use super::Check;
use mvm_core::platform;

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
pub(super) fn runtime_backend_check(plat: platform::Platform) -> Check {
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
        Platform::MacOS => "macOS — native `hvf` on macOS 26+ Apple Silicon; \
             standard builds and releases do not require libkrun"
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

/// Whether this host's spawn scope can carry an allowed-CPU set, which is what
/// exclusive core placement needs. Informational: a host without it refuses a
/// placed topology at admission, and runs everything else as before.
pub(super) fn core_placement_check() -> Check {
    describe_core_placement(mvm_core::spawn_scope::cpuset_gap())
}

fn describe_core_placement(gap: Option<mvm_core::spawn_scope::CpusetGap>) -> Check {
    let info = match gap {
        None => "cpuset controller delegated to the systemd user manager — exclusive core \
                 placement can be served on firecracker"
            .to_string(),
        Some(gap) => format!(
            "exclusive core placement is refused here: {}",
            gap.describe()
        ),
    };
    Check {
        name: "core placement",
        category: "platform",
        ok: true,
        info,
    }
}

/// Which cores the kernel keeps off the general scheduler, and whether the
/// cores admitted topologies hold exclusively are among them. MVM confines its
/// own launches; anything else on the host is scheduled onto held cores unless
/// the kernel isolates them.
pub(super) fn isolated_cores_check() -> Check {
    let held = mvm_client::diagnostics::exclusive_cores_held_on_host();
    describe_isolated_cores(mvm_core::spawn_scope::isolated_cpus(), held.as_ref().ok())
}

fn describe_isolated_cores(
    isolated: Option<mvm_contract::protocol::cpu_set::CpuSet>,
    held: Option<&mvm_contract::protocol::cpu_set::CpuSet>,
) -> Check {
    let Some(isolated) = isolated else {
        return Check {
            name: "isolated cores",
            category: "platform",
            ok: true,
            info: "the kernel publishes no isolated-CPU list on this host".to_string(),
        };
    };
    let shown = if isolated.is_empty() {
        "none".to_string()
    } else {
        isolated.to_string()
    };
    let info = match held.filter(|held| !held.is_empty()) {
        None => format!("isolated from the general scheduler: {shown}; no cores held exclusively"),
        Some(held) => {
            let exposed = held.difference(&isolated);
            if exposed.is_empty() {
                format!(
                    "cores held exclusively ({held}) are all isolated from the general scheduler"
                )
            } else {
                format!(
                    "isolated from the general scheduler: {shown}; held exclusively but not \
                     isolated: {exposed} — host processes MVM does not start can still run there"
                )
            }
        }
    };
    Check {
        name: "isolated cores",
        category: "platform",
        ok: true,
        info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::cpu_set::CpuSet;
    use mvm_core::platform::Platform;

    #[test]
    fn core_placement_reports_delegation_or_the_gap() {
        assert!(describe_core_placement(None).info.contains("delegated"));
        let gap = describe_core_placement(Some(mvm_core::spawn_scope::CpusetGap::NotDelegated));
        assert!(gap.info.contains("refused"), "{}", gap.info);
        assert!(gap.info.contains("Delegate="), "{}", gap.info);
    }

    #[test]
    fn isolated_cores_name_held_cores_the_kernel_does_not_isolate() {
        let set = |list: &str| CpuSet::parse(list).unwrap();
        assert!(
            describe_isolated_cores(None, None)
                .info
                .contains("no isolated-CPU list")
        );
        assert!(
            describe_isolated_cores(Some(set("")), None)
                .info
                .contains("isolated from the general scheduler: none")
        );
        let held = set("2-3");
        assert!(
            describe_isolated_cores(Some(set("2-5")), Some(&held))
                .info
                .contains("are all isolated")
        );
        let partial = describe_isolated_cores(Some(set("2")), Some(&held));
        assert!(
            partial
                .info
                .contains("held exclusively but not isolated: 3"),
            "{}",
            partial.info
        );
    }

    #[test]
    fn runtime_backend_check_macos_reports_native_hvf_without_libkrun() {
        let c = runtime_backend_check(Platform::MacOS);
        assert!(c.ok);
        assert!(c.info.contains("`hvf`"), "got: {}", c.info);
        assert!(
            !c.info.contains("`libkrun`"),
            "standard macOS runtime must not advertise libkrun; got: {}",
            c.info
        );
    }
}
