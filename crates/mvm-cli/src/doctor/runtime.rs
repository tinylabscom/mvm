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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::platform::Platform;

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
}
