# Builder-VM kernel — slim custom Linux 6.12.
#
# = the shared base (`nix/images/kernel/base.nix`) + the builder-only
# infrastructure a workload guest never needs. Source of truth for the
# base config lives in `base.nix`; this file owns only the delta.
#
# The flake passes `base` in (it builds the workload kernel from the same
# `nix/images/kernel/base.nix`). base.nix is imported relatively by the
# builder-vm flake rather than through `workspace`: importing through
# `workspace` forces realisation of that filtered store path, which
# `nix flake check --no-build` refuses.
#
# Builder-only features (why each is here, not in base):
#   - VIRTIO_FS / FUSE_FS / FUSE_DAX — the builder mounts four virtio-fs
#     host shares (/work, /out, /job, /mvm-bins). DAX lets eligible shares
#     bypass the guest page cache by mapping host pages directly into the
#     guest DAX window; the dependency chain (ZONE_DEVICE, MEMORY_HOTPLUG,
#     etc.) is builder-only dead weight for a sealed workload.
#   - NAMESPACES + cgroup cluster — the nix-build sandbox needs user
#     namespaces and cgroups v2. A sealed single-workload guest doesn't.
#   - NETFILTER / iptables cluster — `mvm-host-vm-init` installs an
#     OUTPUT-chain default-deny egress lockdown. Workload egress is
#     enforced host-side (egress proxy) +
#     via guest blackhole *routes* (mvm-guest-netinit, rtnetlink), not
#     iptables, so the guest kernel needs no netfilter tables.
#
# This kernel = the shared base + the builder delta below. It folds in
# the dm-verity / conntrack / ext2 slimming (commit 2e0a8381, audited
# against mvm-host-vm-init): those symbols are force-dropped here (and
# absent from base), kept only by the workload kernel. The resolved
# config is byte-identical to that audited slim builder kernel — verify:
#
#   nix build .#kernel-configfile -o /tmp/b && grep '=y$' /tmp/b | sort

{ pkgs, base }:

base.mkKernel {
  extraEnables = [
    "BLK_DEV_LOOP"
    # virtio-fs (FUSE-backed) — host share mounts
    "VIRTIO_FS" "FUSE_FS" "MIGRATION" "MEMORY_HOTPLUG" "MEMORY_HOTREMOVE" "SPARSEMEM_VMEMMAP" "ZONE_DEVICE" "FS_DAX" "FUSE_DAX"

    # namespaces + cgroups v2 — nix-build sandbox
    "NAMESPACES" "UTS_NS" "IPC_NS" "USER_NS" "PID_NS" "NET_NS"
    "CGROUPS" "MEMCG" "BLK_CGROUP" "CGROUP_SCHED" "FAIR_GROUP_SCHED"
    "CGROUP_PIDS" "CGROUP_FREEZER" "CGROUP_DEVICE" "CGROUP_CPUACCT"
    "CPUSETS"

    # iptables-legacy — egress lockdown. Only
    # the OUTPUT owner-match + default-DROP ruleset is used
    # (mvm-host-vm-init network.rs); no conntrack/state/mark match, so
    # those symbols are force-dropped in extraDisables below.
    "NETFILTER" "NETFILTER_ADVANCED" "NETFILTER_XTABLES"
    "IP_NF_IPTABLES" "IP_NF_FILTER" "IP_NF_TARGET_REJECT"
    "NETFILTER_XT_MATCH_OWNER"
  ];
  extraDisables = [
    # Audited against crates/mvm-host-vm-init. Listed here (not merely
    # absent from base) so olddefconfig drops the defconfig defaults:
    #   - dm-verity: the builder boots `ro` with no roothash and never
    #     opens a dm device (veritysetup only `format`s in userspace);
    #     verified boot is a workload-kernel concern.
    #   - conntrack/state/mark: the egress lockdown is owner-match +
    #     default-DROP only — no stateful match invoked.
    "MD" "BLK_DEV_DM" "DM_VERITY"
    "NF_CONNTRACK" "NF_DEFRAG_IPV4"
    "NETFILTER_XT_MATCH_STATE" "NETFILTER_XT_MATCH_CONNTRACK"
    "NETFILTER_XT_MARK"

    # IPv6 is a workload-kernel feature, not a shared one: the builder VM
    # reaches its network over an IPv4 virtio-net gateway. Force-drop it here
    # because defconfig enables it, and its optional IPsec selectors would
    # otherwise re-enable the shared XFRM framework that base.nix forbids.
    "IPV6"
  ];
}
