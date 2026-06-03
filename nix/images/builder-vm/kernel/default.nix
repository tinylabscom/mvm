# Builder-VM kernel — slim custom Linux 6.12.
#
# = the shared base (`./base.nix`) + the builder-only infrastructure a
# workload guest never needs. Source of truth for the base config lives
# in `base.nix`; this file owns only the delta.
#
# The flake passes `base` in (it builds the workload kernel from the same
# `./base.nix`). base.nix is kept inside this flake's source tree rather
# than under `nix/lib/`: importing it through the `workspace` path forces
# realisation of that store path, which `nix flake check --no-build`
# refuses.
#
# Builder-only features (why each is here, not in base):
#   - VIRTIO_FS / FUSE_FS  — the builder mounts four virtio-fs host
#     shares (/work, /out, /job, /mvm-bins). virtio-fs is FUSE-backed.
#   - NAMESPACES + cgroup cluster — the nix-build sandbox needs user
#     namespaces and cgroups v2. A sealed single-workload guest doesn't.
#   - NETFILTER / iptables cluster — `mvm-host-vm-init` installs an
#     OUTPUT-chain default-deny egress lockdown (Plan 73 B.2.y /
#     ADR-047). Workload egress is enforced host-side (egress proxy) +
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
    # virtio-fs (FUSE-backed) — host share mounts
    "VIRTIO_FS" "FUSE_FS"

    # namespaces + cgroups v2 — nix-build sandbox
    "NAMESPACES" "UTS_NS" "IPC_NS" "USER_NS" "PID_NS" "NET_NS"
    "CGROUPS" "MEMCG" "BLK_CGROUP" "CGROUP_SCHED" "FAIR_GROUP_SCHED"
    "CGROUP_PIDS" "CGROUP_FREEZER" "CGROUP_DEVICE" "CGROUP_CPUACCT"
    "CPUSETS"

    # iptables-legacy — egress lockdown (ADR-047 / Plan 73 B.2.y). Only
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
  ];
}
