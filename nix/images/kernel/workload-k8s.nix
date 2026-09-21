# Workload-guest kernel for in-guest orchestrators — Linux 6.12.
#
# = the shared base (`nix/images/kernel/base.nix`) + the same dm-verity
# delta `workload.nix` carries (verified boot, virtio-fs volumes) + the
# cgroup / namespace / netfilter plumbing a Kubernetes guest (rootless k3s,
# see specs/plans/2026-09-20-kubernetes-in-microvm.md) needs:
#
#   CGROUPS + controllers   — the kubelet and containerd place every pod
#                 container in cgroups; without a mounted hierarchy they
#                 cannot start anything.
#   NAMESPACES + per-ns     — every container is a netns/mount/ipc/pid/uts/
#                 cgroup namespace; USER_NS is what makes the rootless
#                 control plane possible at the mvm workload uid.
#   NETFILTER + conntrack/
#                 iptables    — kube-proxy and the CNI program in-guest
#                 pod/service rules. The guest still has no NIC: this is
#                 the cluster-internal datapath, not a host-facing firewall.
#   BRIDGE / VETH / VXLAN   — the in-guest pod network (flannel).
#   DEVPTS_FS /
#     POSIX_MQUEUE          — container ptys (`kubectl exec`) and POSIX
#                 mqueue mounts.
#
# Where `workload.nix` *required-disables* CGROUPS / NAMESPACES / NETFILTER
# for the sealed single-workload posture (and the config budget ratchet in
# `xtask check-kernel-config-budget` covers only the sealed workload
# kernel), this variant keeps them: hosting a kubelet IS the posture. It is
# deliberately outside the tiny-kernel budget — measure it with
# `workload-k8s-metrics` and record the cost where the variant is adopted.
#
# Kept disabled from the workload delta: eBPF (BPF_SYSCALL), perf,
# checkpoint/restore, loop/md-raid, 9p/btrfs, IPv6 tunnel/IPsec families.
# Degraded metrics are acceptable for a dev/test-tier cluster; each cut
# revisited when a smoke test proves a hard need.

{
  pkgs,
  base,
  optimizeForSize ? false,
}:

base.mkKernel {
  extraEnables = [
    # ── dm-verity + volume transport delta (same as workload.nix) ──
    "MD"
    "BLK_DEV_DM"
    "DM_VERITY"
    "VIRTIO_FS"
    "FUSE_FS"
    "MIGRATION"
    "MEMORY_HOTPLUG"
    "MEMORY_HOTREMOVE"
    "SPARSEMEM_VMEMMAP"
    "ZONE_DEVICE"
    "FS_DAX"
    "FUSE_DAX"
    "IPV6"

    # ── cgroup v2 hierarchy + the controllers a kubelet delegates ──
    "CGROUPS"
    "CGROUP_SCHED"
    "CGROUP_CPUACCT"
    "MEMCG"
    "CGROUP_PIDS"
    "CGROUP_FREEZER"
    "CGROUP_DEVICE"
    "BLK_CGROUP"

    # ── namespaces (USER_NS is the rootless control plane's floor) ──
    "NAMESPACES"
    "UTS_NS"
    "IPC_NS"
    "USER_NS"
    "PID_NS"
    "NET_NS"
    "CGROUP_NS"
    "TIME_NS"

    # ── in-guest pod/service datapath ──
    "NETFILTER"
    "NETFILTER_ADVANCED"
    "NETFILTER_XTABLES"
    "NF_CONNTRACK"
    "IP_NF_IPTABLES"
    "IP_NF_FILTER"
    "IP_NF_NAT"
    "NF_NAT_MASQUERADE"
    "IP_NF_TARGET_MASQUERADE"
    "VETH"
    "VXLAN"
    "BRIDGE_NETFILTER"

    # ── container runtime basics base.nix cuts ──
    "DEVPTS_FS"
    "POSIX_MQUEUE"
  ]
  ++ pkgs.lib.optionals optimizeForSize [ "CC_OPTIMIZE_FOR_SIZE" ];

  # Same safe cuts as the workload kernel: no md-raid, no loop, no eBPF
  # syscall interface, no perf, no checkpoint/restore, no 9p/btrfs, no
  # IPv6 tunnel/IPsec families, no VLAN tagging.
  extraDisables = [
    "IPV6_MIP6"
    "IPV6_VTI"
    "INET6_AH"
    "INET6_ESP"
    "INET6_ESP_OFFLOAD"
    "INET6_ESPINTCP"
    "INET6_IPCOMP"
    "INET6_XFRM_TUNNEL"
    "INET6_TUNNEL"
    "IPV6_SIT"
    "BLK_DEV_MD"
    "BLK_DEV_LOOP"
    "BPF_SYSCALL"
    "PERF_EVENTS"
    "PROFILING"
    "IKCONFIG"
    "IKCONFIG_PROC"
    "CHECKPOINT_RESTORE"
    "NET_9P"
    "BTRFS_FS"
    "GNSS"
    "VLAN_8021Q"
  ]
  ++ pkgs.lib.optionals optimizeForSize [ "CC_OPTIMIZE_FOR_PERFORMANCE" ];

  # The sealed workload kernel's required CGROUPS/NAMESPACES disables are
  # exactly what this variant exists to undo — pass none.
  requiredExtraDisables = [ ];

  # BRIDGE is a base.nix *required* disable ("network plumbing outside the
  # guest contract"). The CNI pod bridge is in-guest-only and this variant
  # is the documented exception to that contract; the enable guard asserts
  # it survives olddefconfig.
  disableExemptions = [ "BRIDGE" ];
}
