# Workload-guest kernel — slim custom Linux 6.12.
#
# = the shared base (`nix/images/kernel/base.nix`) + the dm-verity delta
# a workload guest needs for verified boot. The builder never opens a
# dm-verity device (it boots `root=/dev/vda ro` with no roothash, and
# veritysetup only runs `format` in userspace); those symbols are
# force-dropped in builder.nix. Workload guests do: the kernel must be
# able to open the dm-verity device the initramfs mounts as root.
#
# Built-in symbols (no /lib/modules tree, so `=m` could never load):
#   MD          — device-mapper block layer
#   BLK_DEV_DM  — the dm block device
#   DM_VERITY   — dm-verity target (hash-tree + roothash verification)
#   VIRTIO_FS / FUSE_FS / FUSE_DAX — virtio-fs transport for host-directory
#                 volume shares; the guest mounts each `mvm.uvols=` cmdline
#                 entry over it. DAX lets eligible shares bypass the guest
#                 page cache by mapping host pages directly into the guest DAX
#                 window. The dependency chain (ZONE_DEVICE, MEMORY_HOTPLUG,
#                 etc.) is no longer builder-only dead weight: sealed workloads
#                 can boot from a virtiofs root and map DAX-backed uvols.
# The flake passes `base` in so both the builder and workload kernels share
# one `base.nix` source. base.nix is imported relatively by the builder-vm
# flake rather than through `workspace`, for the same reason as builder.nix:
# importing through `workspace` forces realisation of the filtered store
# path, which `nix flake check --no-build` refuses.

{
  pkgs,
  base,
  optimizeForSize ? true,
}:

base.mkKernel {
  extraEnables = [
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
  ]
  ++ pkgs.lib.optionals optimizeForSize [ "CC_OPTIMIZE_FOR_SIZE" ];
  # Workload-only disables. Each drop lives here (not in shared base.nix)
  # because it depends on a workload-specific enable or would be unsafe for
  # the builder kernel:
  #
  #   NETFILTER   — the guest enforces egress host-side (egress proxy) + via
  #                 blackhole routes (mvm-guest-netinit, rtnetlink), never
  #                 in-guest iptables. The builder kernel KEEPS netfilter for
  #                 its OUTPUT-chain egress lockdown, so this cannot go in base.
  #   BLK_DEV_MD  — the software-RAID personality (md_mod + kworker/R-md*). We
  #                 enable the CONFIG_MD *umbrella* above only so device-mapper
  #                 (BLK_DEV_DM) and dm-verity (Claim 3 verified boot) build; the
  #                 RAID arrays themselves are never assembled in a single-disk
  #                 (vda) guest. Dropping BLK_DEV_MD keeps MD + BLK_DEV_DM +
  #                 DM_VERITY (asserted by base.nix's olddefconfig guard) while
  #                 deleting the unused RAID core. Workload-only because base
  #                 never enables the MD menu, so it has no effect there.
  #   BLK_DEV_LOOP — loopback block devices (loop0–7). No mvm path loop-mounts
  #                 in-guest (the OCI rootfs is virtio-blk `vda`, volumes are
  #                 virtio-fs, dm-verity is dm). Kept OUT of base so the builder
  #                 kernel — which may loop-mount while assembling images — is
  #                 unaffected. TRADEOFF: a user workload that loop-mounts a
  #                 squashfs / disk image in-guest would need this re-enabled;
  #                 unlike NBD/NVMe (no host-side device exists) loop is
  #                 guest-internal, so this is a policy choice, not a free cut.
  #   BPF_SYSCALL / PERF / IKCONFIG / CHECKPOINT_RESTORE — the sealed workload
  #                 path has no eBPF loader, no perf tooling, no
  #                 `/proc/config.gz` consumer, and no CRIU-style
  #                 checkpoint/restore contract. Workload checkpoints are a
  #                 host-level lifecycle feature, not an in-guest process
  #                 checkpoint feature. `NET` still selects the core `BPF`
  #                 symbol in Linux 6.12, so the syscall-facing interface goes
  #                 away here but the interpreter stays built-in until the
  #                 workload networking contract changes.
  #   NAMESPACES / CGROUPS — the sealed guest runs one admitted workload and
  #                 never creates namespace or cgroup hierarchies. Those are
  #                 required by the builder VM's Nix sandbox and therefore
  #                 stay enabled only in builder.nix. They are required cuts
  #                 here so Kconfig cannot silently select them back on.
  #
  # The next four are boot-probe eliminations: each is compiled in by the
  # defconfig base and *initialises at boot* on a single-workload OCI microVM
  # that can never use it. They barely move the built-in symbol count, so the
  # size budget alone never surfaced them — the win is deleted init work and
  # registration threads on the cold-boot path, not bytes.
  #   NET_9P      — the 9P2000 (9pnet) resource-sharing transport. A sealed
  #                 workload shares host directories over virtio-fs, never 9p,
  #                 so the "9pnet: Installing 9P2000 support" init is pure
  #                 boot-probe cost with no reachable transport behind it.
  #   BTRFS_FS    — the workload rootfs is ext4-on-virtio-blk, dm-verity sealed
  #                 (Claim 3); no guest mounts btrfs. Dropping it deletes the
  #                 "Btrfs loaded" registration and its background workers.
  #   GNSS        — GPS/GNSS receiver core. No microVM exposes a GNSS device;
  #                 "gnss: GNSS driver registered" registers a major number for
  #                 hardware that can never appear behind virtio.
  #   VLAN_8021Q  — 802.1Q VLAN tagging. Guest egress is host-mediated (egress
  #                 proxy over vsock), never in-guest VLAN interfaces, so the
  #                 "8021q: 802.1Q VLAN Support" init is dead weight.
  #   CC_OPTIMIZE_FOR_PERFORMANCE — workload kernels optimize for size by
  #                 default. The controlled x86_64 comparison saved about 0.7
  #                 MiB while the same Firecracker boot reached PID 1 within
  #                 normal sub-second variance. Callers can still request the
  #                 performance-oriented build explicitly for experiments.
  extraDisables = [
    # IPv6 itself selects only the SHA-1 library; every one of these is an
    # IPsec-for-v6 option that `olddefconfig` would enable alongside it and
    # that drags in the XFRM transform framework. None is reachable by a
    # workload — the guest has one point-to-point link and no tunnels — and
    # XFRM/XFRM_ALGO/XFRM_USER stay in the required-disable set, so the
    # config guard is what proves they are absent rather than a comment.
    "IPV6_MIP6"
    "IPV6_VTI"
    "INET6_AH"
    "INET6_ESP"
    "INET6_ESP_OFFLOAD"
    "INET6_ESPINTCP"
    "INET6_IPCOMP"
    "INET6_XFRM_TUNNEL"
    "INET6_TUNNEL"
    # 6-in-4 is likewise unreachable: a guest has one point-to-point link
    # and no v4 tunnel endpoint. It is the v6 tunnel that carries no XFRM, so
    # the required-disable set cannot catch it indirectly.
    "IPV6_SIT"
    "NETFILTER"
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
  requiredExtraDisables = [
    "NAMESPACES"
    "CGROUPS"
  ];
}
