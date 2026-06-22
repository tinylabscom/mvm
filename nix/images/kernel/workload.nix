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
#   VIRTIO_FS   — virtio-fs transport for host-directory volume shares; the
#                 guest mounts each `mvm.uvols=` cmdline entry over it. Without
#                 the built-in driver the mount fails "No such device".
#   FUSE_FS     — virtio-fs is FUSE-backed, so the workload needs it too (the
#                 builder kernel already carries both — same proven recipe).
#
# The flake passes `base` in so both the builder and workload kernels share
# one `base.nix` source. base.nix is imported relatively by the builder-vm
# flake rather than through `workspace`, for the same reason as builder.nix:
# importing through `workspace` forces realisation of the filtered store
# path, which `nix flake check --no-build` refuses.

{ pkgs, base }:

base.mkKernel {
  extraEnables = [ "MD" "BLK_DEV_DM" "DM_VERITY" "VIRTIO_FS" "FUSE_FS" ];
}
