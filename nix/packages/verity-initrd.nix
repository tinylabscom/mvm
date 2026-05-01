# Build the verity initramfs baked alongside `mkGuest`'s rootfs when
# `verifiedBoot = true`. The initramfs is a tiny cpio.gz containing a
# single binary at `/init` plus the empty mount targets `/proc`, `/dev`,
# `/sysroot`. ADR-002 §W3.
#
# At boot, Firecracker (or Apple VZ) mounts this initramfs, the kernel
# runs `/init` which is `mvm-verity-init`, and that binary:
#   1. Mounts /proc and /dev.
#   2. Reads `mvm.roothash=…` (and optional `mvm.data=…`/`mvm.hash=…`)
#      from /proc/cmdline.
#   3. Builds /dev/mapper/root via DM ioctls (DM_DEV_CREATE,
#      DM_TABLE_LOAD, DM_DEV_SUSPEND-with-resume).
#   4. Mounts /dev/mapper/root at /sysroot read-only.
#   5. switch_root's to /sysroot/init (the real minimal-init).
#
# Owning the boot pivot in userspace bypasses the Firecracker-aarch64
# bug where the hypervisor auto-appends `root=/dev/vda ro` to the
# kernel cmdline, overriding any verity `root=/dev/dm-0` we set.
#
# Usage from `nix/flake.nix`:
#   verityInitrd = import ./packages/verity-initrd.nix {
#     inherit pkgs verityInitPkg;
#   };
# `verityInitPkg` is the static-musl build from
# `nix/packages/mvm-verity-init.nix`. It must be statically linked —
# the initramfs has no glibc loader, so a dynamic binary at /init
# panics the kernel with `Failed to execute /init (error -2)`.

{ pkgs, verityInitPkg }:

pkgs.runCommand "mvm-verity-initrd"
  {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];
    # Pin SOURCE_DATE_EPOCH for reproducibility — same input bytes
    # must produce a byte-identical cpio. ADR-002 §W3.1 + §W5.3.
    SOURCE_DATE_EPOCH = "1700000000";
  } ''
    mkdir -p root/proc root/dev root/sysroot
    cp ${verityInitPkg}/bin/mvm-verity-init root/init
    chmod 0755 root/init

    # Pin file timestamps and ownership so cpio output is deterministic.
    find root -exec touch -d @$SOURCE_DATE_EPOCH {} +
    find root -exec chown 0:0 {} + 2>/dev/null || true

    # `cpio --reproducible` zeroes the device-major/minor fields and
    # uses MTIME from the file (which we pinned above). `find … -print0`
    # pipes a NUL-separated file list which `cpio -0` parses, avoiding
    # quoting issues.
    cd root
    find . -print0 | LC_ALL=C sort -z \
      | cpio --null --create --format=newc --reproducible \
      | gzip -n -9 > $out

    # cpio -tv smoke check: confirm `init` is in the archive as an
    # executable regular file. `cpio -tv` strips the `./` prefix when
    # printing, so the line we look for ends in a single space + the
    # filename. Match `^-rwx…` to also assert the executable bit.
    if ! gzip -dc $out | cpio -tv 2>/dev/null | grep -qE '^-rwx.* init$'; then
      echo "ERROR: built initramfs is missing executable /init" >&2
      gzip -dc $out | cpio -tv 2>&1 | head >&2
      exit 1
    fi
  ''
