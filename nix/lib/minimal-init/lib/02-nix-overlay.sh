# ── 1a. Writable /nix via overlayfs on a host-backed disk ───────
# Architecture:
#
#   /dev/vda  rootfs    read-only ext4 with a fully-populated Nix
#                       store at /nix and a pre-seeded
#                       /nix/var/nix/db (baked in by mkGuest's
#                       populateImageCommands).
#
#   /dev/vdb  nix-store sparse ext4 file on the host, attached as a
#                       second VirtioBlk device. Mounted at
#                       /var/nix-upper. Holds *only* writes the dev
#                       VM has performed since first boot — new
#                       store paths from `nix build`, the writable
#                       db, GC roots, the `.links` dedup dir.
#
# We compose them with overlayfs: the rootfs's /nix as the read-only
# lower, the ext4 disk's contents as the writable upper, mounted
# back over /nix. ext4 is the only writable upper that works here:
# virtiofs can't surface the `trusted.*` xattrs overlayfs requires,
# so an overlay over a virtiofs upper silently downgrades to RO.
#
# We label the dev-store ext4 with `mvm-nix` (mkfs.ext4 -L mvm-nix
# below) and look it up by label, not by device node. /dev/vdb
# collides with the production microVM convention where vdb is the
# config drive — keying on the label keeps the two paths cleanly
# separable.

find_disk_by_label() {
  want="$1"
  for dev in /dev/vd*; do
    [ -b "$dev" ] || continue
    if blkid "$dev" 2>/dev/null | grep -q "LABEL=\"$want\""; then
      echo "$dev"
      return 0
    fi
  done
  return 1
}
has_disk_signature() {
  blkid "$1" 2>/dev/null | grep -q "TYPE="
}

if [ "$MVM_CONTAINER" = "0" ]; then
  nix_disk="$(find_disk_by_label mvm-nix || true)"
  # First-boot path: the host attached a fresh sparse file. We
  # identify it by being a block device with no signature AND not
  # /dev/vda (the rootfs). Skip /dev/vda explicitly so we never
  # reformat the boot disk if its signature ever evaporates.
  if [ -z "$nix_disk" ] && [ -b /dev/vdb ] && ! has_disk_signature /dev/vdb; then
    echo "[init] formatting /dev/vdb as ext4 (label=mvm-nix) for the writable Nix layer..." > /dev/console
    if mkfs.ext4 -q -F -L mvm-nix /dev/vdb >/dev/console 2>&1; then
      nix_disk=/dev/vdb
    else
      echo "[init] ERROR: mkfs.ext4 /dev/vdb failed" > /dev/console
    fi
  fi
  if [ -n "$nix_disk" ]; then
    mkdir -p /var/nix-upper /var/nix-lower
    if mount -t ext4 "$nix_disk" /var/nix-upper 2>/dev/console; then
      mkdir -p /var/nix-upper/upper /var/nix-upper/work
      mount --bind /nix /var/nix-lower 2>/dev/console
      if mount -t overlay overlay \
           -o "lowerdir=/var/nix-lower,upperdir=/var/nix-upper/upper,workdir=/var/nix-upper/work" \
           /nix 2>/dev/console; then
        # HOME points into the upper layer; materialise it now that
        # the disk is mounted.
        mkdir -p /var/nix-upper/home
        echo "[init] /nix overlayed (lower=rootfs, upper=$nix_disk)" > /dev/console
      else
        echo "[init] ERROR: overlay over $nix_disk failed; nix builds will be read-only" > /dev/console
      fi
    else
      echo "[init] ERROR: $nix_disk mount failed; nix builds will be read-only" > /dev/console
    fi
  fi
fi
