# ── 1. Mount virtual filesystems ─────────────────────────────────
# devtmpfs/proc/sysfs/devpts/tmpfs — the kernel-level plumbing every
# Linux userspace expects. Skipped under container detection because
# Docker already wires these up.

if [ "$MVM_CONTAINER" = "0" ]; then
  mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
  mount -t proc proc /proc
  mount -t sysfs sys /sys
fi

echo "[init] mvm minimal init starting..." > /dev/console
[ "$MVM_CONTAINER" = "1" ] && echo "[init] container mode detected" > /dev/console

# Allow non-root services to write to /dev/console for logging.
chmod 666 /dev/console 2>/dev/null || true

if [ "$MVM_CONTAINER" = "0" ]; then
  mkdir -p /dev/pts /dev/shm
  mount -t devpts devpts /dev/pts 2>/dev/null || true
  # POSIX shared memory. Required by anything that calls sem_open()
  # — notably libfaketime, which nixpkgs' make-ext4-fs.nix uses to
  # produce reproducible timestamps. Without /dev/shm, image-building
  # derivations fail with `sem_open: No such file or directory`.
  mount -t tmpfs -o nosuid,nodev tmpfs /dev/shm 2>/dev/null || true
fi

# bash process substitution (`<(...)`) and many of nixpkgs' setup hooks
# (notably patchelf's) reference /dev/fd/N. Linux exposes file descriptors
# under /proc/self/fd, but conventionally /dev/fd is a symlink to that.
# devtmpfs doesn't provide it — create it (and the std/in,out,err
# aliases) by hand so Nix builds inside the VM don't bail with
# `/dev/fd/63: No such file or directory`.
if [ ! -e /dev/fd ]; then
  ln -s /proc/self/fd /dev/fd 2>/dev/null || true
fi
for n in 0:stdin 1:stdout 2:stderr; do
  target="${n#*:}"
  src="${n%:*}"
  [ -e "/dev/$target" ] || ln -s "/proc/self/fd/$src" "/dev/$target" 2>/dev/null || true
done

mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
