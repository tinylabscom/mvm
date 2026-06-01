#!/bin/sh
# PID 1 of the Stage 0 bootstrap VM.
#
# libkrun mounts an Alpine Linux minirootfs (materialized by
# `mvm_build::stage0::materialize_root_dir`) as the guest root
# over virtiofs (`krun_set_root`) and boots libkrunfw's bundled
# TSI-patched kernel transparently. The root dir is Alpine's
# official minirootfs tarball (hash + PGP-verified against the
# embedded Alpine release key in mvm source) with our `/init`
# layered on top; `krun_set_exec` runs `/init` as PID 1.
#
# Job: install Nix from Alpine's signed package repos
# (`apk add nix`), build the in-repo `nix/images/builder-vm`
# flake into a kernel + rootfs.ext4, and write them to the
# `/out` virtio-fs share. When the host sees the artifacts land,
# it promotes them into the steady-state builder-vm cache and
# we're done with Stage 0 for the lifetime of this machine.

set -eu

# Standard pseudofs essentials. libkrun's container mode
# (set_root) pre-mounts several of these in its in-VM init plumbing;
# gate each on `mountpoint -q` so the script doesn't trip
# `set -eu` on a benign EBUSY.
mountpoint -q /proc || mount -t proc     proc     /proc
mountpoint -q /sys  || mount -t sysfs    sysfs    /sys
mountpoint -q /dev  || mount -t devtmpfs devtmpfs /dev || true
mountpoint -q /tmp  || mount -t tmpfs    -o mode=1777 tmpfs /tmp
mountpoint -q /run  || mount -t tmpfs    -o mode=0755 tmpfs /run

# `/dev/null` insurance. Observed (2026-05-21): some Stage 0 runs
# under libkrun's set_root container mode reach userspace with
# `/dev/random` + `/dev/urandom` present but `/dev/null` missing,
# which then breaks every downstream `2>/dev/null` redirect — and
# the init script's error handlers were exactly the consumers of
# that pattern, so the actual nix-build failure got masked behind
# "/init: line N: can't create /dev/null: nonexistent directory".
# `mknod` with the standard major=1/minor=3 nodes /dev/null
# explicitly; the `|| true` makes it a no-op when libkrun already
# populated the node. Belt-and-suspenders — the error-handler
# rewrite below also drops `2>/dev/null` so even a *failed* mknod
# doesn't lose nix's actual stderr next time.
[ -c /dev/null ] || { mknod /dev/null c 1 3 && chmod 0666 /dev/null; } || true

# Console-visible /dev probe. Gives us evidence on every Stage 0
# run about whether /dev/null was already there (the mknod was a
# no-op) or absent (mknod created it / failed). Cheap; the
# alternative is debugging the next masked failure blind.
echo "stage0-init: /dev probe:" >&2
ls -la /dev/null /dev/random /dev/urandom /dev/zero 2>&1 | sed 's/^/  /' >&2 || true

# Bring eth0 up explicitly before udhcpc. busybox 1.36.x udhcpc
# does not auto-up the interface — sendto returns ENETDOWN and
# udhcpc loops forever. The libkrun virtio-net device is admin-DOWN
# at probe time; this ioctl flips it.
ip link set lo up
ip link set eth0 up

# DHCP. libkrun runs a DHCP server on its host side (gvproxy/passt
# leases an RFC1918 address). udhcpc gets the lease and writes
# /etc/resolv.conf via the default script. -n exits if no lease,
# -q exits after lease, -i pins the interface.
udhcpc -i eth0 -n -q || echo "stage0-init: udhcpc failed (offline; nix build will likely fail at substituter)" >&2

# Alpine's minirootfs ships with an empty /etc/apk/repositories.
# Point apk at the same Alpine branch the minirootfs came from.
# (Bump `ALPINE_BRANCH` in `crates/mvm-build/src/stage0.rs` in
# lockstep with the tarball pin; this constant must agree.)
mkdir -p /etc/apk
cat > /etc/apk/repositories <<'EOF'
https://dl-cdn.alpinelinux.org/alpine/v3.22/main
https://dl-cdn.alpinelinux.org/alpine/v3.22/community
EOF

# Virtio-fs shares from the host. In libkrun's set_root mode the
# kernel exposes them as virtio devices but the in-VM init does
# not mount them — the guest has to do it. Tags match the
# `add_virtio_fs(tag, ...)` calls in `LibkrunBuilderVm::run_stage0`.
mountpoint -q /work     || mount -t virtiofs work     /work
mountpoint -q /out      || mount -t virtiofs out      /out
mountpoint -q /mvm-bins || mount -t virtiofs mvm-bins /mvm-bins
if ! mountpoint -q /work; then
  echo "stage0-init: /work mount failed; aborting." >&2
  exit 64
fi
if ! mountpoint -q /out; then
  echo "stage0-init: /out mount failed; aborting." >&2
  exit 65
fi
# The builder-vm flake installs the pre-cross-compiled host-vm binaries
# (mvm-builder-init, mvm-egress-proxy) from /mvm-bins instead of building
# them with the guest's nix (ADR-065). Without this mount the build aborts
# with "MVM_HOST_BIN_DIR is not set".
if ! mountpoint -q /mvm-bins; then
  echo "stage0-init: /mvm-bins mount failed; aborting." >&2
  exit 66
fi

# libkrun's set_root mode backs the guest root with virtio-fs
# from the host's macOS APFS, which is case-insensitive by
# default. Several Nix derivations contain files that only differ
# by case (e.g. the Linux kernel headers ship `xt_connmark.h` and
# `xt_CONNMARK.h` in the same directory). Substitution from
# cache.nixos.org fails with `creating file '...xt_CONNMARK.h':
# File exists` on APFS — the second file collides with the first.
#
# Fix: mount tmpfs over /nix BEFORE `apk add nix` runs, so the
# nix package's closure (and every subsequent `nix-build`
# substitution) lives on case-sensitive in-memory storage.
# Mounting after apk would leave the nix binary on APFS and
# break the case-sensitive guarantee for substitutions.
#
# Size cap: 14 GiB. The original 4 GiB assumed a ~600 MB closure
# (builder-VM rootfs only). With Plan 95's slim-kernel + the Rust
# binaries (`mvm-host-vm-init`, `mvm-egress-proxy`) building in the
# same VM, the working set runs:
#   kernel intermediates (~3 GiB) +
#   rustc-wrapper substitute closure (~2 GiB) +
#   Rust build artifacts (~5–8 GiB)
# 14 GiB leaves headroom. Memory budget is paid from the libkrun
# guest's RAM allocation (DEFAULT_MEMORY_MIB in
# crates/mvm-build/src/libkrun_builder.rs) — keep that ≥ this cap.
mount -t tmpfs -o size=14G,mode=0755 tmpfs /nix
mkdir -p /nix/store /nix/var/nix /nix/var/log/nix

# Install Nix from Alpine's signed package repos. `apk-tools`
# verifies the signed APKINDEX against /etc/apk/keys/ (the
# Alpine release-signing keys shipped in the minirootfs) and
# each package's signature before installation.
echo "stage0-init: installing nix + dependencies via apk..." >&2
set +e
apk --no-progress update                              > /out/apk-update.log  2>&1
APK_RC=$?
if [ "$APK_RC" -ne 0 ]; then
  echo "stage0-init: apk update exited $APK_RC (see /out/apk-update.log)" >&2
  # `[ -r ]` test instead of the old `2>/dev/null` pattern: a
  # missing `/dev/null` would itself make the redirect fail with
  # "can't create /dev/null: nonexistent directory" and mask the
  # real apk error. See the /dev/null insurance block at the top.
  if [ -r /out/apk-update.log ]; then
    tail -40 /out/apk-update.log >&2
  fi
  exit "$APK_RC"
fi
apk --no-progress add nix git ca-certificates xz      > /out/apk-add.log     2>&1
APK_RC=$?
set -e
if [ "$APK_RC" -ne 0 ]; then
  echo "stage0-init: apk add exited $APK_RC (see /out/apk-add.log)" >&2
  if [ -r /out/apk-add.log ]; then
    tail -40 /out/apk-add.log >&2
  fi
  exit "$APK_RC"
fi

# Nix needs $HOME for cache + lock state. Alpine's apk install of
# nix creates /var/empty and similar but no HOME; set it
# explicitly.
export HOME=/root
mkdir -p "$HOME"

# Tell `nix/images/builder-vm/flake.nix` where the workspace
# root is, since the `path:` URL fetcher store-copies just the
# flake subdir and the flake's `../../..` reference would
# otherwise resolve against the store path (i.e. to filesystem
# `/`, tripping over /dev/btrfs-control + friends). The flake
# checks this env under `--impure` (already set below).
export MVM_WORKSPACE_PATH=/work

# Point the flake at the mounted host-vm binaries (see the /mvm-bins
# mount above). The flake reads this under --impure.
export MVM_HOST_BIN_DIR=/mvm-bins

ARCH="$(uname -m)"
FLAKE_REF="path:/work/nix/images/builder-vm#packages.${ARCH}-linux.default"

echo "stage0-init: building ${FLAKE_REF}" >&2

# --no-link / --no-write-lock-file lets us build against a
# read-only workspace mount. --print-out-paths spits the result
# path to stdout for us to copy from. --option connect-timeout 30
# caps substituter HTTP connect waits at 30s so an unreachable
# mirror fails over fast instead of stalling the whole build behind
# the OS-default TCP timeout (~75-120s).
#
# --max-jobs 1 caps derivation parallelism inside Stage 0. With
# Alpine nix's default `max-jobs = auto`, four heavy derivations
# (mvm-host-vm-init, mvm-egress-proxy, mvm-guest-agent, the slim
# Linux kernel) run concurrently and the combined working set
# exceeds the 16 GiB guest RAM / 14 GiB `/nix` tmpfs envelope —
# SIGKILL at `HOSTCC scripts/basic/fixdep`. libkrun_builder.rs:92-99
# records the peak-per-derivation observation (~5-6 GiB), which fits
# one at a time but not in parallel. Per-derivation parallelism stays
# at the default (cores = nproc) so the kernel compile still uses
# all 4 vCPUs.
set +e
nix build "$FLAKE_REF" \
    --extra-experimental-features "nix-command flakes" \
    --option connect-timeout 30 \
    --max-jobs 1 \
    --no-link --no-write-lock-file --impure \
    --print-out-paths --print-build-logs \
    > /tmp/store-path 2> /out/nix-stderr.log
NIX_RC=$?
set -e

if [ "$NIX_RC" -ne 0 ]; then
  echo "stage0-init: nix build exited $NIX_RC (see /out/nix-stderr.log)" >&2
  echo "stage0-init: === nix-stderr.log tail (last 80 lines) ===" >&2
  # `[ -r ]` rather than the old `tail ... 2>/dev/null` so a missing
  # `/dev/null` (observed at least once on libkrun set_root mode)
  # doesn't mask the real nix error. The /dev/null insurance block
  # at the top of this script is the primary fix; this is the
  # belt-and-suspenders second layer.
  if [ -r /out/nix-stderr.log ]; then
    tail -80 /out/nix-stderr.log >&2
  else
    echo "stage0-init: (could not read /out/nix-stderr.log)" >&2
  fi
  echo "stage0-init: === end nix-stderr.log ===" >&2
  exit "$NIX_RC"
fi

NIX_OUT="$(cat /tmp/store-path)"
if [ -z "$NIX_OUT" ]; then
  echo "stage0-init: nix build emitted no /nix/store path" >&2
  exit 1
fi

# The flake output convention: $out/vmlinux and $out/rootfs.ext4.
# Tolerate the kernel being named Image or bzImage to match other
# flake conventions in the repo.
if   [ -f "$NIX_OUT/vmlinux" ]; then cp -L "$NIX_OUT/vmlinux" /out/vmlinux
elif [ -f "$NIX_OUT/Image"   ]; then cp -L "$NIX_OUT/Image"   /out/vmlinux
elif [ -f "$NIX_OUT/bzImage" ]; then cp -L "$NIX_OUT/bzImage" /out/vmlinux
else
  echo "stage0-init: no kernel in $NIX_OUT" >&2
  exit 1
fi
if [ ! -f "$NIX_OUT/rootfs.ext4" ]; then
  echo "stage0-init: no rootfs.ext4 in $NIX_OUT" >&2
  exit 1
fi
cp -L "$NIX_OUT/rootfs.ext4" /out/rootfs.ext4
[ -f "$NIX_OUT/cmdline.txt" ] && cp -L "$NIX_OUT/cmdline.txt" /out/cmdline.txt

sync
echo "stage0-init: done; halting" >&2
poweroff -f
