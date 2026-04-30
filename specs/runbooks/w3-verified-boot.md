# W3 verified-boot verification runbook

> Created: 2026-04-30
> Last updated: 2026-04-30 (full pass after initramfs fix)
> Parent plan: `specs/plans/27-w3-verified-boot.md`
> ADR: `specs/adrs/002-microvm-security-posture.md`
>
> **Status: ✅ all 5 steps PASS as of 2026-04-30.** The original
> Step 3 failure (Firecracker's aarch64 boot path auto-appends
> `root=/dev/vda ro` and last-wins clobbers `/dev/dm-0`) is fixed
> by an early-userspace verity initramfs that owns the boot pivot
> in userspace via `mvm-verity-init` + `switch_root`. The kernel-
> level `root=` setting is now irrelevant. Tamper test confirms
> the kernel panics with `data block N is corrupted`.

This runbook is the manual end-to-end verification for ADR-002 §W3
(verified boot via dm-verity). The `security.yml::verified-boot-artifacts`
CI gate covers the static-shape check; this runbook covers the live-
boot side that needs `/dev/kvm`, `firecracker`, and `veritysetup` —
all of which are present in the project's Lima dev VM (`mvmctl dev up`)
but not on a macOS host directly.

The whole runbook is mechanical: copy each block into
`limactl shell mvm-builder`, observe the expected signal, move on. Each step
is independently runnable so a partial failure is debuggable in
isolation.

## Prerequisites

Inside `limactl shell mvm-builder` (or any Linux/KVM host with the project
checkout at `$REPO`), confirm tooling:

```bash
ls -la /dev/kvm                    # crw-rw---- 1 root kvm 10, 232 …
which firecracker veritysetup nix  # all three on PATH
nix --version                      # ≥ 2.18 with flakes enabled
```

## Step 1 — Build, inspect artifacts, sanity-check the kernel

```bash
cd "$REPO"
out=$(nix build "./nix/default-microvm#packages.aarch64-linux.default" \
        --no-link --print-out-paths)

ls -la "$out"
# Expected: image.tar.gz, rootfs.ext4, rootfs.verity, rootfs.roothash, vmlinux

cat "$out/rootfs.roothash"
# Expected: a 64-char lowercase-hex string + newline

strings "$out/vmlinux" | grep -iE 'verity|dm-mod|device-mapper' | head
# Expected: matches for 'dm-verity', 'device-mapper', 'verity_algorithm',
# 'verity_mode', 'verity_version' — proves CONFIG_DM_VERITY=y took effect.
```

**Verified 2026-04-30**: store path
`/nix/store/rg208ijvys4vwfby3qmz7xs85bj347rs-mvm-default-microvm`
contained all four artifacts plus a 16 MiB Linux 6.1.169 aarch64
vmlinux with the expected verity strings.

## Step 2 — `veritysetup verify` round-trip

```bash
veritysetup verify \
    "$out/rootfs.ext4" \
    "$out/rootfs.verity" \
    "$(cat "$out/rootfs.roothash")"
echo "exit=$?"
# Expected: exit=0
```

**Verified 2026-04-30**: exit 0. The Nix-built sidecar matches the
ext4 it was built against, and the roothash produced by mkGuest is the
same one veritysetup recovers from the tree.

## Step 3 — Live Firecracker boot via the verity initramfs

The verity boot path uses the `rootfs.initrd` baked by mkGuest. The
kernel mounts the initramfs first, runs `mvm-verity-init` as PID 1,
which constructs `/dev/mapper/root` via DM ioctls, mounts it at
`/sysroot`, then `switch_root`s to the real init. The kernel-level
`root=` setting is irrelevant because the initramfs picks the real
root explicitly.

```bash
work=/tmp/w3-smoke
rm -rf "$work" && mkdir -p "$work"
cp "$out/vmlinux"        "$work/vmlinux"
cp "$out/rootfs.ext4"    "$work/rootfs.ext4"
cp "$out/rootfs.verity"  "$work/rootfs.verity"
cp "$out/rootfs.initrd"  "$work/rootfs.initrd"
chmod u+w "$work"/*

hash=$(cat "$out/rootfs.roothash")
python3 - <<EOF > "$work/config.json"
import json
boot_args = (
    "console=ttyS0 reboot=k panic=1 init=/init "
    f"mvm.roothash=${hash} mvm.data=/dev/vda mvm.hash=/dev/vdb"
)
print(json.dumps({
    "boot-source": {
        "kernel_image_path": "$work/vmlinux",
        "boot_args": boot_args,
        "initrd_path": "$work/rootfs.initrd",
    },
    "drives": [
        {"drive_id": "rootfs", "path_on_host": "$work/rootfs.ext4",
         "is_root_device": True, "is_read_only": True},
        {"drive_id": "verity", "path_on_host": "$work/rootfs.verity",
         "is_root_device": False, "is_read_only": True},
    ],
    "machine-config": {"vcpu_count": 1, "mem_size_mib": 256, "smt": False},
}, indent=2))
EOF

sudo timeout 30 firecracker --no-api --config-file "$work/config.json" \
    > "$work/fc.stdout" 2> "$work/fc.stderr"

grep -E 'mvm-verity-init|device-mapper:|switching to|/sysroot' "$work/fc.stdout"
```

**Expected** (verified 2026-04-30):

```
mvm-verity-init: starting
mvm-verity-init: data=/dev/vda hash=/dev/vdb roothash=…
mvm-verity-init: verity table = 419840 sectors, 209920 data blocks
mvm-verity-init: dm-ioctl kernel version 4.47.0
mvm-verity-init: DM_DEV_CREATE ok
[..] device-mapper: verity: sha256 using implementation "sha256-generic"
mvm-verity-init: DM_TABLE_LOAD ok
mvm-verity-init: dm-verity device active
mvm-verity-init: /sysroot mounted (verity-protected)
mvm-verity-init: switching to /init
[init] /etc/{passwd,group,nsswitch.conf} are read-only bind-mounts
```

The trailing `[init]` line confirms the real `minimal-init` script
reached userspace from the verity-protected `/dev/dm-0`. (Subsequent
warnings about missing config drives or `setpriv` flag conflicts are
unrelated to W3 — they're side effects of using the production rootfs
without the per-VM config/secrets drives.)

## Step 4 — Tamper-panic regression

Tampering inside the ext4 superblock guarantees verity sees the
corruption at first read (the kernel reads the superblock during the
initial mount). Picking a "deeper" offset gambles on that block
actually being read — verity is lazy, so a tampered byte that the
boot path never touches goes undetected. That's not a verity bug; it
just means the regression test has to point at a block ext4 is sure
to read.

```bash
# Restore from the unmodified store path before tampering.
cp "$out/rootfs.ext4" "$work/rootfs.ext4"
chmod u+w "$work/rootfs.ext4"

# Clobber 128 bytes inside the ext4 superblock at offset 1024.
dd if=/dev/urandom of="$work/rootfs.ext4" bs=1 count=128 \
   seek=1024 conv=notrunc

sudo timeout 15 firecracker --no-api --config-file "$work/config.json" \
    > "$work/fc-tamper.stdout" 2>&1
grep -E 'data block .* is corrupted|Kernel panic' "$work/fc-tamper.stdout"
```

**Verified 2026-04-30** — output:

```
[..] device-mapper: verity: 254:0: data block 1 is corrupted
mvm-verity-init: FATAL: mount(/dev/dm-0 → /sysroot, ext4): I/O error (os error 5)
[..] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100
```

Verity returns `-EIO` for the corrupted read, the mount fails, PID 1
exits, and the kernel panics. The VM does NOT reach userspace.

## Step 5 — Dev-image exemption

```bash
out_dev=$(nix build "./nix/dev-image#packages.aarch64-linux.default" \
            --no-link --print-out-paths)
ls "$out_dev"
[ ! -f "$out_dev/rootfs.verity"   ] && echo "OK: no rootfs.verity"
[ ! -f "$out_dev/rootfs.roothash" ] && echo "OK: no rootfs.roothash"
```

**Verified 2026-04-30**: dev-image output contains
`image.tar.gz rootfs.ext4 vmlinux` only. The
`verifiedBoot = false` override in `nix/dev-image/flake.nix` is
correctly suppressing the verity sidecar.

## Findings

### Finding #1 (RESOLVED 2026-04-30) — Firecracker auto-appends `root=/dev/vda ro` on aarch64

**Resolution**: implemented option (2) below. mkGuest now bakes a
~250 KB cpio.gz initramfs at `rootfs.initrd` whose `/init` is
`mvm-verity-init` (a static-musl Rust binary). The initramfs runs
*before* the kernel commits to a root device, so Firecracker's
trailing `root=/dev/vda ro` becomes irrelevant — `mvm-verity-init`
constructs `/dev/mapper/root` via DM ioctls, mounts it, and
`switch_root`s explicitly. Live boot + tamper test both green.

**What**

Firecracker v1.14.1 on aarch64 unconditionally appends
`pci=off root=/dev/vda ro earlycon=uart,mmio,<addr>` to the kernel
cmdline regardless of what the API caller put in `boot_args`. With
verity in play, the cmdline ends up looking like:

```
root=/dev/dm-0 ro … dm-mod.create="…" pci=off root=/dev/vda ro earlycon=…
```

The kernel uses last-wins semantics for `root=`, so the user's
`root=/dev/dm-0` is silently overridden, and the kernel tries to
mount `/dev/vda` directly. dm-verity is constructed correctly but
never on the read path that matters.

**Why this matters**

The W3 implementation (`crates/mvm-runtime/src/vm/microvm.rs::configure_flake_microvm_with_drives_dir`)
sets `boot_args = "root=/dev/dm-0 ro rootwait init=/init {dm_create} {base_args}"`
when verity is on. The Apple Container path (`crates/mvm-apple-container/src/macos.rs`)
does the analogous thing. Both share the same defect: Firecracker's
auto-append (and presumably whatever the VZ code path does on macOS)
is not accounted for, so a verity-enabled production microVM still
boots off raw `/dev/vda`. Verity is initialized but doesn't gate
reads against the rootfs the running guest is actually using.

**Status**: ADR-002 §W3 claim (#3 — "a tampered rootfs ext4 fails to
boot") **does not yet hold in practice**. Static structure passes
(Steps 1, 2, 5 all green), the kernel constructs the verity device
correctly, but the cmdline plumbing means the kernel ignores the
verity-protected device and mounts the raw block device instead.

**Possible fixes** (in rough preference order)

1. **Drop our user-supplied `root=` and use a fixed dm name that the
   FDT default points at.** The dm-mod.create syntax accepts a
   `<name>` field; if we name the device so it ends up at
   `/dev/vda`, Firecracker's `root=/dev/vda` becomes the dm-verity
   target. Doesn't actually work — dm devices live under
   `/dev/dm-N` and `/dev/mapper/<name>`, not `/dev/vd*`.

2. **Use a tiny initramfs that does verity setup in early
   userspace, then `switch_root` to `/dev/mapper/rootfs`.** The
   initramfs runs `veritysetup open /dev/vda root <hash> /dev/vdb`
   and `exec switch_root /mnt /init`. This bypasses the
   cmdline-`root=` issue entirely because the kernel mounts
   the initramfs first and we choose the eventual root manually.
   Cost: an extra ~1MB artifact in the rootfs build, plus an
   initramfs builder in mkGuest. This is the typical real-world
   verity setup.

3. **Check if Firecracker has a knob to suppress the
   arch-specific cmdline append.** A quick look at v1.14.1
   source in `vmm/src/arch/aarch64/fdt.rs` shows the append is
   unconditional. A Firecracker feature request or patch is
   plausible but slow.

4. **Pre-process the boot_args so our `root=` is the LAST one.**
   Doesn't work — Firecracker appends after user input, not
   before.

5. **Use `root=253:0` (dm-0's major:minor) instead of
   `root=/dev/dm-0`.** Same problem: Firecracker still appends
   `root=/dev/vda ro` after, and last `root=` still wins.

The pragmatic path is **(2) initramfs**. It's well-understood, the
build cost is small, and it gives us full control over the boot
sequence without depending on Firecracker behavior.

**Action**: file as a follow-up under §W3 in plan 27 and gate the
ADR-002 claim #3 on it. Mark §W3 status as "host-side wired,
not enforcing — initramfs work outstanding" until this is closed.

### Finding #2 — `pkgs.cryptsetup` build is heavy on first build

`nix build .#default-microvm` on the Lima VM took ~30 minutes the
first time (it pulled and built `elfutils-0.194-dev` + a few other
non-cached deps). Cached build is fast. Document this in the
runbook so a first-time runner doesn't think the build is hung.

## Operator checklist

Before claiming the W3 boot regression passes, run all five steps
and check off:

- [x] Step 1: artifacts present + kernel has DM_VERITY strings.
- [x] Step 2: `veritysetup verify` exits 0.
- [x] Step 3: live boot mounts `/dev/dm-0` as root via verity initramfs.
- [x] Step 4: tampered ext4 panics in early boot (`data block N is corrupted`).
- [x] Step 5: dev-image build emits no verity sidecar.

All five green as of 2026-04-30. The runbook + the
`security.yml::verified-boot-artifacts` CI gate together provide the
technical receipt for ADR-002 claim #3 ("a tampered rootfs ext4
fails to boot").
