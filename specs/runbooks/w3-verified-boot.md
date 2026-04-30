# W3 verified-boot verification runbook

> Created: 2026-04-30
> Parent plan: `specs/plans/27-w3-verified-boot.md`
> ADR: `specs/adrs/002-microvm-security-posture.md`
>
> **Status: 4 of 5 steps PASS. Step 3 surfaced a real bug —
> Firecracker's aarch64 boot path auto-appends `root=/dev/vda ro`
> to the kernel cmdline, which clobbers `root=/dev/dm-0` (last
> `root=` wins). dm-verity is constructed correctly but the kernel
> mounts `/dev/vda` directly instead of the verity-protected
> `/dev/dm-0`. See "Findings" below for the fix path.**

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

## Step 3 — Live Firecracker boot, expecting `/dev/dm-0` root mount

```bash
work=/tmp/w3-smoke
rm -rf "$work" && mkdir -p "$work"
cp "$out/vmlinux"        "$work/vmlinux"
cp "$out/rootfs.ext4"    "$work/rootfs.ext4"
cp "$out/rootfs.verity"  "$work/rootfs.verity"
chmod u+w "$work/rootfs.ext4" "$work/rootfs.verity"

hash=$(cat "$out/rootfs.roothash")
size=$(stat -c %s "$work/rootfs.ext4")
data_blocks=$((size / 4096))
sectors=$((data_blocks * 8))
salt=$(printf '0%.0s' $(seq 1 64))
table="0 ${sectors} verity 1 /dev/vda /dev/vdb 4096 4096 ${data_blocks} 0 sha256 ${hash} ${salt}"

python3 - <<EOF > "$work/config.json"
import json
boot_args = (
    "console=ttyS0 reboot=k panic=1 root=/dev/dm-0 ro init=/init "
    "dm-mod.create=\"rootfs,,,ro,${table}\""
)
print(json.dumps({
    "boot-source": {
        "kernel_image_path": "$work/vmlinux",
        "boot_args": boot_args,
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

grep -E 'device-mapper|verity|panic|dm-0' "$work/fc.stdout"
```

**Expected on success** — kernel reaches userspace and you see
something like `/dev/dm-0 on / type ext4 (ro,…)` from `mount`.

**Observed 2026-04-30** (the bug, see Findings #1):

```
[1.450509] device-mapper: ioctl: 4.47.0-ioctl … initialised: dm-devel@redhat.com
[1.639826] device-mapper: verity: sha256 using implementation "sha256-generic"
[1.659951] device-mapper: ioctl: dm-0 (rootfs) is ready
[1.685428] VFS: Cannot open root device "vda" or unknown-block(254,0): error -16
[1.708495] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
```

Verity setup itself succeeds (`dm-0 (rootfs) is ready`), but the kernel
then tries to mount `/dev/vda` instead of `/dev/dm-0`. The cause is in
the captured boot cmdline:

```
… root=/dev/dm-0 ro init=/init dm-mod.create="…" pci=off root=/dev/vda ro earlycon=…
                                                           ^^^^^^^^^^^^^
                                              Firecracker auto-append, last root= wins
```

Firecracker's aarch64 boot path appends `pci=off root=/dev/vda ro
earlycon=uart,mmio,…` after the user's `boot_args`. The kernel uses
last-wins for `root=`, so the user's `root=/dev/dm-0` is overridden.

## Step 4 — Tamper-panic regression

Until Step 3's bug is fixed this step can't run end-to-end (the kernel
panics before reaching the verity-data read). The intent is preserved
here for when the fix lands:

```bash
"$REPO/target/debug/mvmctl" stop verity-smoke 2>/dev/null || true
printf '\xff' | dd of="$work/rootfs.ext4" bs=1 count=1 \
    seek=$((4096 * 1000)) conv=notrunc

sudo timeout 30 firecracker --no-api --config-file "$work/config.json" \
    > "$work/fc-tamper.stdout" 2>&1
grep -E 'data block .* is corrupted|Kernel panic' "$work/fc-tamper.stdout"
```

Expected on success: a line like
`dm-verity: data block <n> is corrupted` followed by a kernel panic.
The VM must NOT reach userspace.

**Verified 2026-04-30: blocked by Findings #1.** Once the cmdline
override is fixed, the tamper test will be re-run.

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

### Finding #1 — Firecracker auto-appends `root=/dev/vda ro` on aarch64

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
- [ ] Step 3: live boot mounts `/dev/dm-0` as root. *Blocked on Finding #1.*
- [ ] Step 4: tampered ext4 panics in early boot. *Blocked on Finding #1.*
- [x] Step 5: dev-image build emits no verity sidecar.

When Steps 3 and 4 are checked, the runbook + the
`security.yml::verified-boot-artifacts` CI gate together provide the
technical receipt for ADR-002 claim #3.
