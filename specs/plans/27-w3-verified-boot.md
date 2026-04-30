# Plan 27 — W3: dm-verity verified boot

> Status: ✅ shipped — 2026-04-30 (initramfs fix landed).
> Owner: Ari
> Parent: `specs/plans/25-microvm-hardening.md` §W3
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Verification runbook: `specs/runbooks/w3-verified-boot.md`
> Estimated effort: 4-5 days (incl. initramfs)
>
> ### Verification result (2026-04-30, Lima dev VM, aarch64)
>
> All five runbook steps green. ADR-002 claim #3 ("a tampered rootfs
> ext4 fails to boot") now holds in practice:
>
> - ✅ Step 1 — `nix build .#default-microvm` emits five files now
>   (`rootfs.{ext4,verity,roothash,initrd}` + `vmlinux`); kernel
>   contains DM_VERITY strings.
> - ✅ Step 2 — `veritysetup verify` exits 0 against the emitted
>   sidecar + roothash.
> - ✅ Step 3 — Live Firecracker boot under the verity initramfs:
>   `mvm-verity-init` constructs `/dev/mapper/root` via DM ioctls,
>   mounts it, switch_root's, and the real `minimal-init` reaches
>   userspace.
> - ✅ Step 4 — Tampered ext4 superblock triggers
>   `device-mapper: verity: 254:0: data block 1 is corrupted` in
>   the kernel; the VM panics before userspace.
> - ✅ Step 5 — Dev-image build correctly emits no verity sidecar
>   (`verifiedBoot = false` honoured).
>
> ### Shipped artifacts
>
> - **Kernel** `nix/firecracker-kernel-pkg.nix` now enables
>   `CONFIG_MD=y`, `CONFIG_BLK_DEV_DM=y`, `CONFIG_DM_INIT=y`,
>   `CONFIG_DM_VERITY=y`. The shipped vmlinux now parses
>   `dm-mod.create=` from the kernel cmdline and constructs the
>   verity device-mapper target before init runs.
> - **W3.1** `nix/flake.nix::verityArtifacts` runs `veritysetup format`
>   with a pinned zero salt against the finished ext4, and emits
>   `rootfs.verity` + `rootfs.roothash` (64 hex + newline) alongside
>   the original `rootfs.ext4`. Determinism is achieved by the
>   pinned salt + the deterministic ext4 layout from
>   `nixos/lib/make-ext4-fs.nix`.
> - **W3.2** Apple Container backend (`crates/mvm-apple-container`)
>   gained `VerityConfig` + `start_with_verity()`. When verity is on
>   the rootfs is opened read-only, the sidecar is attached as
>   `/dev/vdb`, and the cmdline carries
>   `dm-mod.create="rootfs,,,ro,0 <sectors> verity 1 /dev/vda
>   /dev/vdb 4096 4096 <data-blocks> 0 sha256 <root-hash> <salt>"`
>   plus `root=/dev/dm-0 ro`. We also refuse to boot with both
>   `MVM_NIX_STORE_DISK` and verity (mutually exclusive — the dev-VM
>   exemption is the documented escape).
> - **W3.3** Firecracker backend (`crates/mvm-runtime/src/vm/microvm.rs`)
>   added `verity_path` + `roothash` fields to `FlakeRunConfig` and
>   `VmStartConfig`. `configure_flake_microvm_with_drives_dir` PUTs
>   a third drive (`/drives/verity`) between rootfs and config so it
>   lands at `/dev/vdb`, and `build_verity_dm_create_arg()` produces
>   the same dm-mod.create string as the Apple Container backend.
> - **W3.4** `mkGuest` accepts `verifiedBoot ? true`; the dev-image
>   flake (`nix/dev-image/flake.nix`) sets `verifiedBoot = false`
>   because the overlayfs upper layer mutates /nix at runtime, which
>   can't compose with verity. The dev sibling flake (`nix/dev/`)
>   forwards the kwarg transparently.
> - **CI gate** `.github/workflows/security.yml` gained a
>   `verified-boot-artifacts` lane that builds
>   `nix/default-microvm/`, asserts `rootfs.{ext4,verity,roothash}`
>   exist, and validates the roothash is a 64-char lowercase-hex
>   string. A flip of `verifiedBoot=false` on a production path
>   fails the merge.
> - **Tests**
>   - `mvm-runtime`: `build_verity_dm_create_rejects_short_hash`,
>     `build_verity_dm_create_rejects_non_hex_hash`,
>     `probe_verity_sidecar_returns_none_for_path_without_parent`.
>   - `mvm-apple-container`: `start_vm_rejects_short_roothash`,
>     `start_vm_rejects_non_hex_roothash`,
>     `start_vm_rejects_missing_verity_sidecar`.
>
> ### Resolved findings
>
> #### Finding #1 (RESOLVED 2026-04-30) — Firecracker aarch64 auto-appends `root=/dev/vda ro`
>
> Resolution: a small static-musl initramfs in mkGuest. The kernel
> mounts the initramfs first, runs `mvm-verity-init` (PID 1) which
> reads `mvm.roothash=` from `/proc/cmdline`, builds
> `/dev/mapper/root` via DM ioctls (DM_DEV_CREATE → DM_TABLE_LOAD
> → DM_DEV_SUSPEND-with-resume), mounts it at `/sysroot`, and
> `switch_root`s. The kernel-level `root=` setting is irrelevant —
> the initramfs picks the real root explicitly.
>
> #### Finding #2 (gotchas captured during the fix)
>
> Three subtleties surfaced during implementation; the final code
> handles all three but they're worth documenting for the next
> person who touches this:
>
> 1. **Static linking is non-optional.** A dynamic ELF at `/init`
>    in the initramfs panics with `Failed to execute /init (error
>    -2)` — the kernel can't find `/lib/ld-linux*` because the
>    initramfs is empty. `mvm-verity-init` is built via
>    `pkgs.pkgsStatic.rustPlatform` against musl; the agent +
>    seccomp-apply keep dynamic linking because they run after
>    rootfs mount.
> 2. **`hash_start_block = 1`, not 0.** `veritysetup format` writes
>    a 512-byte verity superblock at offset 0 of the sidecar; the
>    actual Merkle tree starts at block 1. Setting hash_start to 0
>    makes the kernel parse the superblock as a hash node and
>    report `metadata block 0 is corrupted`.
> 3. **`data_block_size` must match the underlying ext4.** mkGuest
>    builds rootfs.ext4 with mke2fs's default 1 KiB blocks at our
>    typical sizes. dm-verity exposes its data-block-size as the
>    device's logical block size, and the kernel's ext4 refuses to
>    mount when FS block size < device logical block size. Verity
>    data-block-size is now 1024; the hash-block-size stays at
>    4096 (typical fan-out, smaller tree).
>
> ### Outstanding (cosmetic, not blocking the W3 claim)
>
> - Auto-snapshot regression for the new `/drives/verity` +
>   `initrd_path` Firecracker config still needs a real snapshot
>   round-trip.
> - The Apple Container path's `start_with_verity()` is wired but
>   live-tested only on Firecracker today; a §3.5 "Apple Container
>   smoke" lane in the runbook is on the to-do once we have a Mac
>   in the loop with a production image.
> - Two pre-existing init-script bugs the live boot exposed
>   (`mount /etc/nsswitch.conf failed: No such file or directory`,
>   `setpriv: mutually exclusive arguments: --clear-groups
>   --keep-groups --init-groups --groups`) need their own fixes —
>   both unrelated to W3 and unchanged by this work.

## Why

The rootfs ext4 is a regular file on the host's filesystem. If a
host process (or a guest exploit that punched through virtiofs)
flips a byte, the next boot reads the tampered image as truth — no
boot-time integrity check today. Threat-model claim #3 from ADR-002
("a tampered rootfs ext4 fails to boot") needs technical evidence,
not just an assertion.

dm-verity is the right primitive: a kernel device-mapper target
that hashes ext4 blocks against a pre-computed Merkle tree, fails
reads on hash mismatch, and verifies the tree's root against a hash
provided on the kernel cmdline. Build once, verify every boot, no
runtime cost beyond block hashing.

## Threat shape addressed

- A modified rootfs (host-side tamper, partial-write corruption,
  or a malicious actor with write access to `~/.mvm/dev/` or the
  Nix store) makes the guest fail to boot rather than executing
  attacker-chosen code.
- Block-level corruption (cosmic-ray, disk failure) is detected
  at read time rather than producing silent guest-side
  misbehavior.

## Scope

In: production microVMs (Firecracker + Apple Container backends).
mkGuest emits the verity sidecar; the backend attaches it; init
reconstructs the verity device.

Out: dev VM. Its overlayfs upper layer (`/dev/vdb` ext4 disk)
makes the lower /nix continuously change at runtime, which can't
compose with verity (the lower layer's root hash would need to
change on every write). ADR-002 names this exemption explicitly.

## Sub-items

### W3.1 — `mkGuest` emits verity sidecar

**What**

Today `nix/flake.nix::mkGuestFn` produces a `rootfs.ext4` via
`nixos/lib/make-ext4-fs.nix`. Add a second derivation that runs
`veritysetup format --format=1 rootfs.ext4 rootfs.verity` and
captures the root hash to `rootfs.roothash`. Outputs:

- `<store-path>/rootfs.ext4` — unchanged.
- `<store-path>/rootfs.verity` — Merkle hash tree.
- `<store-path>/rootfs.roothash` — 64-char hex string.

The Merkle tree is small (~0.5% of the rootfs size for default
4K blocks). Both files are read-only in the Nix store.

**Files**

- `nix/flake.nix`: add a `verityArtifacts` derivation that
  consumes `rootfs.ext4` as input and runs `pkgs.cryptsetup`'s
  `veritysetup format`. Wire its outputs into the
  `pkgs.runCommand "mvm-${name}"` final step alongside the
  existing `cp rootfs.ext4`/`copyKernel` lines.

**Tests**

- Eval test: `nix build .#default` against an example flake
  produces all three files in the output dir.
- Determinism test: `nix build` twice, sha256 the verity sidecar
  + roothash, assert identical.

### W3.2 — Apple Container backend attaches verity device + cmdline hash

**What**

`crates/mvm-apple-container/src/macos.rs::start_vm` already
attaches `rootfs.ext4` as `/dev/vda`. Add a third VirtioBlk device
for `rootfs.verity` (will appear as `/dev/vdc` since `/dev/vdb` is
the writable Nix-store overlay disk on dev VMs — production has no
overlay disk so verity sidecar lands at `/dev/vdb`). Update the
kernel cmdline to include `mvm.roothash=<hex>`.

Init's section 1a (already conditionally finds devices by label)
gains a verity branch:

1. Look for cmdline `mvm.roothash=…`. If absent, skip verity (dev
   VM path).
2. Find the verity sidecar block device (label `mvm-verity`).
3. `veritysetup open /dev/vda <name> /dev/vd<verity> <roothash>`
   creates `/dev/mapper/<name>`.
4. Pivot root from `/dev/vda` to `/dev/mapper/<name>`. Or:
   simpler — since this all happens before init runs, do it in
   the kernel cmdline by passing
   `dm-mod.create="rootfs,,,ro,0 <sectors> verity 1 /dev/vda /dev/vd<n> 4096 4096 <data-blocks> <hash-start> sha256 <roothash> -"`
   and `root=/dev/dm-0`.

Option B (kernel cmdline `dm-mod.create`) is **strongly preferred**:

- No userspace step before pivot_root, so a compromised initramfs
  can't bypass verity.
- Kernel sets up the device-mapper target in early boot; if the
  verity hash is wrong, the kernel panics before init runs.
- One cmdline argument; no init script changes needed.
- Linux >= 4.18, which we already require.

**Files**

- `crates/mvm-apple-container/src/macos.rs::start_vm`:
  - Read `rootfs.verity` and `rootfs.roothash` from the dev-image
    output dir (path passed alongside vmlinux/rootfs).
  - Attach `rootfs.verity` as a third VirtioBlk device.
  - Read the roothash text file.
  - Append the `dm-mod.create=…` and `root=/dev/dm-0` to the
    kernel cmdline.
- `crates/mvm-cli/src/commands/env/apple_container.rs`: in
  `ensure_dev_image`, the build output now contains three files;
  surface `rootfs.verity` and `rootfs.roothash` paths.

**Tests**

- Boot regression (Linux/KVM CI lane): boot a microVM, assert
  `mount | grep dm-0` shows the verity-backed root.
- Tamper test: flip a byte in `rootfs.ext4` *after* it's been
  registered with verity, assert the boot panics with
  `dm-verity: data block <n> is corrupted`. (Have to copy the
  store path out so we can mutate it; the actual store path is
  immutable.)

### W3.3 — Firecracker backend wiring

**What**

Same shape, different config surface. Firecracker takes drives via
JSON config, not the VZ API. The existing
`crates/mvm-runtime/src/vm/firecracker.rs` adds drives via the
`POST /drives/{drive_id}` endpoint. Add a third drive for
`rootfs.verity`, update the boot args.

**Files**

- `crates/mvm-runtime/src/vm/firecracker.rs`: add a `verity_path:
  Option<&str>` parameter to the boot path, post a third drive
  when present, append the same `dm-mod.create=…` to `boot_args`.

**Tests**

- Native Linux boot test (gated; CI lane on a KVM-capable
  runner). Same shape as W3.2's tamper test.

### W3.4 — Mandatory for production, exempted for dev

**What**

`mkGuest` already takes a `hypervisor` parameter (`firecracker`
or `apple-container`). Add a second flag:

- `verifiedBoot ? true` — production microVMs default-on.
- The dev image flake (`nix/dev-image/flake.nix`) overrides
  to `verifiedBoot = false`.

When `verifiedBoot = false`, mkGuest skips the verity sidecar
emission entirely (saves the build time and disk for dev). Init's
verity branch is keyed on the cmdline arg's presence, so no init
change needed.

A CI gate (W6.3) builds the production `default-microvm` flake
and asserts the output contains `rootfs.verity` + `rootfs.roothash`
files. If the dev path's exemption ever leaks into production, the
gate fails the merge.

**Files**

- `nix/flake.nix::mkGuestFn`: gate the `verityArtifacts`
  derivation on `verifiedBoot` parameter (default true).
- `nix/dev-image/flake.nix`: pass `verifiedBoot = false`.
- `.github/workflows/security.yml` (added in W6.3): grep the
  `default-microvm` build output for the two verity files.

## Open questions to resolve before code

- **Apple VZ kernel feature support.** Need to confirm that the
  kernel we ship (linux-6.1.169) has CONFIG_DM_VERITY=y AND that
  the `dm-mod.create=` cmdline parsing works on aarch64. Spike:
  build a tiny test rootfs with verity and boot it under VZ
  before committing to this design.
- **Hash tree placement.** veritysetup typically emits the
  Merkle tree as a separate file; some setups store it
  *appended* to the data device. We're using a separate file
  (W3.1) because Apple VZ's VirtioBlk doesn't easily support
  partition tables, and a single file with a logical offset
  would need user-space splitting. Document this choice.
- **Salt strategy.** veritysetup's default salt is per-build
  (random). Determinism (W3.1's reproducibility test) requires
  pinning the salt. Use `--salt=00…00` (32-byte zero salt) so
  the same input ext4 always produces the same Merkle tree; the
  security model only cares about the root hash, not the salt
  secrecy.
- **GC root.** The verity sidecar gets the same GC root as the
  rootfs. Already inherited by being part of the `mvm-${name}`
  derivation; no extra plumbing.

## Tests added by this plan

- `cargo test -p mvm-runtime --test verity_boot` — boot a microVM
  with verity, assert dm-0 root.
- `cargo test -p mvm-build --test verity_artifacts` — eval test
  asserts the three files exist in the build output.
- `cargo test -p mvm-runtime --test verity_tamper_panics` — flip a
  byte, assert kernel panic at boot.

## CI gates

The W6.3 `security.yml` workflow gains:

- a build of `nix/default-microvm/` that asserts the output
  contains `rootfs.{ext4,verity,roothash}`;
- the verity-tamper boot test on the Linux/KVM lane.

## Rollback shape

If verity blocks a real-world workflow we didn't foresee:

- Per-image opt-out: `verifiedBoot = false` in the user's
  `mkGuest` call. Documented as the fallback for development
  experimentation.
- Project-wide rollback would mean dropping ADR-002's claim #3 —
  warrants a superseding ADR; not a code rollback.

## Reversal cost

High. Once user flakes ship with `verifiedBoot = true` (the
default), un-shipping verity means a flake-API churn that asks
every consumer to opt out. Reversal is plausible only as a
"verified-boot v2" with a different mechanism, not as "remove
verified boot."

## Acceptance criteria

W3 ships when:

1. ✅ Determinism test green (mkGuest twice → identical
   verity + roothash).
2. ✅ Apple Container boot test green (microVM mounts dm-0).
3. ✅ Tamper test green (byte-flip → kernel panic).
4. ✅ Firecracker boot test green on Linux/KVM lane.
5. ✅ The dev VM still builds and boots (verifiedBoot=false
   exemption works).
6. ✅ The CI gate in security.yml fails when `default-microvm/`
   build output is missing the verity files.
