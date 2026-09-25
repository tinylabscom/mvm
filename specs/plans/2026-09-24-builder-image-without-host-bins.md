# Builder image without baked host binaries

Backing: preview
Validation: none

**Status:** DRAFT. This is a design; nothing here is implemented. It was
written against `origin/main` at `9ebb81b459` on 2026-09-24. Re-verify every
file:line citation before starting a workstream, because the builder code
moves quickly.

**Related:** `specs/plans/2026-09-22-builder-image-source-freshness.md` (#3524,
the loader-side freshness check this plan narrows),
`specs/plans/2026-09-16-image-repository-extraction.md` and
`specs/plans/2026-09-24-image-cutover-and-deletion.md` (the builder flake is
moving to `mvm-images`), `specs/plans/2026-08-17-embedded-binary-content-store.md`
(the embed cache), ADR-004, ADR-018, ADR-030, ADR-001.

## Problem

From a source checkout, `mvmctl machine run` rebuilds the whole builder VM
image through Stage 0 after nearly every `git pull`. The measured Stage 0 cost
is 17 minutes on the Firecracker builder
(`specs/sprint/delivery/3324-firecracker-builder-image.md:69`), and tens of
minutes on a contributor laptop.

The cause is the cache key. `builder_vm_source_fingerprint`
(`crates/mvm-cli/src/commands/env/builder_vm/stage0_cache.rs:442-488`) folds in
the SHA-256 of **every** embedded Rust host binary (layer 2, lines 459-469). The
binaries it folds are:

- the three baked ones, `mvm-host-vm-init`, `mvm-egress-proxy` and
  `mvm-builderd`;
- two seed binaries, `stage0-init` and `mvm-rootfs-patcher`; and
- one bootstrap-support binary, `mvm-egress-client`.

None of the last three is installed in the image, so folding them is
over-invalidation even by the key's own logic.

The three baked binaries link `mvm-build`, which reaches `mvm-core`,
`mvm-contract`, `mvm-agentd`, `mvm-fs`, `mvm-http`, `mvm-vmm` and `mvm-sdk`.
Layer 4 (`setpriv_source.rs`) adds the source closure of `mvm-agentd`, which
reaches `mvm-core` and `mvm-contract`.

Measured over the 28 days before this plan (549 commits on `main`):

| Path set | Commits touching it | Share |
|---|---:|---:|
| Host-binary crate closure + `Cargo.lock` + toolchain | 239 | 44% |
| `mvm-setpriv` closure (`mvm-core`, `mvm-contract`, `mvm-agentd`) | 138 | 25% |
| Builder flake Nix inputs (`BUILDER_FLAKE_NIX_INPUTS` + the flake) | 41 | 7.5% |
| Any of the above, which is what moves the key today | 260 | 47% |

These are path-level upper bounds: a test-only edit under a crate still counts.
At roughly 20 commits a day, a daily pull moved the key on essentially every
day. #3524 made this sharper, correctly: the generic loader now refuses a cache
whose fingerprint does not match, so a stale image can no longer be booted by
accident.

## How it works today

### Build-time embedding

- `crates/mvm-cli/build.rs:284-296` cross-compiles and embeds six binaries:
  `HOST_BINARIES`, `SEED_BINARIES` and `BOOTSTRAP_SUPPORT_BINARIES`
  (`crates/mvm-cli/src/host_binaries/manifest.rs:31-72`).
- `host_binaries/extract.rs:50-74` extracts them to
  `~/.mvm/cache/host-bins/<combined-hash>/`, checking each against its
  compiled-in SHA-256 (`verify_sha`, line 99).
- `nix/lib/mvm-host-binaries.nix:12-25` is the Nix mirror of `HOST_BINARIES`,
  with install paths under `/sbin`. `xtask check-mvm-host-binaries-sync` holds
  the two in parity.

### Baking into the rootfs

- **In-tree flake.**
  - `nix/images/builder-vm/flake.nix:88-99` reads `MVM_HOST_BIN_DIR` under
    `--impure` and throws if it is unset.
  - `hostBinExtraFilesFor` (101-107) maps `mvm.lib.<system>.hostBinaries` to
    mkGuest `extraFiles` (consumed at 337-340).
  - mkGuest installs them with `install -m` (`nix/lib/mk-guest.nix:1267-1314`)
    into a plain `make-ext4-fs` image (1654-1712).
  - Every output (`default`, `dev`, `stage0-rootfs`) goes through
    `mkBuilderVmRootfs`.
  - The rootfs is not verity-sealed: `entrypoint.shell` makes it a dev image
    (`mk-guest.nix:250-252`).
- **`mvm-images`.**
  - `images/builder-vm/image.nix:72-93` is the same mechanism.
  - Published images get their bytes from
    `scripts/build-host-binaries.sh`, which runs `cargo zigbuild --release` at
    the `mvm` revision pinned in `mvm-images/flake.lock` (currently
    `5460c6e…`).
  - The CI entry point is `.github/workflows/build.yml:129-139`.
  - The published image's binaries therefore come from the pinned `mvm`
    commit, **not** from the running `mvmctl`.
- **Stage 0.**
  - `bootstrap_tool_builder_vm_image_in_process`
    (`env/builder_vm/bootstrap.rs:243-320`) computes the fingerprint.
  - It then materializes the seed root with `stage0-init` as `/init`
    (`crates/mvm-build/src/stage0.rs:342-362`) and runs `Stage0Vm<D>`
    (`crates/mvm-runtime/src/builder_runner/stage0_vm.rs:105-194`).
  - The host packs `{work, mvm-bins, conf}` as a raw tar onto the read-only
    input disk (`builder_runner/runner.rs:154-178`;
    `crates/mvm-build/src/builder_disk_transport.rs:9-21`).
  - `stage0-init` bind-mounts `mvm-bins` at `/mvm-bins`
    (`crates/mvm-build/src/bin/stage0-init.rs:1255-1279`) and exports
    `MVM_HOST_BIN_DIR=/mvm-bins` (1004-1010). It then runs `nix build` of the
    builder flake (1070-1108), which bakes the binaries.
  - The host checks that `/sbin/mvm-host-vm-init` exists in the result
    (`env/builder_vm/image_ops.rs:4-20`, `HOST_VM_INIT_ROOTFS_PATH` in
    `bootstrap.rs`).
- **Pair builds (a sibling `mvm-images` checkout).**
  - This is the default for a contributor whose `mvm-images` checkout sits
    beside `mvm` (`crates/mvm-build/src/image_source.rs:419-472`).
  - `build_target_for_pair` (`crates/mvm-build/src/image_source/build.rs:580-690`)
    readies the tool builder through the in-tree Stage 0 first. It then runs
    `build-host-binaries.sh --mvm-checkout` on the host (357-384) and builds
    `builder-vm.default` inside the tool builder with
    `--override-input mvm path:/work/mvm`.
  - The pair key (`image_source/cache/key.rs:228-266`) includes the whole `mvm`
    checkout identity, so any `mvm` commit rebuilds the pair image too.
  - Worst case after a pull is therefore **two** Nix builder builds: the
    in-tree Stage 0 image and then the pair image.

### Boot and PID 1

There are three builder cmdline producers today, and they disagree about PID 1:

| Path | Cmdline source | PID 1 |
|---|---|---|
| HVF / Firecracker (`BuilderRunner`) | `BUILDER_CMDLINE_TAIL`, `builder_runner/spec.rs:25-27` | `init=/sbin/mvm-host-vm-init` directly |
| libkrun / QEMU, fetched cache | `SYNTHESIZED_BUILDER_VM_CMDLINE`, `env/builder_vm.rs:49-50`, or the image's `cmdline.txt` | busybox `/init`, then `mvm.chain_init=/sbin/mvm-host-vm-init` (`mk-guest.nix:576-583`) |
| Stage 0 | `STAGE0_CMDLINE_TAIL`, `spec.rs:171-173` | the seed's `stage0-init` as `/init` |

PID 1 comes from the Nix-built rootfs on every steady-state path. `init=`
selects the path directly, or through busybox `/init`, so it must exist before
the guest can read anything the host hands it.

`mvm-host-vm-init` then spawns `/sbin/mvm-builderd` by absolute path
(`crates/mvm-build/src/bin/mvm-host-vm-init.rs:2061-2076`). It spawns
`mvm-egress-proxy` from `PATH`, which resolves to `/sbin` (2798-2805).

Every one-shot builder job **already** carries the running CLI's extracted
host binaries at `/mvm-bins`, on the input tar (`runner.rs:98-118`). So does the
HVF persistent builder (`commands/build/persistent_builder.rs:308-325`). They
are there only so that a nested build of the builder flake can bake them.

### The HVF patcher: re-injection already exists, partially

`resolve_hvf_builder_image` (`crates/mvm-cli/src/commands/build/hvf_builder_image.rs:75-210`)
runs on every HVF builder resolution. It:

1. copies the base rootfs;
2. boots a one-shot HVF VM whose initramfs `/init` is `mvm-rootfs-patcher`
   (`builder_runner/inject.rs:39-146`, cpio built by
   `crates/mvm-build/src/rootfs_inject.rs:150`);
3. overwrites `/sbin/mvm-host-vm-init` in the copy; and
4. caches the result under `builder-vm/hvf/<sha(kernel, rootfs, init)>/`.

It re-injects `mvm-host-vm-init` only. `mvm-egress-proxy` and `mvm-builderd`
stay whatever the base image baked. Firecracker, libkrun and QEMU do no
injection (`commands/build/fc_builder_image.rs:1-8`).

### Fetched (release) images

A release `mvmctl` does four things with the builder image:

1. It verifies the signed `image-set.json` against `crates/mvm-core/images.lock`
   (`commands/env/published_image_set.rs:30-77`).
2. It downloads `builder-vm-vmlinux-<arch>` and `builder-vm-rootfs-<arch>.ext4`,
   checking each for digest and size against the signed member
   (`stage0_cache.rs:1063-1133`).
3. It writes its own `cmdline.txt` and `manifest.json`.
4. It records `.mvm-provenance.json` with `source_kind: fetched` and an empty
   `source_fingerprint`.

The set records `mvm_source_commit` (`crates/mvm-core/src/image_set.rs:70-73`),
but nothing compares it for a released set. Nothing compares the baked host
binaries with the running CLI's.

The only compatibility gates are `guest_agent_protocol` and
`builder_cache_contract = 4` (`crates/mvm-build/src/builder_vm.rs:1332`). The
host↔`mvm-host-vm-init` job wire (`HostVmRequest`) carries no version and
relies on `deny_unknown_fields`. **A released CLI at commit Y therefore runs
builder binaries from commit X today**, and drift surfaces only as a runtime
parse failure.

### Consumers of the fingerprint

| Consumer | Location | Role |
|---|---|---|
| Tool-builder bootstrap decision | `env/builder_vm/bootstrap.rs:243-320` | build vs reuse |
| Loader freshness (#3524) | `env/builder_vm.rs:243-257`, registered at `commands/mod.rs:617-627`, consumed by `crates/mvm-build/src/builder_vm_image.rs:18-31,130-300` | configured-cache and shared-seed admission |
| Unembedded-binary preflight | `builder_vm_image.rs:224-300` (`BootstrapPreflight`), `mvm_build::builder_vm_bootstrap` | delegates the decision to an embedded helper, because an unembedded binary cannot compute layer 2 |
| Cache sidecars | `stage0_cache.rs:713-731, 861-895` (`.mvm-source.sha256`, provenance, digest manifest) | persistence |
| `cache ls` display | `commands/ops/cache.rs:1094` | display only |
| HVF baked-image key | `hvf_builder_image.rs:33-39` | separate key over kernel, rootfs and init |
| Pair fingerprint | `env/builder_vm/local_pair.rs:27-30` | a separate key, over the whole `mvm` checkout |
| Tests | `env/builder_vm/builder_vm_bootstrap_tests.rs:902-1290` | layer coverage, import-site scan |

## Design: the builder boot payload

The rule is the one ADR-018 already applies to workloads: *mvm never mutates
image content to inject its own binaries*. The builder image becomes the Nix
output and nothing else. mvm's own Rust for the builder travels beside it, as a
**builder boot payload** that the running `mvmctl` assembles from its embedded
bytes at every boot.

### Format: an initramfs, not a disk

The payload is a deterministic newc cpio, loaded by the VMM as the guest
initramfs. Its contents:

```
/init                              mvm-host-vm-init (stage-1 role, below)
/mvm/host-bins/mvm-host-vm-init
/mvm/host-bins/mvm-egress-proxy
/mvm/host-bins/mvm-builderd
/mvm/host-bins/MANIFEST            "<name> <sha256>" per binary, sorted
```

`/init` and `/mvm/host-bins/mvm-host-vm-init` are the same bytes. The cpio
writer can emit a hard link, or the file twice; it is about 0.75 MB either way.

Why an initramfs rather than the read-only block device the problem statement
suggested:

- **PID 1 is solved by construction.** The kernel runs the initramfs `/init`
  before any root is mounted. PID 1 does not have to pre-exist in the image,
  and no in-image shim is needed.
- **Every backend already loads one.** `VmmSpec.initramfs` exists and is used
  by the workload runner (`crates/mvm-backends/src/driver/qemu.rs:183-185`;
  Firecracker `initrd_path`; HVF `HvfSupervisorConfig.initramfs`, used by
  `inject.rs`). libkrun's `krun_set_kernel` takes one
  (`crates/deps/libkrun-sys/src/start.rs:121-127`).
- **No new device slot, no label discovery, and no guest filesystem driver.**
  The builder already juggles five to six disks whose slot order is load-bearing
  (`spec.rs:119-133`).
- **No verity question.** The builder kernel deliberately drops
  `MD`/`BLK_DEV_DM`/`DM_VERITY` (`nix/images/kernel/builder.nix:57-65`). A
  verity-protected disk would need a kernel change and `CONFIG_DM_INIT`. The
  kernel lives in `mvm-images`, and the Stage 0 kernel is a fetched bootstrap
  seed, so that change is slow to deliver. An initramfs is loaded into guest
  RAM by the VMM from a host file, which is the same trust class as the kernel
  image itself.
- **The code exists.** `rootfs_inject::build_newc_cpio` writes the archive in
  process. `mvm_agentd::guest_mount::pivot_to_root`
  (`crates/mvm-agentd/src/guest_mount.rs:520-545`) is the canonical
  switch_root sequence the workload initramfs uses.

Size is about 1.9 MB uncompressed today (0.76 + 0.47 + 0.66 MB). It is written
uncompressed, because every backend accepts that and it avoids a compressor in
the loop.

### Assembly and integrity on the host

- The payload is assembled **per boot, in memory, into the VM's own 0700 state
  directory**. It is not placed in a shared cache. Assembly is a copy of about
  2 MB of already-extracted bytes, well under 100 ms, so a cache buys nothing
  and would add a poisoning surface.
- Its source is `host_binaries::ensure_extracted`, which already re-verifies
  each file against the compiled-in SHA-256 (`extract.rs:62-66`). The chain is:
  embedded bytes (their digests compiled into `mvmctl`, which release signs
  under claim 20) → extraction checked against those digests → cpio. No
  unverified byte enters the payload.
- The payload's own SHA-256 goes on the cmdline as `mvm.boot_payload=<hex>`.
  Stage 1 recomputes the digest over the unpacked `MANIFEST` and binaries and
  refuses to continue on a mismatch.
  - This is a **consistency check against host-side mix-ups** (a stale file at
    the path, a wrong pairing), not a security boundary. A host that can
    rewrite the payload can rewrite the cmdline too, and ADR-001 puts a
    malicious host out of scope. It is stated that way in the ADR text below.
- The cpio is deterministic: fixed mtime 0, uid and gid 0, fixed modes, sorted
  entries. Two hosts running the same `mvmctl` produce byte-identical payloads.
  That keeps ADR-004's "which VMM ran it is never visible" property.

### Guest boot sequence

The kernel unpacks the payload and runs `/init`, which is `mvm-host-vm-init`.
It detects stage 1 by being PID 1 with `/mvm/host-bins/MANIFEST` present and
no stage-2 marker in its environment. Stage 1 then:

1. Mounts `/proc`, `/sys`, `/dev` (devtmpfs), and tmpfs on `/run` and `/tmp`,
   all inside the initramfs. `pivot_to_root` moves exactly these five and fails
   if one is not a mount point.
2. Verifies the payload digest (above).
3. Copies `/mvm/host-bins/*` to `/run/mvm/host-bins/` (mode 0555) on that
   tmpfs. The binaries then survive the pivot as part of `/run`.
4. Reads `root=`/`rootfstype=` from `/proc/cmdline`, waits for the device
   (`rootwait` semantics), and mounts it **read-only** at `/sysroot`.
5. Reads `/sysroot/etc/mvm/builder-boot-abi`. It refuses with a console marker
   naming both numbers if the file is outside the range this payload supports.
   See *Compatibility contract* below.
   - mkGuest images already carry `/run` and `/tmp` as mount points
     (`mk-guest.nix:564-568`), so the image needs no new directory.
6. Unlinks the initramfs payload files to return their RAM, then calls
   `pivot_to_root("/sysroot")`, which moves `/proc`, `/sys`, `/dev`, `/run` and
   `/tmp` into the new root and chroots.
7. `execv("/run/mvm/host-bins/mvm-host-vm-init", …)` with a stage-2 environment
   marker, because the cmdline cannot change. PID 1 stays PID 1, now backed by
   a tmpfs file rather than the discarded ramfs.

Stage 2 is today's `mvm-host-vm-init`, with three edits:

- tolerate pseudo-filesystems that are already mounted. In particular, it must
  **not** mount a fresh tmpfs on `/run`, which it does today
  (`mvm-host-vm-init.rs:2888-2909`), because that would hide
  `/run/mvm/host-bins`;
- spawn `mvm-builderd` and `mvm-egress-proxy` from `/run/mvm/host-bins`
  (one constant, replacing the `/sbin` literals); and
- prepend that directory to `PATH` for its children.

The builder cmdline drops `init=/sbin/mvm-host-vm-init` and
`mvm.chain_init=…`. The payload's `/init` is the kernel's default `rdinit`.
The steady-state producers (`BUILDER_CMDLINE_TAIL`,
`SYNTHESIZED_BUILDER_VM_CMDLINE`, the QEMU rewrite in
`crates/mvm-build/src/qemu_builder.rs:1474-1500`, and the libkrun
`checked_builder_cmdline` call sites) converge on one builder boot-contract
function. Four drifting copies are how Firecracker once got HVF's console
tokens (`spec.rs:17-23`).

### Compatibility contract

The image gains one file, `/etc/mvm/builder-boot-abi`, containing an integer.
It is written by the builder flake and is stable across Rust changes. It names
what the payload may assume about the image:

- `/run` exists as a mount point;
- busybox, `nix`, `iptables` and `/usr/bin/firecracker` are at their paths;
- the builder uid 902 exists in `/etc/passwd`;
- the persistent-store layout on `/dev/vdb`.

The payload declares the ABI range it supports. Stage 1 refuses outside that
range; it never guesses.

- **Legacy images** (no marker, host binaries baked in `/sbin`) are ABI `0`.
  The new payload supports `0` during the transition, because its `/init` wins
  regardless and the baked copies are simply never executed.
- **The image set** gains `builder_boot_abi` beside `builder_cache_contract` in
  the signed manifest's `[compatibility]` and in `images.lock`. Acquisition
  refuses a mismatch before download, as it already does for the cache
  contract. The field name needs the `mvm-images` schema owner's agreement; see
  open questions.
- `BUILDER_VM_CACHE_CONTRACT_VERSION` moves 4 → 5, because the cached
  artifact's meaning changes. See *Migration*.

### What the image and its key become

- **Both builder flakes stop baking host binaries.** This covers the in-tree
  flake while it exists (W8 deletes it) and `mvm-images`'
  `images/builder-vm/image.nix`. Specifically:
  - `hostBinDir`, `hostBinExtraFilesFor`, the `MVM_HOST_BIN_DIR` throw and
    `mvm.lib.<system>.hostBinaries` leave the builder evaluation.
  - `extraFiles` keeps only `/usr/bin/firecracker`.
  - `nix/lib/mvm-host-binaries.nix` and its sync gate are retired. `mvm-images`
    must stop reading `hostBinaries` **before** `mvm` deletes the export (see
    *Sequencing*).
- **Evaluation becomes pure on the `mvm-images` side.** That repository already
  refuses `MVM_WORKSPACE_PATH`, and `MVM_HOST_BIN_DIR` was its remaining impure
  input for the builder. Dropping `--impure` from the builder job lets its
  reproducibility lane rebuild the image with nothing out of band.
- **`builder_vm_source_fingerprint` loses layer 2** and keeps layers 1, 3 and 4.
- **Layer 4 must narrow too, or half the win is lost.** `mvm-setpriv` is the
  one mvm Rust binary that has to stay in the image: mkGuest's `/init` and the
  closure registration reference it by store path (`mk-guest.nix:285-294,
  341-350`). It is a 462-line binary whose only workspace uses are
  `mvm_agentd::fd_hygiene::configure_close_fds` and four capability constants,
  the latter in tests only. But `cargo build -p mvm-agentd --bin mvm-setpriv`
  (`nix/packages/mvm-setpriv.nix`) compiles all of `mvm-agentd`, `mvm-core` and
  `mvm-contract` inside Nix, and the key has to hash that closure: 138 of the
  549 commits above. Moving the binary into a leaf package whose closure is
  `libc` alone makes layer 4 move only when the privilege-drop helper itself
  changes. It also shortens every image build that compiles it, workload
  images included. This is a crate-count decision; see open questions.
- **The pair key narrows by role.** For `ImageBuildRole::BuilderVm`, the `mvm`
  half of `LocalImageCacheKey` becomes a digest of exactly what the `mvm-images`
  builder evaluation reads from the `mvm` input: `nix/flake.nix`,
  `nix/flake.lock`, `nix/lib`, the builder-reachable `nix/packages` recipes,
  the kernel configs, and the setpriv closure. It is not the checkout's commit
  and dirty state. Other roles keep the whole-checkout identity until each has
  its own derived input set.
  - The derivation must come from the same import-site scan that
    `BUILDER_FLAKE_NIX_INPUTS` is tested against
    (`builder_vm_bootstrap_tests.rs:1101-1170`). A key narrower than the flake's
    real reads serves a stale image, which is the #3447 lesson.
- **The unembedded-binary preflight simplifies.** The fingerprint no longer
  needs the embed table, so a plain `cargo build` `mvmctl` can decide freshness
  itself. It still needs the payload to *boot*, and it keeps today's helper
  re-exec for that. `SourceCheckoutFreshness::BootstrapPreflight`
  (`builder_vm_image.rs:31-35`) goes away.

### Per backend

| Backend | Change |
|---|---|
| HVF (one-shot, `BuilderRunner`) | `builder_spec` sets `initramfs: Some(payload)` (today `None`, `spec.rs:136`); the cmdline tail drops `init=`. `resolve_hvf_builder_image` and the patcher VM are **deleted**: `hvf_builder_image.rs`, `builder_runner/inject.rs`, the `mvm-rootfs-patcher` bin and its `SEED_BINARIES` entry. HVF boots the Stage 0 or fetched image as-is, like Firecracker. This also removes a full rootfs copy per `mvm-host-vm-init` change under `builder-vm/hvf/`. |
| Persistent builders: HVF (`builder_runner/hvf_persistent.rs`) and libkrun; QEMU and Firecracker refuse (`commands/build/persistent_builder.rs:199-225`) | Same payload at boot. **New staleness rule:** the persistent builder records the payload digest it booted with in its session record (`~/.mvm/run/persistent-builder.json`, `crates/mvm-build/src/persistent_builder.rs:854-857`). A CLI whose payload digest differs stops it and boots a fresh one. Today a running persistent builder keeps whatever init it booted with, and only its `/mvm-bins` is current (`commands/build/persistent_builder.rs:305-311`). |
| Firecracker (`BuilderRunner`) | Same as HVF one-shot: `initrd_path` from `VmmSpec.initramfs`. `fc_builder_image.rs` is unchanged. The persistent builder is still refused by name. |
| libkrun (`crates/mvm-build/src/libkrun_builder.rs`) | Set `KrunContext.initramfs_path` beside `rootfs_path`. `validate_boot_config` (`libkrun-sys/src/start.rs:180-219`) currently rejects that pair (`has_rootfs == has_initramfs`); the underlying call already passes both (`start.rs:121-130`). Relax the rule to allow `rootfs + initramfs` and add a unit test. Replace the image-cmdline `init=/init mvm.chain_init=` with the shared boot contract. libkrun Stage 0 (`root_dir` over virtiofs, bundled libkrunfw kernel) is unchanged. |
| QEMU (`crates/mvm-build/src/qemu_builder.rs`) | The steady-state builder (around 1316) adds `-initrd <payload>`; `qemu_build_cmdline` stops preserving `init=`. The QEMU **Stage 0** path boots the host distro's kernel and initrd (`qemu_builder.rs:664-688`) and is untouched, because Stage 0 does not use the payload. |
| Stage 0 (all backends) | Unchanged in shape. It still boots the host-assembled seed with `stage0-init` as `/init` and still carries `/mvm-bins/mvm-egress-client` on the input tar. It stops exporting `MVM_HOST_BIN_DIR`, because the flake no longer reads it. The post-build check changes from "`/sbin/mvm-host-vm-init` exists" to "`/etc/mvm/builder-boot-abi` exists and is supported". The Stage 0 output then depends on nothing from `stage0-init`'s bytes, which was already true of its content. |

Builder **jobs** stop packing `mvm-bins` onto the input tar (`runner.rs:111`,
`hvf_persistent.rs:203`, `libkrun_builder.rs:414,1106,3146`,
`qemu_builder.rs:1268`). Its only consumer was the nested builder-flake bake.
Stage 0 keeps its own `mvm-bins`.

### Published images

- The released builder image carries no mvm Rust except `mvm-setpriv`, which is
  compiled by Nix from the pinned `mvm` source. It is authenticated as today: a
  root-filesystem digest inside the signed `image-set.json` (claim 20).
- The host binaries are pinned **by being inside the signed `mvmctl` archive**.
  Their SHA-256 values are compiled into the binary that release signs and
  attests (claim 20, `ci:release-provenance`). No image-manifest field is needed
  to pin them, and none is added. That removes today's unpinned case, where the
  bytes executed in a released builder came from `mvm-images`' pinned `mvm`
  commit and were never compared with the CLI's.
- `mvm_source_commit` stays as provenance for the image's Nix-built content and
  `mvm-setpriv`.
- `scripts/build-host-binaries.sh` and the builder job's cargo-zigbuild step
  leave `mvm-images`. The image train no longer builds Rust for the builder
  beyond `mvm-setpriv`.

## Security analysis

### What ADR-004 covers today, and after

| Property | Today | After |
|---|---|---|
| Builder rootfs verity | none; ADR-004 accepts the gap explicitly | none; unchanged |
| Identity of mvm's Rust in the builder (source checkout) | fingerprint layer 2 over the embed table, checked against `.mvm-source.sha256` before boot (#3524) | the bytes *are* the running `mvmctl`'s embed table, re-verified at extraction and assembled per boot. No cache entry can be stale, because there is none |
| Identity of mvm's Rust in the builder (release) | bytes from `mvm-images`' pinned `mvm` commit, authenticated as part of the rootfs digest but never compared with the CLI | the CLI's own embedded bytes, authenticated by the CLI archive signature |
| HVF | init patched into a cached copy by a helper VM; proxy and daemon stale | no patching; one path for all backends |
| Image build purity | `--impure` for `MVM_HOST_BIN_DIR` | pure on the `mvm-images` side; the in-tree flake stays impure for `MVM_WORKSPACE_PATH` until W8 deletes it |
| Cache key | Nix inputs + setpriv closure + six binary digests | Nix inputs + setpriv leaf; binary identity is not a cache property any more |

Nothing is weakened. Two properties improve: the release path's CLI/image skew
is gone, and every backend runs the same bytes.

The residual change is that the builder's PID 1 now comes from a host file the
VMM loads, not from a host file the VMM attaches as `/dev/vda`. Both are
host-trusted inputs under ADR-001's threat model, and the kernel image already
arrives the first way.

### ADR-001 claims ledger

No row's witness set changes. The builder is not a claim-bearing tier for the
workload claims.

- **Claims 1–5 and 8–19** concern workload guests, admission, the broker and
  the audit chain. The builder boots from no admitted plan (`spec.rs:154-156`).
- **Claim 3** (tampered rootfs fails to boot) is scoped to sealed workload
  rootfs on block+ext4 backends. ADR-004 already excludes the builder, and that
  does not change.
- **Claim 6** (`ci:hash-verify-tests`,
  `download_runtime_overlay_rejects_checksum_mismatch`) covers the runtime
  overlay and dev image downloads. Untouched.
- **Claim 7** (`ci:reproducibility`) double-builds `mvmctl`, which is where the
  host binaries now live exclusively. The `mvm-images` builder build becomes
  pure, which helps that repository's own reproducibility lane. No witness
  moves.
- **Claim 10** is about untrusted workloads. The builder's egress rides the
  same endpoint under `trusted_build_egress()`. `mvm-egress-proxy`'s
  owner-match lockdown is builder defense in depth; it changes where the binary
  is read from, not what it enforces.
- **Claim 11** names `mvm-host-vm-init` and the `LibkrunBuilderVm::run_build`
  Install arm. The code is unchanged. Its witnesses (`ci:app-deps-audit` and
  the sealed-volume verifier) do not depend on how the binary reaches the
  guest.
- **Claim 20** keeps every witness. What changes is which signed artifact
  covers the builder's host binaries: the CLI archive rather than the image
  set's rootfs member. The row's prose already covers both.

There is no ADR-001 edit. W6 adds new witnesses for the boot payload as
ordinary tests, not ledger rows, because the builder is not a claim tier. See
open questions.

### Proposed ADR-004 amendment (text to add under Decision)

> **mvm's own builder binaries travel beside the builder image, not inside it.**
> The builder image is the Nix output of the builder flake and nothing else:
> the flake bakes no binary from `mvmctl`'s embedded payload. At every builder
> boot, `mvmctl` assembles a deterministic initramfs from its embedded
> binaries, each re-verified against the SHA-256 compiled into `mvmctl`. The
> VMM loads it the way it loads the kernel. Its `/init` mounts the image
> read-only, copies the binaries to a tmpfs, pivots, and continues as the
> builder's PID 1. The payload digest travels on the kernel cmdline, and the
> guest refuses a payload that does not match it. That check catches host-side
> mix-ups; a malicious host is outside this ADR's threat model.
>
> The image declares a builder boot ABI, and the payload refuses an image
> outside its supported range. The builder image's cache key therefore covers
> only what Nix builds. In a release, the builder's host binaries are
> authenticated by the `mvmctl` archive signature rather than by the image
> set, and they always match the running CLI.

And in Consequences, replace "content-addressed caching keyed to the
workspace, the embedded-binary content hash, and the flake" with "keyed to the
flake and the Nix and Rust sources it compiles". Add:

> A Rust-only change to `mvmctl` no longer rebuilds the builder image.

Also correct the stale backend paragraph while there. It names three backends
and "native Linux uses QEMU"; auto-detect now answers Firecracker on
Linux-with-KVM, and there are four builder backends.

### Proposed ADR-030 amendment

Item 4 is unchanged in substance. Append:

> The builder image a source checkout builds contains no binary from `mvmctl`'s
> embedded payload. Those binaries are supplied at boot from the running
> `mvmctl`, so they are never a downloaded, published artifact on any channel.

### ADR-018 cross-reference

Add one sentence to ADR-018's Context, pointing at ADR-004's amendment as the
builder analogue of "mvm never mutates image content to inject its own
binaries".

## Alternatives considered

1. **Keep baking, fold only the three baked binaries.** This is correct, and
   it is W0 below because it is free. But `mvm-host-vm-init` links `mvm-build`
   and through it most of the workspace, so the key still moves on about 44% of
   commits. It does not solve the problem.
2. **Keep baking, key on a narrower *source* set.** For example, hash only
   `crates/mvm-build/src/bin/**`. Rejected: this is the stale-image hole #3524
   closed. The bytes depend on their whole closure, and a key narrower than the
   bytes boots old code.
3. **Generalize the HVF patcher to every backend and all three binaries.**
   This decouples the Nix build, but every host-binary change costs a full
   rootfs copy (gigabytes) and a helper-VM boot per backend. It keeps a second
   mutable image identity (`builder-vm/hvf/<key>`), needs a patcher boot path
   on Firecracker, libkrun and QEMU, and still bakes. Strictly worse than
   loading the bytes.
4. **A read-only ext4 "host-bins" disk,** mounted by the image's busybox
   `/init` before chaining (the original direction). Workable: the pure-Rust
   ext4 writer builds it in milliseconds, and busybox `/init` could `findfs
   LABEL=`. Rejected against the initramfs because:
   - it needs a disk slot on every backend, in a layout whose ordering is
     already fragile;
   - it needs label discovery in shell;
   - it needs a busybox `/init` path for HVF and Firecracker, which boot
     `init=` directly today; and
   - integrity by dm-verity would need `DM_VERITY` and `DM_INIT` put back into
     the builder kernel, which Stage 0 fetches as a pinned seed.

   Without verity, it gives the same host-trust integrity as the initramfs
   with more moving parts.
5. **A layered image (Nix base + a small Rust overlay via overlayfs).**
   Assembling an overlay root needs an initramfs anyway, so this is design 4
   plus overlayfs.
6. **Make contributors fetch by default** (`MVM_BOOT_IMAGE=fetch`). This
   contradicts ADR-030 item 4. It would also boot binaries from `mvm-images`'
   pinned commit rather than the contributor's tree, which is the skew this
   plan removes.
7. **Key on the Nix derivation path.** Boot the existing builder, `nix eval`
   the builder attribute's `drvPath`, and reuse the image when it is unchanged.
   This key is exact and would absorb false positives in layer 3, for example a
   workload-kernel config edit under `nix/images/kernel`. It needs a bootable
   builder to evaluate, which this plan provides, because an older image stays
   bootable with the new payload. Deferred as a follow-up (open question 5), not
   rejected.

**Recommendation:** the boot-payload initramfs, together with W0, the
`mvm-setpriv` leaf and the per-role pair key. Without the last two, a
`mvm-core` or `mvm-contract` edit still rebuilds through layer 4 and through
the pair key.

## Performance estimate

| Change after a pull | Today | After |
|---|---|---|
| Rust-only, outside the setpriv leaf (the common case) | Stage 0 rebuild: 17 min measured on Firecracker, tens of minutes on laptops. On HVF, plus a rootfs copy and patcher boot. With a sibling `mvm-images`, plus a host `cargo zigbuild` of three binaries and a second in-builder Nix build of the pair image | `cargo build` re-embeds (the embed content store already keys this) plus payload assembly under 100 ms. **No Nix, no VM before the job VM** |
| Edit to `mvm-setpriv` itself | full rebuild | full rebuild (rare) |
| Builder Nix inputs (`nix/lib`, `nix/packages`, kernel configs, flake locks) | full rebuild | full rebuild. Median-case cost is unchanged by this plan; the `drvPath` follow-up would cut false positives |
| Boot of the builder VM | kernel + rootfs | plus about 2 MB of initramfs unpack and copy, estimated under 50 ms, to be measured in W6 |

On the 28-day sample, the builder-image key would have moved on about 41 of 549
commits (7.5%, all Nix-input edits) instead of 260 (47%). That is roughly one
day in three of daily pulls rather than every day. Many of those 41 are
kernel-pin bumps and image-extraction work, which leave this repository with W8.

## Migration and cache invalidation

- `BUILDER_VM_CACHE_CONTRACT_VERSION` 4 → 5. Every existing
  `builder-vm/<arch>/` cache (Stage 0, pair or fetched) is rebuilt or
  refetched **once**, because the fingerprint shape changes and the new image
  lacks nothing the new payload needs. Say so in the release notes. The shared
  seed at `~/.mvm/cache/builder-vm` fails the contract check and is not copied
  (`builder_vm_image.rs:185-225`).
- `builder-vm/hvf/<key>/` entries become orphans. `mvmctl cache prune` learns to
  remove them. They are removed rather than migrated.
- Persistent builders from an older CLI are stopped on first contact, under the
  payload-digest rule above.
- `images.lock` gains `builder_boot_abi`, which reaches the lock through
  `xtask repin-image-lock`. Old CLIs keep their compiled lock and so their old
  image set: they never see an image without baked binaries. A new CLI accepts
  legacy ABI `0` images, so the order in which `mvm` and `mvm-images` land does
  not strand anyone.

### Sequencing across repositories

1. `mvm`: the payload and stage 1 land. The new CLI boots old images (ABI 0)
   and new ones. The in-tree flake still bakes, which is harmless because the
   payload wins.
2. `mvm-images`: stop consuming `mvm.lib.hostBinaries` and `MVM_HOST_BIN_DIR`,
   write the ABI marker, drop `build-host-binaries.sh` from the builder job,
   and publish an image set with `builder_boot_abi = 1`.
3. `mvm`: pin that set (`update-image-pin.yml`), then remove layer 2, the in-tree
   bake (if W8 has not already deleted the in-tree flake), the `hostBinaries`
   export and its sync gate, and the job-side `mvm-bins` packing.

W8 of `2026-09-24-image-cutover-and-deletion.md` may delete
`nix/images/builder-vm` first. If so, the in-tree edits in step 3 are moot, and
the Stage 0 flake reference follows W8's re-pointing.

## Workstreams

- [ ] **W0 — fold only what is baked.** Layer 2 folds `HOST_BINARIES` rather
      than `EMBEDDED`, so `stage0-init`, `mvm-rootfs-patcher` and
      `mvm-egress-client` edits stop invalidating the builder cache. Tests:
      the fingerprint is unchanged when a seed or support binary's digest
      changes, and changed when a baked one's does. Independent of everything
      below; it lands first.
- [ ] **W1 — payload assembly.** In `mvm-build`, next to
      `rootfs_inject::build_newc_cpio`, add a deterministic payload builder
      that takes the extracted host-bin directory and returns bytes plus a
      digest. Use a builder struct, not positional arguments. Tests:
      byte-identical output across runs and input orders, the `MANIFEST`
      matches the bytes, a tampered input file is refused because extraction
      verification fails, and golden-digest stability.
- [ ] **W2 — stage 1 in `mvm-host-vm-init`.** Detection, payload-digest check,
      root mount, ABI check, tmpfs copy, `pivot_to_root` reuse, and re-exec.
      Stage 2 tolerates pre-mounted pseudo-filesystems and resolves siblings
      from `/run/mvm/host-bins`. Tests: unit tests for cmdline parsing,
      ABI-range decisions (in, below, above, missing equals 0), and digest
      mismatch refusal; a Linux-gated test of the copy and pivot plan against a
      temp root. Run `just check-gated`, because this is `cfg(target_os =
      "linux")` code macOS cannot compile.
- [ ] **W3 — one builder boot-contract cmdline.** Converge
      `BUILDER_CMDLINE_TAIL`, `SYNTHESIZED_BUILDER_VM_CMDLINE`, the QEMU
      rewrite and the libkrun call sites on one function that emits
      `mvm.boot_payload=` and no `init=`. Tests: one table test over all four
      backends' console tokens.
- [ ] **W4 — wire every backend.** HVF and Firecracker `builder_spec` and
      `persistent_builder_spec`; libkrun, including relaxing `validate_boot_config`
      with a test that `rootfs + initramfs` is accepted and `root_dir +
      initramfs` still refused; QEMU steady state. Stop packing job-side
      `mvm-bins`.
      - While at these call sites, attach the builder root **read-only at the
        VMM** on libkrun (`libkrun-sys/src/start.rs:128-129` passes `false`)
        and QEMU (no `readonly=on`, `qemu_builder.rs:1321-1329`).
      - Today only the guest's `ro` cmdline token protects the shared cached
        image on those two backends. After this change, stage 1 owns the root
        mount and nothing in the guest writes it. HVF and Firecracker already
        enforce read-only at the VMM.

      Live witnesses: a builder job completes on HVF (Apple Silicon
      host) and Firecracker (the KVM box). libkrun and QEMU get one explicit
      `--builder` run each; record them in the delivery note.
- [ ] **W5 — persistent-builder payload staleness.** Record the payload digest
      in the persistent builder's state; on mismatch, stop and restart it.
      Tests: a mismatched digest triggers a restart and a matching one reuses.
- [ ] **W6 — delete the HVF patcher.** Remove `hvf_builder_image.rs`'s bake,
      `builder_runner/inject.rs`, the `mvm-rootfs-patcher` bin and its
      `SEED_BINARIES` entry, and `hvf-rootfs-inject`. Teach `cache prune`
      about `builder-vm/hvf/`. Measure boot overhead (payload assembly plus
      guest stage 1) on HVF and Firecracker, and record it in the delivery note.
- [ ] **W7 — the `mvm-images` side** (a PR in that repository). Stop consuming
      `hostBinaries`/`MVM_HOST_BIN_DIR`, write `/etc/mvm/builder-boot-abi`,
      drop the builder job's host-binary build, drop `--impure` for the builder
      attribute, add `builder_boot_abi` to `assemble-release.py` and the
      manifest schema, and publish.
- [ ] **W8 — `mvm` cut-over.** Pin the new set. Remove fingerprint layer 2
      and the unembedded `BootstrapPreflight` path. Remove the in-tree bake
      (unless already deleted by the cutover plan's W8),
      `nix/lib/mvm-host-binaries.nix`, `xtask check-mvm-host-binaries-sync`
      and Stage 0's `MVM_HOST_BIN_DIR` export. Replace the Stage 0
      `/sbin/mvm-host-vm-init` check with the ABI-marker check. Move the cache
      contract 4 → 5. Tests: update the fingerprint layer tests
      (`builder_vm_bootstrap_tests.rs`) so a change to the embed table no
      longer moves the key and every Nix input still does.
- [ ] **W9 — `mvm-setpriv` leaf.** Move the binary into a package with a
      `libc`-only closure (pending the crate-count decision), vendoring
      `configure_close_fds`. Point `nix/packages/mvm-setpriv.nix` and
      `setpriv_source::SETPRIV_PACKAGE` at it. Tests: the existing layer-4
      tests (`builder_vm_source_fingerprint_changes_with_setpriv_source`,
      `…_ignores_changes_outside_the_setpriv_closure`) now name the leaf, and
      an `mvm-core` edit no longer moves the key. Claims 1 and 2 witnesses
      that exercise `mvm-setpriv` stay green unchanged.
- [ ] **W10 — per-role pair key.** Replace the `mvm` whole-checkout identity in
      `LocalImageCacheKey` for `BuilderVm` with the derived input digest,
      generated from the same import-site scan. Tests: a crate edit outside
      the builder's inputs does not move the builder-vm pair key; an edit to
      each listed input does; other roles are unchanged.
- [ ] **W11 — ADR amendments** (ADR-004, ADR-030, ADR-018 cross-reference),
      landed in the same PR as W8, with the text above. Update `CLAUDE.md`
      §"Builder backend selection", the contributor guide's builder section,
      and `specs/REFACTOR-STATUS.md`.
- [ ] **W12 — measured acceptance.** On the Apple Silicon workstation and the
      KVM box: after a one-line `mvm-core` edit plus `just embed`, time
      `mvmctl machine run` end to end, before and after. Acceptance: no Stage 0
      and no Nix build is started, which the console log and `mvmctl doctor`'s
      builder line both show. Record the numbers in
      `specs/sprint/delivery/<issue>-builder-boot-payload.md`.

## Test and witness plan

- **Negative paths:**
  - a payload digest mismatch halts in stage 1 with a named marker;
  - an image ABI above or below the supported range is refused, naming both
    numbers;
  - an image missing `/run` is refused;
  - libkrun still refuses `root_dir + initramfs`;
  - `image-set.json` with an unknown `builder_boot_abi` is refused at
    acquisition, before download.
- **Positive paths:** a legacy ABI-0 image boots with the payload, which W4's
  live runs cover for a cached pre-change image; a new image boots; the
  payload is byte-identical across two runs; all four backends pass the table
  test.
- **Regression lock:** a test enumerates the builder flake's `extraFiles` keys
  (read from the flake source, like the import-site scan) and fails if any
  entry resolves under `MVM_HOST_BIN_DIR`. This stops re-baking from creeping
  back.
- **Gates:** `cargo nextest run --workspace`, doc tests, `just check-gated`
  (stage 1 is Linux-gated), Clippy with `-D warnings`, `cargo fmt --all`, and
  the repository gates. `check-builder-shell-job-sites` and
  `check-single-network-path` must stay green; the payload adds no network
  path.

## Decisions

Taken on 2026-09-24.

1. **Crate count for W9.** `mvm-setpriv` becomes its own leaf package. Leaving
   layer 4 wide keeps about 25% of commits rebuilding the image, which costs
   more than one small guest-only crate.
2. **Schema field.** The boot ABI gets its own `builder_boot_abi` field in the
   signed image-set `[compatibility]` section, so a Nix-only change can bump
   `builder_cache_contract` without claiming an ABI change.
3. **Legacy ABI 0 support window.** Marker-less images stay accepted for one
   release cycle: until the `image-set` carrying `builder_boot_abi = 1` is the
   only pinned set and the W7 window of the cutover plan has closed.
4. **Witness status.** The builder boot payload is covered by ordinary tests.
   ADR-004 keeps the builder outside the numbered claims, and this plan does
   not change that.
5. **`drvPath` keying (alternative 7).** A follow-up plan, once the payload
   makes any cached image bootable.
6. **Ordering against the cutover plan's W8.** Stage 0 remains a from-seed
   source build for contributors after `nix/images/builder-vm` is deleted,
   because ADR-030 item 4 depends on it.

## Non-goals

- Sealing the builder rootfs with dm-verity. ADR-004's accepted gap is
  unchanged.
- Changing the workload initramfs or runtime overlay (ADR-018).
- Changing Stage 0's seed, its pinned kernel, or its `/mvm-bins` input.
- Removing `mvm_source_commit` from the image set.
