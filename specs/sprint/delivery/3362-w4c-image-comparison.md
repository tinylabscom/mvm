# Compare the mvm-images build with the published image set

Backing: shipped-source
Validation: check-sprint-append; live comparison and boot evidence below

The comparison lane used for the reproducibility evidence is
`tinylabscom/mvm-images` `.github/workflows/reproduce.yml`.

W4c of `specs/plans/2026-09-16-image-repository-extraction.md` asks whether
the images `tinylabscom/mvm-images` builds are the images `mvm` ships, with
every difference explained. `mvm-images` builds from `mvm` pinned at
`6717e2451e`; the published set it is compared with, `boot-image/v0.1.5`, was
built from `032d719429` (132 commits earlier). The initramfs and the standalone
kernels are not on the boot-image train, so they are compared with the
`v0.18.0-rc.1` CLI release (`e3abd2808f`) instead.

Sources: `mvm-images` `build.yml` run 35431276498 (the W4b pull request; its tree
is identical to `main` after the squash merge, and the `main` run 35433442131 is
used as a second independent build), and `reproduce.yml` run 35434194000 from
tinylabscom/mvm-images#5. Rootfs contents were compared with `debugfs rdump` and
a per-file sha256 on a Linux host.

The later aarch64 Firecracker witness uses `build.yml` run 35462836122 from
`mvm-images` `main` at `4c0d55e562dc88032c6d1cd5a3c588dafbdcffc6`.
That tree's `flake.lock` pins `mvm` exactly at
`3720eeccefc959d273a4ce912c75ac56f54315f0`; the default-image metadata records
the same revision as `generatorRev`. The run's `source-drift` job and every
aarch64 producer job passed.

## Against `boot-image/v0.1.5`

The file set matches on both architectures with two kinds of difference.
`v0.1.5` carries 11 cosign `.bundle` files that the build lane does not produce;
it signs nothing, by design, until W6. `mvm-images` also builds the initramfs and
the kernels, which `mvm` publishes from other workflows. Every asset present on
both sides differs in bytes, for the reasons below. Both architectures have the
same explanation, file for file.

| Asset | What differs | Why |
|---|---|---|
| builder and workload `vmlinux`, QEMU-wasm `kernel.img` | Linux 6.12.108 → 6.12.110; the aarch64 builder's embedded config differs only in two upstream Kconfig changes | kernel pin bumps `1c8d5154c3` (#3214) and `fb56ef4f98` (#3281) |
| builder `rootfs.ext4` | 16 of ~17,600 paths: `mvm-setpriv`, `mvm-host-vm-init`, `mvm-egress-proxy`, `mvm-builderd`, the rootfs tree and `/init` that name them, `nix-path-registration`. Every nixpkgs file is identical | `mvm-agentd` and `mvm-build` source changes (for example `136bb8041f`, `d3f82fff54`, `1adb064cc7`), and the `0.18.0-rc.2` version bump `c8e3c98a1c` |
| default microVM `rootfs.ext4` | 9 paths: `/init`, `/etc/mvm/entrypoint` (it names the new `mvm-setpriv` store path), `mvm-setpriv`, `nix-path-registration` | the same source changes |
| `rootfs.verity`, `rootfs.roothash`, builder `manifest.json`, checksum files | follow from the bytes above | derived |
| builder checksum manifest | also lists the SBOM | `028026e023` (#3232) added it to `release-boot-image.yml` |
| SBOMs | 3 (default) and 6 (builder) store paths change hash; no name is added or removed | the mvm-built paths above |
| `default-microvm-meta-<arch>.json` | `generatorRev` only | the documented W4b rewrite (`mvm-src.rev`) |
| runtime overlay | guest binaries; `sdk-py` `_dsl.py`, `_ir/workload.py`, `_protocol/protocol.py`; `VERSION` `0.18.0-rc.1` → `0.18.0-rc.2` | network presets `a424c1a872` (#3415), reseed protocol `1adb064cc7` (#3400), agent changes, version bump |
| SDK sidecars (4) | `libmvm_host_services.so`, `VERSION` | the library links `mvm-agentd` and `mvm-core`, both changed; version bump |
| QEMU-wasm pack | `kernel.img`, `rootfs.bin`, `pack.data`, `pack.js`; the QEMU engine is identical | kernel bump; `rootfs.bin` has identical files and random filesystem metadata (below) |
| initramfs (against `v0.18.0-rc.1`) | `/init` only | agent changes after `e3abd2808f` |
| kernels (against `v0.18.0-rc.1`) | 6.12.109 → 6.12.110 | `fb56ef4f98` |

No difference traced to the build environment: `rust-toolchain.toml` and the
zig and cargo-zigbuild pins are unchanged between the two commits, and
`scripts/build-host-binaries.sh` runs the same toolchain as
`release-boot-image.yml`. No difference is unexplained.

## Same commit

`reproduce.yml` builds the builder VM and the default microVM (prod `default` and
`dev`) from `mvm`'s own in-tree image flakes at `6717e2451e` and from
`mvm-images`, on one runner per architecture. All six `drvPath`s are identical
between the two, so both yield the same output path.

Independent builds of that one derivation do not produce identical bytes.
Between the two `build.yml` runs, every kernel, kernel config, `mvm-meta.json`
and SBOM is byte-identical, and so are the guest binaries in the runtime overlay
and the initramfs. Between `build.yml` and `reproduce.yml`, the kernels and
metadata match, and the builder and default rootfs trees match file for file.
That includes the three `cargo zigbuild` host binaries: the builder image
imports them by content, and its output path is the same on every runner.

What differs is filesystem and verity metadata. Every ext4 has identical files
and a random directory hash seed. The runtime overlay pins its seed, but passes
`-E` twice, and `mke2fs` keeps only the last one. The verity superblock UUIDs
are random, and the initramfs cpio records inode numbers. `nix build --rebuild`
of `default-tenant.default` reports "may not be deterministic" on both
architectures. Recorded as #3499. Until it is fixed, equivalence between two
producers has to be checked file by file rather than by digest.

## Boots

Nothing sanctioned points `mvmctl` at unpublished images yet; that is W5. The
boots below place `mvm-images` artifacts into an isolated `MVM_HOME` in the
layout the resolvers read, so they are development-tier evidence, not a verified
release:

- `cache/default-microvm/dev/{vmlinux,rootfs.ext4,mvm-meta.json}`: the `dev`
  default image from `reproduce.yml`. `mvmctl run` with no image boots the dev
  variant; `build.yml` publishes only prod.
- `cache/runtime-overlay/0.18.0-rc.2/<arch>/`: the overlay tarball's members.
- `cache/initramfs/0.18.0-rc.2/<arch>/`: the initramfs, with its `VERSION`
  sidecar rewritten from `0.18.0` to `0.18.0-rc.2`. Unmodified, the CLI refuses
  it (#3500). The cpio and its hash are untouched.
- `cache/kernels/<arch>/workload/{vmlinux,vmlinux.sha256,config}`: the workload
  kernel.
- `cache/builder-vm/<arch>/{vmlinux,rootfs.ext4,cmdline.txt,manifest.json}`:
  the builder image, with `MVM_BOOT_IMAGE=fetch`, so a source-checkout
  `mvmctl` takes the cache on its structural check rather than the source
  fingerprint.
- `nix/images/runtime-overlay/flake.nix` moved aside in the `mvmctl` checkout
  while booting, so a contributor build does not rebuild the overlay from
  source over the injected one.

`mvmctl` was built from `main` at `f03bcfb435` on each host.

- **x86_64, Firecracker v1.14.1 on KVM.** `mvmctl run --no-detect -- sh -c
  '…'` booted the dev default image (`backend=firecracker`, initramfs and
  overlay attached) and printed `hello-from-mvm-images`, `6.12.110`,
  `mvm-default-microvm-dev`. With the prod bytes from `build.yml`
  (`image_sha256=9744fa4d…`) in the same slot, `echo hi` ran. The logs do not
  say whether dm-verity was engaged on that path. `MVM_BOOT_IMAGE=fetch mvmctl
  machine run --flake ./examples/exit_code` used the cached `mvm-images`
  builder as the Firecracker builder VM (`mvm-host-vm-init` as PID 1). The
  in-guest `nix build` of the fixture against this checkout took 248 s. The
  sealed workload it produced booted on the `mvm-images` workload kernel and
  exited 7, which is what the fixture bakes.
- **aarch64, HVF on macOS 26 (Apple Silicon).** The same `mvmctl run` printed
  `aarch64`, `6.12.110`, `mvm-default-microvm-dev` (`backend=hvf`), and the prod
  bytes (`5536abe9…`) ran `echo`. `MVM_BOOT_IMAGE=fetch mvmctl machine run
  --flake ./examples/exit_code` booted the `mvm-images` aarch64 builder under
  HVF. `mvm-host-vm-init` ran as PID 1, the runtime overlay mounted, and the
  guest agent and egress client started. The build did not finish. The FlowMux
  egress session to the host closed about eight minutes in, after which the
  guest kept one CPU busy with no further console output. The run hit its
  90-minute limit (exit 124) on a host at load average 70 to 250. The same job
  took 248 s on the Firecracker host. The cause is not diagnosed.
- **aarch64, Firecracker v1.14.1 on KVM.** Run 35462836122's default microVM,
  runtime overlay, initramfs, and workload kernel passed their producer
  checksum manifests, then booted through the real `mvmctl run --hypervisor
  firecracker` path in the approved Lima KVM test environment. The sealed prod
  default image was mirrored into the development cache slot that the no-image
  `run` path resolves; its verity sidecars were retained. Admission recorded
  rootfs SHA-256 `341f27c597aa587ceb0f344e48533ff59ec00f9380d798feacccbaf4f997ccc6`,
  the universal initramfs and runtime overlay attached, Firecracker reached the
  serving guest agent in 1,046 ms, activation completed in 401 ms, `/bin/true`
  exited 0, and teardown completed. The chain recorded `plan.launched` for plan
  `sha256:f0c2875b9f55c16ae07d2bf955e330b89e98bf0852f74d681e8f996f9bf07928`.
  The signed receipt SHA-256 is
  `d0e35877cf0552f789ce0614c9f3bdedca62fa480810e20499b4fb11bd81994f`;
  the JSON boot log SHA-256 is
  `045542a3008ac76f0213a8e2caf94a6614d18545b23262ac26524e7b42a46157`.

Two more findings from the boots: a Firecracker transient run rewrites the
cached dev rootfs, which changes its digest on every launch (#3502); and
`examples/exit_code/flake.nix` still documents `--timeout 120`, which the
Firecracker tier now refuses as an unenforceable wall-clock grant.

## aarch64 Firecracker on real hardware (rpi1, 2026-09-21)

The Lima aarch64 run above uses a virtual `/dev/kvm` under the approved
test-environment exception; W4c also asked for the boot on a real aarch64
KVM host. `rpi1.local` (Raspberry Pi 4, GICv2, kernel `6.18.34+rpt`,
Firecracker v1.14.1, `/dev/kvm` usable) provided one.

Setup mirrors the Lima run: the `build.yml` run 35462836122 aarch64 set
(default microVM, runtime overlay, initramfs — its `VERSION` already reads
`0.18.0-rc.2`, workload kernel, builder image), checksums verified on the
host, in the isolated `MVM_HOME` layout above. `mvmctl` was cross-built
from `f03bcfb435` for `aarch64-unknown-linux-gnu` on macOS (the repo's
zig filter-linker wrappers; host helpers built alongside per the release
layout), with one local deviation documented below.

- **Default-image boot: witnessed.** `mvmctl run --hypervisor firecracker
  --no-detect` printed `hello-from-mvm-images-aarch64-rpi1`, `aarch64`,
  `6.12.110`, `witness-done` — the mvm-images default image bytes booted
  end to end through the real `mvmctl` path on real aarch64 KVM hardware.
- **Builder build: blocked by the host kernel, not the images.** Two findings
  came from this witness. The first is resolved: #3577 removed the hardcoded
  `--enable-pci`, so Firecracker keeps virtio devices on MMIO and the GICv2 Pi
  follows the same launch shape as the successful witness build. The remaining
  blocker is #3578: the substitution endpoint confines itself with Landlock and
    the Pi OS kernel has `CONFIG_SECURITY_LANDLOCK` unset, so the endpoint
    refuses to run (`ruleset status NotEnforced; refusing partial
    confinement`), the guest egress proxy never binds, and
    `mvm-host-vm-init` refuses the build ~7s in. No supported opt-out
    exists; the guest-side error names nothing useful.
  With the flag dropped, the builder VM itself boots on the Pi
  (`mvm-host-vm-init` mounts the overlay and forks agent and egress
  client); the build stops only where the endpoint's absence is felt.

So the aarch64 Firecracker *boot* leg of W4c is witnessed on real
hardware. The aarch64 builder *build* is witnessed on x86_64 Firecracker
above; on this Pi it waits on #3578 (or a Landlock-capable kernel).

## HVF builder build on physical Apple Silicon (2026-09-21)

The remaining leg ran after the #3522 egress fix landed. The same isolated
`MVM_HOME` layout, the same `build.yml` aarch64 artifacts, and an `mvmctl`
built from this branch's base with `just embed` (the embedded
`mvm-host-vm-init` et al.), on macOS 26 under load:

`MVM_BOOT_IMAGE=fetch mvmctl machine run --flake ./examples/exit_code`
completed end to end: the `mvm-images` aarch64 builder VM booted under HVF,
the in-guest Nix build of the fixture finished, the sealed workload it
produced was admitted (`plan.admitted`, image `quiet-lynx-257b`, rootfs
sha256 `85c6f04b…` in the audit chain under the isolated home), launched
(`plan.launched`, 2026-09-22T02:24:57Z), and the host exited 7 — the code
the fixture bakes. The built image persists under
`images/sha256:ea828b09…` in the isolated home.

Every leg W4c asked for is now witnessed: the comparison against
`boot-image/v0.1.5` with every difference explained, same-commit
equivalence on both architectures, x86_64 Firecracker boots and a build
through the `mvm-images` builder, the aarch64 boot on real KVM hardware
(rpi1, above), and the builder build on physical Apple Silicon HVF here.

## Remaining

#3499 decides whether the publication gate can compare digests, or has to
compare file trees.
