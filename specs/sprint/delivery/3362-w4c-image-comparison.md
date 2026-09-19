# Compare the mvm-images build with the published image set

Backing: preview
Validation: none — this records a comparison and live boots run by hand
against CI artifacts; no code in this repository changed. The comparison
lane it relies on is `tinylabscom/mvm-images` `.github/workflows/reproduce.yml`.

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
- **aarch64, Firecracker.** Not run. The Raspberry Pi KVM host did not resolve
  from this machine, and no other aarch64 KVM host was available.

Two more findings from the boots: a Firecracker transient run rewrites the
cached dev rootfs, which changes its digest on every launch (#3502); and
`examples/exit_code/flake.nix` still documents `--timeout 120`, which the
Firecracker tier now refuses as an unenforceable wall-clock grant.

## Not yet

W4c stays open until the aarch64 image set boots on Firecracker, and until a
build completes through the `mvm-images` builder on HVF. #3499 decides
whether the publication gate can compare digests, or has to compare file trees.
