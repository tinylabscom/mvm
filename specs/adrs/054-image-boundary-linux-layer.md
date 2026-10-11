# ADR-054: mvm-images owns the Linux layer; mvm ships the guest runtime

Backing: preview
Validation: none

## Status

Accepted, 2026-10-05. Tracking issue:
[#4100](https://github.com/tinylabscom/mvm/issues/4100).

Amends ADR-030 decision 4 (both the builder image and every user-facing image
build from `mvm-images`) and ADR-004's account of how mvm's own Linux binaries
reach a guest. Supersedes the consumer half of
`specs/plans/2026-09-29-guest-bins-artifact-decoupling.md`. ADR-018 carries a
dated note that corrects its acquisition text against today's code and points
here for where the overlay and sidecar are going.

This records a decision, not a delivery. The code still follows the old
boundary until the workstreams listed at the end land; "Where the code is
today" below says exactly what runs now. The design detail lives in
`specs/plans/2026-10-05-image-boundary-linux-layer.md`.

## Context

Since the image train moved out of this repository (ADR-030 decision 4,
`specs/plans/2026-09-16-image-repository-extraction.md`), `mvm-images` has
built two different kinds of thing:

1. **The Linux layer**: kernels, the base `default-tenant` and
   `rootless-tenant` root filesystems, the builder VM image, and the Stage 0
   seeds. These change when a kernel, a package or a toolchain moves.
2. **mvm's guest runtime**: the guest agent and its helpers, the universal
   initramfs, the runtime overlay, the glibc and musl SDK sidecars,
   `mvm-setpriv`, and `mkGuest`'s `/init`. `mvm-images` compiles these from
   mvm's source through an `mvm` flake input, so they change whenever mvm's
   guest code does.

The second kind turned every guest change in mvm into an image event, and the
cost was measured:

- The merge queue's guest-image-boot lane built the image pair from an
  `mvm-images` checkout in about 31 minutes, on Rust-only PRs as well
  (merge-group run 36367678633, measured 2026-09-29).
- The release e2e pair-built the SDK sidecar and the dev image, about 22 and
  39 minutes, until the release lane moved to the pinned set on 2026-10-04.
- Fetch-when-unchanged, which adopts a published member only when the tree's
  source fingerprint matches the one the set recorded, was abandoned for the
  release lane after twelve commits touching the fingerprint inputs landed in
  22 hours (2026-10-02T21:37Z to 2026-10-03T20:31Z). A release-window run
  almost never matched.
- `just release` in `mvm-images` could not finish on a Mac: evaluating the
  aarch64 `mvm` override took about five to six hours.

The obvious remedy, moving the guest-facing Nix library across with the
images, was measured too: since June, 38 of the 58 commits to
`nix/lib/mk-guest.nix` also changed mvm's guest or host crates. Moving or
vendoring `mkGuest` would make most guest work a two-repository change, which
is the cost this decision exists to remove.

## Decision

Three repositories, three owners:

| Repository | Owns | Changes when |
|---|---|---|
| `mvm-images` | Kernels; base `default-tenant` and `rootless-tenant` root filesystems that contain no mvm binaries and no mvm-authored `/init`; the builder VM image; the Stage 0 seeds. Nix-built, reproduced, cosign-signed, published as one image set, with SLSA build provenance. | A kernel, package or toolchain moves. Never as a consequence of an mvm merge. |
| `mvm` | `mvmctl` plus one signed guest-runtime release asset, version-locked to the CLI: the guest-bins archive (guest agent and helpers, the initramfs agent, `mvm-setpriv`, `libmvm_host_services.so` for glibc and musl, the GPU shims, the Python SDK tree). `mvmctl` assembles the runtime overlay, the initramfs and the SDK sidecar from it, or from a source build in a checkout, at boot. | Every CLI release. A guest change is a single-repository change. |
| `mvm-packs` | Packs. Each pack's CI builds its image on the pinned base set, rebuilds it to check reproducibility, signs it and attests it; `mvmctl pull` verifies. | Per pack. |

The rules that follow from the table:

1. **`mvm-images` builds only the Linux layer.** It drops the `mvm` flake
   input, and new work there does not add one. A base root filesystem carries
   no mvm binary and no mvm-authored `/init`. Image sets stay Nix-built,
   reproduced and cosign-signed under the `mvm-images` release workflow
   identity, and gain a build-provenance attestation. `mvm-images` is never
   part of mvm's merge queue: no mvm merge waits on an image build.
2. **mvm ships the guest runtime with each CLI release.** The archive is a
   release asset signed under the CLI release workflow identity, listed in the
   signed checksum manifest and covered by the release's build provenance. A
   downloaded `mvmctl` fetches the archive that matches its own version
   through the CLI-train verifier; a source checkout builds the same pieces
   with the pinned cargo-zigbuild toolchain. `mvmctl` assembles the runtime
   overlay (pure-Rust ext4 plus in-process dm-verity), the initramfs (Rust
   newc cpio) and the SDK sidecar from it. The image-set roles
   `RuntimeOverlay`, `SdkSidecar` and `Initramfs` leave the image-set
   contract.
3. **The initramfs agent is the only guest init.** Every boot, dev boots
   included, starts from the universal initramfs; nothing mvm boots runs
   `mkGuest`'s `/init`. `mvm-setpriv` reaches a workload through the runtime
   overlay and the builder through its boot payload, at builder boot ABI 2.
4. **Packs are the image registry.** A workload image that is not one of the
   base images is a pack in `mvm-packs`, built in CI on the base set
   `crates/mvm-core/images.lock` pins, reproduced, signed and attested.
5. **`mkGuest` stays in mvm** as the workload-author library. It is the API a
   workload flake calls, and it co-changes with mvm's crates far more often
   than with anything in `mvm-images` (the 38-of-58 figure above).

`nix/packages/libkrunfw.nix` stays in mvm. It builds the kernel libkrun links
into its own host library for the libkrun backend; it is a host dependency, not
a guest image any image set carries, so rule 1 does not apply to it. Moving it
would make `mvm-images` publish host libraries. Decided by the maintainer on
2026-10-05 (#4015).

## Where the code is today

Text elsewhere in this repository must describe these as current behaviour
and cite #4100 for the direction, never the reverse.

- Every workload backend already boots through the universal initramfs: the
  static agent is PID 1, receives the rootfs and runtime-overlay verity
  parameters in `ActivateEnvironment` over vsock, mounts and checks them,
  mounts the SDK sidecar and volumes, and pivots in-process.
  `mkGuest`'s `/init` still runs for dev boots, for the chained builder boot,
  and for `mvm-images`' own e2e boots.
- A source checkout builds one guest-runtime archive from this tree
  (`mvm_build::guest_runtime::resolve_or_build_source_guest_runtime`), keyed
  by its digest, and assembles all three pieces from it on the host, whether
  or not an `mvm-images` checkout is selected: the runtime overlay with the
  GPU shims and the Python SDK tree
  (`mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime`:
  the pure-Rust ext4 writer and in-process verity), the initramfs from the
  archive's sealed initramfs agent (`mvm_build::initramfs::initramfs_cpio`),
  and the SDK sidecar without a bundled loader or libc
  (`mvm_build::sdk_sidecar::build_sdk_sidecar_from_guest_runtime`). The Wasm
  tier preopens the same overlay files as a directory. A selected checkout
  pair-builds only workload images and kernels.
- In a source checkout every route goes through that one archive and those
  assemblers. Bootstrap resolves the archive once and assembles all four
  pieces from it (`mvm_build::runtime_pieces::assemble_runtime_pieces`); the
  explicit `mvmctl build runtime-overlay build` and
  `mvmctl build sdk-sidecar build` assemble the piece they name from it, with
  no `mvm-images` checkout and no builder VM, and `--source download` installs
  the pinned image set's member instead. Each assembled piece records the
  digest of the archive it came from beside its version-keyed files, and
  `mvmctl doctor`'s `guest runtime` line reports, per piece, that archive (and
  whether it is the one this tree builds today) or the image-set member a
  launch would attach. The archive object is the one digest-keyed cache; the
  pieces keep their version-keyed slots because that is what the launch
  resolvers read, and the sidecar keys reuse on its host-services sources
  rather than the archive digest.
- The builder boot payload (builder boot ABI 1) already hands the builder
  `mvm-host-vm-init` and `mvm-builderd` per boot. `mvm-setpriv` is the one mvm
  binary the builder image still bakes, and `mvm-host-vm-init` runs it from
  `/sbin`.
- Each CLI release builds the guest-bins archive and publishes it as a signed
  asset (#4103): in the cosign sign loop, the signed checksum manifest and
  the build provenance, and `tests/release_assets.rs` still refuses the
  overlay, sidecar and initramfs as image assets of `release.yml`.
  `install.sh` and the deb and rpm packages install it beside `mvmctl`;
  `mvmctl bootstrap` on a release binary and `mvmctl env update` acquire it
  through `mvm_build::runtime_overlay::fetch_cli_release_archive` (digest,
  then signature). Nothing assembles the overlay, initramfs or sidecar from
  it yet (#4104), so a release binary still boots the image set's copies.

## Consequences

### What moves

- The guest-bins archive grows to carry every guest artifact mvm owns,
  including the shared objects, `mvm-setpriv`, the initramfs agent and the
  Python SDK tree (#4102), and ships as a signed CLI release asset (#4103).
- `mvmctl` assembles the overlay, the initramfs and the SDK sidecar from the
  archive or a source build, with one cache keyed by the archive digest
  (#4104). The host-built sidecar is the library alone.
- Everything `mkGuest`'s `/init` still does that the agent does not moves into
  Rust, and the base root filesystem stops carrying an mvm `/init` (#4106).
- `mvm-setpriv` joins the builder boot payload at ABI 2; the builder image
  then bakes no mvm binary, and the builder cache key stops folding the setpriv
  source closure for ABI 2 images (#4107).
- The guest runtime leaves the image-set contract, and fetch-when-unchanged is
  deleted: `MVM_FETCH_UNCHANGED_IMAGES` (including its `pinned` value),
  `mvm_build::fetch_unchanged`, and the members' `source_fingerprint` (#4105).
  The `guest_agent_protocol` range in `images.lock` is replaced by a
  base-image contract version that the base root filesystem declares and
  `mvmctl` checks before boot.
- mvm's CI stops building guest pieces through `mvm-images` (#4108).
- `mvm-images` drops the `mvm` input and every read of mvm's source
  (tinylabscom/mvm-images#49) and attests build provenance for image sets
  (tinylabscom/mvm-images#50). Pack CI moves to the pinned base set
  (tinylabscom/mvm-packs#12).

### Ordering

The order is forced by what shipped CLIs accept.
`ImageSetRequirement::current_train()` requires `runtime_overlay`,
`sdk_sidecar_{glibc,musl}` and `initramfs` on both architectures, and every
acquire of the locked set, every image set embedded in a signed bundle, and
`image boot verify --require-complete` enforce it. Every `mvmctl` released so
far therefore refuses a set without those roles. The mvm release that relaxes
the requirement ships first; `mvm-images` publishes a set without the roles
only after it, and only that release or a later one may pin such a set.
Older CLIs keep pinning their own published sets and are unaffected.

`ImageSetRole` is a closed serde enum. Deleting the three variants makes the
pinned `image-set/v0.2.4` manifest unparseable, so either the variants stay
deserializable until the pin advances past every set that carries them, or
the pin advances in the same change. `IMAGES_CHECKOUT_MARKERS` recognises an
`mvm-images` checkout by its `runtime-overlay` and `initramfs` image
definitions and changes in lockstep with their deletion.
`check_embedded_image_set_for_backend` requires a `RuntimeOverlay` member in
an embedded set; what a `.mvmpkg` that embeds an image set records about the
guest runtime it was tested with is decided in #3928.

### Why `mkGuest` stays

Workload authors call `mkGuest` from their own flakes; it is mvm's API, not an
image definition. The commit history above says it moves with mvm's crates.
What changes is narrower: its `/init` stops being part of any image mvm boots
(#4106), it gains an option to omit its own `mvm-setpriv` copy, which the
builder image sets (#4107), and the workload-author guide is updated with it.

### Superseded

- The guest-bins plan's bump job, which had mvm's release workflow open PRs in
  `mvm-images` to advance a guest-bins pin.
- `mvm-images` consuming the archive through a `guest-bins.nix` recipe, and
  `image-set/v0.3.0` as the first set built on it.
- Vendoring `mkGuest` into `mvm-images` with a fixture test pinning the two
  copies together.
- Fetch-when-unchanged, deleted under #4105.

### What stays the same

- `crates/mvm-core/images.lock` pins one signed image set by root digest and
  exact release-workflow identity. It pins the base set: kernels, base root
  filesystems, the builder image and the Stage 0 seeds.
- Every downloaded byte is still digest-verified, and every signed root or
  release asset is still bound to an exact GitHub Actions workflow identity.
  The guest runtime is authenticated the way the CLI archive is, under the
  CLI release workflow, rather than under the image-set workflow.
- Host Nix is never used (ADR-030 decision 3). The guest runtime was never a
  Nix build on the host and does not become one: it is cargo-zigbuild output
  from the pinned toolchain, the same mechanism ADR-004 uses for the builder
  binaries embedded in `mvmctl`.
- The claim posture is unchanged in substance. The runtime overlay is still
  dm-verity sealed and its root hash still reaches the agent in
  `ActivateEnvironment`; what changes is where the overlay's bytes come from.
  The ADR-001 rows whose witnesses name the image-set path (claims 3, 6
  and 20) are corrected in #4109, which owns the ledger.

### Costs

- Each CLI release carries the guest runtime for both architectures. The
  archive #3976 introduces measured about 11 MB for both architectures with
  ten static executables each, before the shared objects and the Python SDK
  tree join it.
- A fix to the guest agent now needs a CLI release; there is no image-only
  path for it. Kernel and package fixes still ship as image sets without one.
- During the transition the image set and the CLI both carry guest pieces,
  and `mvmctl` keeps reading the image-set roles until #4105 lands.

## Workstreams

In order; items on the same line can run in parallel.

1. [#4101](https://github.com/tinylabscom/mvm/issues/4101): record the
   decision (this ADR, `CLAUDE.md`, `AGENTS.md`, plans).
2. [#4102](https://github.com/tinylabscom/mvm/issues/4102): the guest-bins
   archive carries every guest artifact (builds on #3976).
3. [#4103](https://github.com/tinylabscom/mvm/issues/4103): ship it as a
   signed CLI release asset.
4. [#4104](https://github.com/tinylabscom/mvm/issues/4104): `mvmctl`
   assembles the overlay, initramfs and SDK sidecar from it ·
   [#4106](https://github.com/tinylabscom/mvm/issues/4106): the initramfs
   agent is the only guest init ·
   [#4107](https://github.com/tinylabscom/mvm/issues/4107): builder boot
   ABI 2 carries `mvm-setpriv`.
5. [#4105](https://github.com/tinylabscom/mvm/issues/4105): remove the guest
   runtime from the image-set contract and delete fetch-when-unchanged ·
   [#4108](https://github.com/tinylabscom/mvm/issues/4108): mvm CI stops
   building guest pieces through `mvm-images`.
6. [tinylabscom/mvm-images#49](https://github.com/tinylabscom/mvm-images/issues/49):
   `mvm-images` drops the `mvm` input and builds only the Linux layer ·
   [tinylabscom/mvm-images#50](https://github.com/tinylabscom/mvm-images/issues/50):
   build-provenance attestation for image sets.
7. [#4109](https://github.com/tinylabscom/mvm/issues/4109): claims ledger and
   docs.

In parallel from the start:
[tinylabscom/mvm-packs#12](https://github.com/tinylabscom/mvm-packs/issues/12):
pack CI builds on the pinned base set, reproduces, signs and attests.
