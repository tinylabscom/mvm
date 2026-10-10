---
kind: design
issue: https://github.com/tinylabscom/mvm/issues/4100
status: accepted
---

# Image boundary: mvm-images builds the Linux layer, mvm ships the guest runtime

Backing: preview
Validation: none

The design attachment for [#4100](https://github.com/tinylabscom/mvm/issues/4100).
The decision and its rationale are ADR-054
(`specs/adrs/054-image-boundary-linux-layer.md`); this document holds the
implementation notes the workstream issues need and that would make those
issues unreadable. Status, scope and acceptance belong to the issues. Nothing
here records progress.

It supersedes `specs/plans/2026-09-29-guest-bins-artifact-decoupling.md`,
whose producer half (the guest-bins archive, #3976) carries over and whose
consumer half (`mvm-images` building from the archive) does not.

## Target

After the last workstream:

- `mvm-images` has no `mvm` flake input and reads nothing from mvm's source.
  It publishes kernels, the base `default-tenant` and `rootless-tenant` root
  filesystems (no mvm binary, no mvm `/init`), the builder image (builder
  boot ABI 2, no mvm binary) and the Stage 0 seeds, as one reproduced,
  cosign-signed image set with a build-provenance attestation.
- Each `mvmctl` release carries one guest-runtime archive per release, signed
  under the CLI release workflow and version-locked to the CLI. A downloaded
  `mvmctl` fetches the matching archive; a source checkout builds the same
  members on the host.
- `mvmctl` assembles the runtime overlay, the universal initramfs and the SDK
  sidecar from the archive at boot, into one cache keyed by the archive
  digest, and `mvmctl doctor` names the archive each piece came from.
- Every boot starts from the initramfs agent. `mvm-setpriv` reaches workloads
  through the overlay and the builder through its boot payload.
- mvm's merge queue builds no image. Its boot lanes run the pinned base set
  with a guest runtime built from the tree.
- Packs in `mvm-templates` are built in CI on the pinned base set, reproduced,
  signed and attested, and `mvmctl pull` verifies them.

## Ordering

The sequence is set by what already-shipped CLIs accept, not by convenience.

1. Record the decision (#4101).
2. Complete the archive (#4102), then ship it as a release asset (#4103).
3. Assemble from it (#4104), make the initramfs agent the only init (#4106),
   and move `mvm-setpriv` into the builder boot payload (#4107). These three
   are independent of each other.
4. Relax the image-set contract and delete fetch-when-unchanged (#4105);
   move CI off `mvm-images` for guest pieces (#4108).
5. Only after an mvm release containing #4105 exists: `mvm-images` drops the
   `mvm` input and publishes a set without the guest-runtime roles
   (tinylabscom/mvm-images#49), and attests provenance
   (tinylabscom/mvm-images#50).
6. Correct the claims ledger and docs (#4109).

Pack CI (tinylabscom/mvm-templates#12) depends only on the pinned base set and
runs in parallel throughout.

The hard edge is step 5. `ImageSetRequirement::current_train()` in
`crates/mvm-core/src/image_set/validate.rs` requires the runtime overlay, both
SDK sidecars and the initramfs on both architectures. It is enforced on every
acquire of the locked set (`published_image_set.rs`), on image sets embedded
in signed bundles (`plan/bundle.rs`) and by `image boot verify
--require-complete`. Every `mvmctl` released before #4105 refuses a set that
lacks those roles, so such a set may be pinned only by a release that no
longer requires them. Older CLIs keep pinning their own sets and are not
affected.

## Workstream notes

### #4102: the archive carries every guest artifact

The archive #3976 introduces (`mvmctl build guest-bins`) holds ten static
musl executables per architecture: the nine runtime-overlay executables plus
`mvm-oci-entrypoint`, with a manifest recording each member's sha256, the
workspace version and the guest and cdylib source fingerprints. It is
deterministic (sorted members, zeroed metadata, no gzip timestamp) and
re-verified after writing. It reuses the existing cached guest builds, so on
a warm cache the verb only packages.

What it must gain, all built with the existing cargo-zigbuild path:

- `libmvm_host_services.so` for glibc, targeting
  `<arch>-unknown-linux-gnu.2.34` to match the published library's
  GLIBC_2.34 floor, and for musl, built with `-C target-feature=-crt-static`;
  both architectures. Measured on the pinned toolchain: the glibc build needs
  `libpthread.so.0` and `libc.so.6` (highest symbol version GLIBC_2.34), the
  musl build needs `libc.so`, and neither needs `libgcc_s`.
- The GPU shims `libcuda.so.1`, `libcudart.so` and `libnvidia-ml.so.1`, glibc
  and musl, from one Rust table that the GPU conformance step also reads.
- `mvm-setpriv`, static musl.
- The initramfs agent: static, thin LTO, `panic=abort`, without `addons`.
- The Python SDK tree.

Two corrections ride along. Today one cargo invocation unifies the
`mvm-agentd/addons` feature into the sealed agent; the sealed agent and every
other non-addon binary must build without it. Libraries are checked by kind,
not as executables: ELF class, machine, `ET_DYN`, and a `NEEDED` set that
contains the libc soname and stays inside an explicit allow-list. The
manifest also records the producing commit and whether the tree was dirty.

### #4103: a signed CLI release asset

`release.yml` builds the archive for each release and treats it like the CLI
tarballs: the cosign sign loop, the `assets=(...)` list with its bundle, the
signed checksum manifest, and build provenance. The pins that move with it:

- `nix/packaging/release/verify-release-assets.sh`, its test script, and
  `tests/release_assets.rs`. Its test that the CLI release carries no image
  keeps refusing the overlay, sidecar and initramfs as image assets and
  admits the archive by name.
- `install.sh`, self-update and the deb and rpm packages (#4047) install or
  fetch the matching archive. Self-update replaces the CLI and the guest
  runtime together.
- A downloaded `mvmctl` fetches the archive through
  `mvm_build::runtime_overlay::fetch_cli_release_archive`, which already
  checks the digest and then the signature and has no production caller yet;
  `install_runtime_overlay_archive` is its installer.
- The pre-publish archive smoke (#4046) boots the unpublished guest runtime,
  so the CLI and guest pairing is exercised before anything is published.
- ADR-001 rows 6 and 20 and `model/claims.toml` MVM-SEC-06 and MVM-SEC-20
  follow any witness that is renamed or re-pointed; #4109 owns those edits.
- `tests/nix_flake_structure.rs`'s check that image fetches do not derive
  their release URL from the CLI version excludes `runtime_overlay.rs` and
  `sdk_sidecar.rs`. Under this design that exclusion becomes the intended
  model rather than an exception.

### #4104: mvmctl assembles the guest runtime

- **Runtime overlay.** The host build (then from loose cargo-zigbuild
  binaries; now `build_runtime_overlay_from_guest_runtime`: the pure-Rust ext4
  writer, in-process verity) gains the GPU shims under
  `gpu/{glibc,musl}` and the Python SDK tree, so its contents match what the
  image set publishes today.
- **Initramfs.** Built from the archive's initramfs agent with the existing
  Rust newc cpio writer.
- **SDK sidecar.** A new host build path: the archive's library, packed with
  the pure-Rust ext4 writer. The bundled loader and `libc.so.6` the published
  sidecar carries are dropped. The workload process that loads the library
  already has a loader and a libc of its own, so they are never used.
- **Cache.** One cache keyed by the archive digest for all three pieces.
- **`mvmctl run --image` outside a source checkout** gets its guest runtime
  from the archive. Today it refuses when nothing is cached.

### #4106: the initramfs agent is the only guest init

A read of the boot path (code, not a live run) found that every workload
backend already boots through the universal initramfs. Firecracker, libkrun,
HVF, QEMU and `apple-container` attach it; the static agent is PID 1, takes
activation over vsock, mounts and verity-checks the root and the overlay,
mounts volumes and the SDK sidecar, pivots in-process and drops to uid 901.
Already in Rust: pseudo-filesystems, cgroup2 delegation, devpts, workload
identity, hostname, verb grant, host-signer anchor, FlowMux identity, egress
CA bundle, netinit, the egress client, the overlay and sidecar mounts,
mediated `ping`, the CRNG reseed helper, orphan reaping and the clock seed.

What only the shell `/init` still does is this workstream's real scope:

- the config and secrets drives (`/dev/vdb`, `/dev/vdc`);
- `mvm.chain_init`, the builder's chain into `mvm-host-vm-init`, which moves
  with #4107;
- the addon-DNS fork, which has no Rust launcher;
- the egress client as uid 989 with `net_bind_service`;
- the `MVM_RUNTIME_OVERLAY`, `PYTHONPATH` and `NODE_PATH` exports;
- per-service seccomp-apply wiring (`mkServiceBlock`);
- autostarting the entrypoint, capturing its exit, running exit-report and
  powering off. On the universal path the host drives this through
  `RunEntrypoint`; the open question is whether anything besides dev boots
  and `mvm-images`' own e2e boots still needs the autostart;
- `mvm.secret_env`, which the runner still emits but no agent code reads,
  because the universal path delivers the environment per `RunEntrypoint`.
  The emitter can be deleted.

The identity files need a choice: either the agent provisions `/etc/passwd`
and `/etc/group` read-only at boot, which claim 2 relies on, or the base root
filesystem keeps a fixed, documented set. The uid layout is unified either
way; today the initramfs path uses 901 and `mkGuest` uses 990 and 1000.
`mkGuest` and the workload-author flakes guide are updated in the same work.

Possible defects found during that read, each to be confirmed before it is
fixed:

1. On the Rust path the egress client appears to run as uid 0: PID 1 spawns
   it before the privilege drop, while `mkGuest` runs it as 989 under
   `mvm-setpriv`. The uid-switching spawn helper exists and has no caller.
2. `apple-container` gets no runtime overlay, because the overlay attach
   matches only firecracker, hvf, qemu and libkrun, while the overlay-contract
   gate still runs, so a vsock-egress boot there would fail activation.
3. The cached-workload-kernel lookup returns nothing for libkrun, which maps
   to the bundled kernel, which the libkrun driver refuses; an OCI launch on
   libkrun through `mvm-client` may therefore have no kernel.
4. Detached runs report exit through a hard-coded
   `/usr/local/bin/mvm-exit-report`; OCI injection does not ship it and the
   overlay's copy lives at `/mvm/runtime/exit-report`.

### #4107: builder boot ABI 2

- `HostBinary` gains a `package` field (`parse_embedded_manifest` assumes
  `mvm-build` today), and `mvm-setpriv` joins the payload table. The Nix
  mirror and `check-mvm-host-binaries-sync` follow.
- `mvm-host-vm-init` resolves `mvm-setpriv` through `guest_host_binary`
  instead of the literal `/sbin/mvm-setpriv`, so ABI 0 and ABI 1 images keep
  booting.
- `BuilderBootAbi` 2, the supported range, ADR-004, and every test that pins
  the range move together.
- The builder cache key stops folding the `mvm-setpriv` source closure for
  ABI 2 images.
- `mkGuest` gains an option to omit its own `mvm-setpriv`; the builder image
  in `mvm-images` sets it and declares ABI 2.

### #4105: the image-set contract

- `ImageSetRole::{RuntimeOverlay, SdkSidecar, Initramfs}` leave the schema,
  the completeness checks, `PublishedImageSet` acquisition,
  `image boot verify --require-complete`, the pair-build contracts and
  `bin/dev build image-set`.
- `ImageSetRole` is a closed serde enum, so deleting the variants makes the
  pinned `image-set/v0.2.4` manifest unparseable. Either keep them
  deserializable until the pin has advanced past every set that carries them,
  or advance the pin in the same change.
- `IMAGES_CHECKOUT_MARKERS` in `crates/mvm-build/src/image_source.rs`
  recognises an `mvm-images` checkout by `images/runtime-overlay/image.nix`
  and `images/initramfs/image.nix`. It changes in lockstep with their
  deletion, as do the `EMITTED` fixture in
  `crates/mvm-core/src/image_set/tests/local.rs` and `mvm-images`'
  `emit-local-manifest.py`.
- `check_embedded_image_set_for_backend` in `plan/bundle.rs` requires a
  `RuntimeOverlay` member in an embedded set. What a bundle records about the
  guest runtime it was tested with is decided in #3928.
- Fetch-when-unchanged is deleted: `MVM_FETCH_UNCHANGED_IMAGES` including its
  `pinned` value, `mvm_build::fetch_unchanged`, the `image dev ensure` fetch
  arm, `boot_pinned_images` in `e2e-docs.yml`, and the members'
  `source_fingerprint`.
- `images.lock`'s `[compatibility] guest_agent_protocol` is replaced by a
  base-image contract version that the base root filesystem declares and
  `mvmctl` checks before boot. The guest-agent protocol becomes a property of
  the CLI and its own guest runtime, which ship together.
- The re-measure in `specs/plans/2026-09-27-release-e2e-under-image-target.md`
  is retargeted to this arrangement.

### #4108: CI stops building guest pieces through mvm-images

More lanes take the guest runtime from `mvm-images` than the issue body first
listed:

- The `guest-image-boot` lane boots the pinned base set with a tree-built
  guest runtime instead of building `runtime-overlay` from an `mvm-images`
  checkout. It is already dispatch-only and outside the required aggregate,
  so `release.yml`'s comment that the merge queue boots guest-source changes
  through it is wrong today.
- `boot-latency`, which the merge queue requires, fetches
  `runtime-overlay-x86_64.tar.gz` from the locked set beside the default
  image.
- `security.yml`'s `verified-boot-artifacts` (the claim-3 CI witness) and
  `sealed-prod-no-ssh` fetch and cosign-verify the set's overlay member;
  `xtask check-workflow-paths` pins that.
- `e2e-docs.yml` checks out `mvm-images` for the source-matched SDK sidecar,
  and `scripts/e2e-documented-surface.sh` and
  `scripts/e2e-source-bootstrap.sh` require it.
- `image-pair.yml` runs `mvm-images`' `check-source-drift.sh` and goes when
  that script does.
- Extended CI's source-bootstrap lane and the documented-surface pair arm
  stop pair-building the overlay, sidecar and dev image.

The merge-group wall is measured before and after over at least ten runs.

### #4109: claims ledger and docs

- Claim 3: the runtime overlay's verity root hash comes from the CLI-assembled
  overlay, not from the signed image set.
- Claim 6: `fetch_expected_hashes`, `verify_manifest_signature` and
  `verify_artifact_hash` are test-only; production acquires images through
  `acquire_image_set()`. The claim-20 witness that refuses an unsigned
  manifest before parsing therefore exercises test-only code. Both are
  re-pointed at the production path.
- Claim 20 covers the guest-runtime asset. Self-update verifies each tarball's
  own bundle but not the checksum manifest's.
- `CLAUDE.md` says `MVM_BOOT_IMAGE=fetch` fetches the published boot image
  even with a checkout selected; `default_microvm.rs` refuses it for the
  default workload image.
- The public docs (`architecture/boot-flow.md` and the pages that describe
  image-set roles) move here or with the workstream that changes them.

### mvm-images and mvm-templates

`mvm-images`#49 deletes the `runtime-overlay`, `initramfs` and SDK sidecar
roles and outputs, `sources/` and `SOURCES.md`, `check-source-drift.sh`,
`check-local-mvm-override.sh`, `just with-mvm`, the pin-advance procedure and
the sidecar fingerprint port in `assemble-release.py`. Base root filesystems
are composed there without `mkGuest`'s `/init`, mvm binaries or mvm's
workspace filter. Boot witnesses use a small test init in place of the
runtime overlay and still invoke the VMM directly. Every other read of mvm's
source is replaced, including the kernel size budget read from mvm's
`xtask`, the shebang and kernel-format assertion scripts, the guest-agent
protocol range read from mvm's agent source, and building `mvmctl` from the
pinned source to run `image boot verify --require-complete` (a released
`mvmctl` replaces it). The QEMU/WebAssembly smoke pack imports mvm's
`crates-io.nix` today and needs its own decision.

`mvm-images`#50 attests build provenance for every published member and the
`image-set.json` root under the release workflow identity. Verifying it in
`PublishedImageSet` is an optional follow-up in mvm.

`mvm-templates`#12 builds each pack's image on the base set `images.lock`
pins (tag and digest) rather than on an mvm source revision, rebuilds it and
refuses to publish on any byte difference, signs the image and the pack
descriptor, attests provenance, and records the image digest, the
attestation and the base-set pin in the descriptor. `mvmctl pull` verifies
the attestation and refuses a pack whose base set its own lock does not
accept. A rule for published packs when mvm's lock moves to a new base set is
part of that issue.

## Open questions

- `nix/packages/libkrunfw.nix` builds a kernel inside mvm (#4060). It is a
  host library for the libkrun backend, not a guest image; the proposal is to
  exempt it, which needs an owner decision.
- A `.mvmpkg` that embeds an image set (#3928) will no longer carry the guest
  runtime. Whether it records the guest-runtime version it was tested with is
  decided there.
