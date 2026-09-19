# Extract the image release train into `mvm-images`

Backing: preview
Validation: none — this plan describes a repository migration that has not
started. Each workstream names the tests and live evidence required before its
checkbox may be completed.

**Issues:** [#3363](https://github.com/tinylabscom/mvm/issues/3363) (W1) ·
[#3367](https://github.com/tinylabscom/mvm/issues/3367) (W2) ·
[#3365](https://github.com/tinylabscom/mvm/issues/3365) (W3) ·
[#3362](https://github.com/tinylabscom/mvm/issues/3362) (W4) ·
[#3364](https://github.com/tinylabscom/mvm/issues/3364) (W5) ·
[#3369](https://github.com/tinylabscom/mvm/issues/3369) (W6) ·
[#3368](https://github.com/tinylabscom/mvm/issues/3368) (W7) ·
[#3366](https://github.com/tinylabscom/mvm/issues/3366) (W8) ·
[#3373](https://github.com/tinylabscom/mvm/issues/3373) (optional W9)

## Outcome

Create one public `tinylabscom/mvm-images` repository that owns the build,
verification, signing, publication, and lifecycle of MVM's system-image train:

- builder VM kernel and rootfs;
- default workload kernel and verity-sealed rootfs;
- universal runtime overlay;
- SDK sidecars;
- Stage 0 seed inputs; and
- the QEMU/WebAssembly smoke pack currently published with boot images.

The `mvm` repository consumes an immutable, signed image-set manifest pinned by
digest. Runtime and release CI fetch the pinned set by default. Source builds
remain available as an explicit development and reproducibility path, including
a first-class sibling-checkout workflow for changing `mvm` and `mvm-images`
together.

This is a repository and release-boundary change, not permission to weaken the
existing artifact controls. Every downloaded byte remains digest-verified,
signed manifests remain bound to an exact GitHub Actions identity, revocation
remains fail-closed where it is fail-closed today, and production never
auto-discovers or silently admits an unsigned sibling checkout.

## Why now

The image train already has an independent `boot-image/vN` counter, but its
workflow and sources live in `mvm`. A CLI release then downloads those assets,
re-signs part of them under the CLI release identity, and uploads duplicate
bytes to the CLI release. The runtime also carries repository-specific URLs,
workflow identities, revocation locations, and a Stage 0 kernel pin.

This half-separation creates two costs:

1. `mvm` CI and release gates repeatedly pay for image preparation even when
   the image inputs did not change.
2. The product and image release trains are logically independent but remain
   operationally and cryptographically entangled.

The measured Linux documented-surface run on 2026-09-15 spent approximately:

| Work | Wall time |
|---|---:|
| Build the two test binaries and SDK prerequisites | 10 minutes |
| Prepare source-derived builder/image artifacts | 37 minutes |
| Execute 313 live scenarios | 67 minutes |

The first workstream removes the avoidable image preparation from the release
critical path. The repository extraction makes that fast path the normal,
maintainable contract instead of a CI-only override. Scenario sharding is a
separate optimization because even a zero-cost image fetch leaves roughly an
hour of live behavior to execute.

## What gets lighter, and what does not

The immediate measurable win is release and Extended CI: unchanged image inputs
stop paying the roughly 37-minute source-derived preparation cost. Ordinary PRs
also become faster and less failure-prone as image-only workflows, Nix
evaluation, and publication checks move behind path-scoped contracts in
`mvm-images`. The merge-queue improvement will initially be smaller because
some image jobs are already path-scoped; W8 must measure it rather than infer it.

The `mvm` project becomes lighter in ownership and maintenance surface: fewer
image sources and lock files, fewer publisher permissions, less duplicated
release machinery, and fewer image-only changes in host-runtime PRs. Do not
promise a dramatic clone-size or installed-binary reduction. Large published
bytes already live primarily in release assets, and runtime consumers still
download the packs they need. The main benefit is a narrower repository and
release boundary, not moving bytes for its own sake.

## Supported hosts and backends

Image metadata describes the guest artifact, not the developer's host OS. Pack
selection is based on guest architecture, boot protocol, artifact format, and
required device/capability features. Host backends then declare which of those
contracts they can satisfy.

| Host/backend | Initial support | Contract |
|---|---|---|
| Linux / Firecracker | required | x86_64 and aarch64 Linux guest packs with KVM/Firecracker boot evidence |
| macOS / HVF | required | aarch64 Linux guest packs with physical Apple Silicon HVF boot evidence |
| Windows / future backend | schema-ready, not yet shipped | may consume a compatible Linux guest pack once a Windows backend and native Windows witness exist |

This avoids separate “macOS images” when Firecracker and HVF can boot the same
compatible Linux guest bytes. It also avoids claiming Windows support before a
backend exists. A future Windows-specific artifact role or format can be added
by a schema version without changing repository ownership or weakening
compatibility checks.

## Boundary: one image repository, not one repository per image

Use one `mvm-images` repository initially. The artifacts share:

- the same guest/host protocol and source revision;
- kernel and Nix inputs;
- runtime-overlay and SDK-sidecar compatibility;
- signing, SBOM, revocation, and completeness policies; and
- one release-set atomicity requirement.

Splitting the builder VM and workload boot image into separate repositories
would create cross-repository partial-release states without giving them an
independent team or lifecycle. Revisit that only when the artifacts genuinely
have separate owners and compatibility contracts.

## Target ownership

### `mvm-images` owns

- `nix/images/builder-vm/` — the builder kernel and rootfs, `stage0-rootfs`,
  the kernel attributes, and the SDK sidecar re-export;
- `nix/images/default-tenant/`;
- `nix/images/runtime-overlay/` — the overlay **and** the glibc and musl SDK
  sidecars (there is no separate `nix/images/sdk-sidecar/`);
- `nix/images/initramfs/`, which `release.yml` publishes on the CLI train today;
- `nix/images/kernel/` (base, builder and workload configs, flake, README),
  `scripts/build-kernel-artifacts.sh`, the kernel config budget, and kernel
  publication, which `kernel-build.yml` uploads to the CLI release today;
- the QEMU/WebAssembly smoke pack: `nix/packages/qemu-wasm.nix`,
  `qemu-wasm-smoke-image.nix`, `qemu-wasm-smoke-pack.nix`,
  `emscripten-cross.meson`, `scripts/build-qemu-wasm-smoke-pack.sh`, and the
  `scripts/run-qemu-wasm-*.py` and `serve-qemu-wasm-smoke-pack.py` harnesses;
- `nix/packaging/release/assert-sidecar-coherent.sh`;
- the image-only CI lanes: builder and pack reproducibility, verified-boot
  artifacts, cache warming, and the kernel CVE watch;
- image assembly, boot tests, SBOM generation, signing, and publication;
- the immutable image-set manifest and revocation documents; and
- reproducibility instructions for every published artifact.

The guest and builder binaries inside the images are **not** moved. They are
compiled from `mvm` source against `mvm`'s `Cargo.lock`, so their recipes stay
beside that lockfile and the tests that pin them. `mvm-images` consumes them
from an `mvm` flake input pinned to an exact commit: `mvm.packages.<system>.*`
for the guest recipes, `mvm.lib.<system>.mkGuest` for the guest assembly, and a
`cargo zigbuild` of `mvm-host-vm-init`, `mvm-egress-proxy` and `mvm-builderd`
from a checkout of the same commit. Nothing is copied from `mvm` into
`mvm-images`.

### `mvm` continues to own

- host CLI/runtime source and guest-agent source;
- the Nix recipes that compile that source for a guest
  (`nix/packages/mvm-guest-agent*.nix`, `mvm-setpriv.nix`,
  `mvm-egress-client.nix`, `mvm-addon-dns.nix`, `mvm-exit-report.nix`,
  `mvm-sdk-cdylib.nix`, `workspace-unpack.nix`, `embedded-rust-toolchain.nix`)
  and the helpers they share with host packages (`nix/lib/workspace-filter.nix`,
  `static-crates-cargo-deps.nix`, `crates-io.nix`, `mvm-host-binaries.nix`),
  exported as flake outputs;
- the user-facing flake API (`nix/lib/default.nix`, `mk-guest.nix`,
  `mkFunctionWorkload.nix`, `factories/`, `wrappers/`, `profiles/`);
- artifact acquisition, verification, cache, and admission code;
- the guest/host protocol and compatibility declarations;
- the compiled default image-set pin;
- live boot and cross-version compatibility tests;
- the code that boots a builder: Stage 0 orchestration in `mvm-build`, the
  builder runner in `mvm-runtime`, and the VMM drivers both use; and
- explicit source-build integration used by contributors.

Stage 0's *seed inputs* move; the code that runs Stage 0 does not. Fixes to how
a builder boots, stops, or reclaims its store (#3360) therefore land in `mvm`.

`mvm-images` may check out an exact public `mvm` commit to cross-compile guest
and builder binaries. It records that commit in the image-set manifest. It must
not track `mvm/main` implicitly during a release build.

## Image-set contract

One release publishes one atomic image set. The manifest is the root object;
individual assets are never selected by asking GitHub for “latest”.

The versioned schema contains at least:

- schema version and image-set version;
- producing repository, workflow identity, tag, and source commit;
- exact `mvm` source commit used for embedded guest/builder binaries;
- supported architectures and artifact roles;
- content digest and size for every artifact;
- guest/host protocol version and explicit host compatibility range;
- Nix lock digest and relevant upstream source pins;
- SBOM digest/URI per pack;
- revocation channel; and
- optional deprecation/supersession metadata that cannot redirect an existing
  immutable version.

`mvm` pins the image set in a small checked-in lock file rather than scattering
the tag and repository through Rust constants and workflows. The lock contains
the repository, immutable release tag, manifest digest, and expected signing
identity. Generated Rust/build metadata may derive from it, but there is one
source of truth.

## Trust invariants

1. Production and release channels accept only immutable, digest-pinned image
   sets whose manifest verifies under an allow-listed `mvm-images` workflow
   identity.
2. A checksum without a verified manifest is not a production fallback.
3. Repository name, workflow path, tag namespace, certificate identity, and
   manifest digest are all checked; changing hosting is a trust-root migration.
4. Revocation is scoped to the image identity and remains independently
   retrievable. A network failure cannot turn a known revocation into success.
5. A partial architecture or artifact set cannot publish.
6. The manifest's compatibility declaration is checked before boot, not after a
   guest fails its handshake.
7. Release workflows never consume a mutable branch, “latest” release, or an
   automatically discovered local checkout.
8. Existing CLI releases remain able to fetch their original image locations
   throughout the compatibility window.

## Local sibling-repository development

Yes: paired local development is a required workflow, not an escape hatch.

Recommended checkout layout:

```text
mvmco/
  mvm/
  mvm-images/
  .worktrees/
    mvm-<change>/
    mvm-images-<change>/
```

The integration is explicit:

```text
released source  -> signed remote manifest -> verified artifact cache
local source     -> sibling build output   -> dev-identified artifact cache
                                             |
                                             v
                                  one resolver and boot path
```

Provide a checked-in wrapper, tentatively:

```bash
MVM_IMAGES_DIR=../mvm-images bin/dev image build builder-vm
MVM_IMAGES_DIR=../mvm-images bin/dev machine run ...
```

The final spelling may be a config/CLI value rather than an environment
variable, but it must have these semantics:

- the path is explicit and canonicalized; no sibling auto-discovery;
- the image repository commit and dirty state are recorded in the local
  manifest and cache identity;
- local output is content-addressed and uses the same schema/parser as released
  output;
- unsigned local manifests are accepted only by source/development builds and
  are visibly reported as `local-dev`, never `verified-release`;
- release-channel binaries and production admission reject local sources even
  when the path variable/config is present;
- a signed release can still be forced during development for comparison;
- paired-change CI can check out both repositories at explicit SHAs; and
- one command prints the two commits, dirty states, artifact digests, and trust
  tier so a bug report is reproducible.

Do not use a Git submodule. A submodule would make routine source checkout and
contribution depend on the image repository while still failing to express the
local dirty state or the signed release identity. The lock-file plus explicit
sibling override keeps release and development concerns separate.

## Development-complexity budget

The migration adds real release-engineering complexity: two protected
repositories, a trust-root transition, cross-repository compatibility, and pin
updates. It must not make normal host-runtime work a two-repository workflow.
Contributors who do not change images continue to clone and work only in
`mvm`; released packs are fetched from the checked-in lock.

Image development requires paired checkouts, but the supported path remains one
wrapper command that builds the selected local role and runs it through the
normal resolver. It must not require copying artifacts, editing global config,
publishing a test release, or manually coordinating cache directories. If the
two-repository example cannot be completed from a clean checkout using the
documented wrapper, W5 is not complete.

## Worktree isolation and known overlap

The split reduces git index/object contention because each repository has its
own git store. It does not remove shared mutable runtime resources. Every paired
worktree command must scope `MVM_HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, image
staging directories, VM/TAP/socket names, and mutable Stage 0 state to the
worktree pair. Immutable, content-addressed outputs may be shared only after an
atomic publish into the cache.

Two worktrees overlapped this migration when it was planned; both are resolved:

- `mvm-m1-e2e-docs-sidecar` was deleted unmerged. W1 supersedes it, and its
  diff is archived on #3374, which tracks the part W1's workflow changes do not
  fix.
- `mvm-fc-builder-image` landed as #3376 (Firecracker builder image, and a
  builder guest that halts instead of powering off). It changed host-side
  builder code, which stays in `mvm`, so W4 has nothing of it to move.

Do not begin destructive path moves while a source area W4 touches has
unintegrated changes. In steady state, independent paired worktrees should
collide less than they do in the monorepository, provided mutable state remains
pair-scoped.

## Migration workstreams

Each workstream gets one GitHub issue and normally one or more small PRs. No PR
may combine the trust-root switch with deletion of the old producer.

### W1 — Remove source image preparation from release E2E (#3363)

- [x] Set the Linux documented-surface release lane to fetch the currently
      pinned signed builder image, matching the live macOS lane.
- [x] Move the source/Stage-0 bootstrap witness into a focused trusted nightly
      job instead of running it before all 313 release scenarios.
- [x] Retain a live flake build through the fetched builder so the release gate
      still exercises user-visible build behavior.
- [x] Record phase timings in the suite output.
- [x] Compare two post-merge runs against the 2026-09-15 baseline (10 minutes
      of build, 37 minutes of source image preparation, 67 minutes of
      scenarios; 118-minute job) and record the result on #3363.

**Measured, and the 25-minute hypothesis is rejected as stated.** The Linux
documented-surface job, all 313 scenarios passing in each run:

| | baseline 2026-09-15 | 2026-09-17 | 2026-09-18 nightly |
|---|---:|---:|---:|
| job wall clock | 118 min | 92 min | 106 min |
| build | ~10 min | 8.8 min | 10.4 min |
| builder image | (in preparation) | 6.6 min | 7.7 min |
| SDK sidecar | (in preparation) | 23.4 min | 26.5 min |
| image preparation total | 37 min | 30.0 min | 34.2 min |
| scenarios | 67 min | 50.2 min | 57.8 min |

The saving is 26 and 12 minutes, so one of the two runs misses the 25-minute
bar. Fetching the builder image did what it was meant to: preparation that was
a from-source Stage 0 is now a 7-minute verified download. What remains is the
source-matched SDK sidecar, which the baseline had already been paying inside
the same 37 minutes and which is now the single largest preparation cost.

The larger effect is not in the table: on 2026-09-16 this lane twice spent its
entire 180-minute budget on a Stage 0 that hung, and was cancelled before the
suite ran. Release evidence went from unobtainable to obtained.

Next lever, deliberately not taken here: acquire the published signed SDK
sidecar when its source fingerprint matches the tree. That changes what the
release gate covers — a released CLI consumes the published sidecar, so it is
arguably closer to the shipped artifact — and it is a decision of its own
rather than a speedup to fold in.

Delivered so far: `specs/sprint/delivery/3363-release-e2e-fetches-the-builder-image.md`.
The published-image fetch now stages and swaps atomically, refuses a foreign
architecture or a manifest that disagrees with the signed pins, and records its
provenance. Revocation is deferred to W3: boot images have no published
revocation channel yet, so a fail-closed check would refuse every fetch.

Acceptance:

- the release lane verifies the signed manifest and fails closed on a wrong
  digest, signing identity, architecture, or missing asset;
- the source-bootstrap job covers a cold source path independently;
- no existing live scenario is removed or newly tolerated; and
- two green runs show the release critical path improved by at least 25 minutes
  or the result is recorded and the hypothesis rejected.

### W2 — Bootstrap and govern `tinylabscom/mvm-images` (#3367)

- [ ] Create the public repository with ownership, branch protection, release
      environments, CODEOWNERS, security policy, dependency update policy, and
      least-privilege Actions permissions.
- [ ] Document artifact roles, supported architectures, release cadence,
      retention, incident response, and the no-secrets/no-customer-data rule.
- [ ] Pin every third-party action by immutable commit where the current image
      producer does so.
- [ ] Add a no-publish dry run and a protected tag namespace for image releases.

Acceptance: an empty/synthetic release cannot publish an incomplete set, and an
untrusted branch cannot mint the allow-listed release identity.

### W3 — Define the manifest, lock, and compatibility contract (#3365)

- [x] Add a versioned image-set manifest schema and round-trip/negative tests.
- [x] Model guest architecture, boot protocol, artifact format, and required
      capabilities independently of the host OS so Firecracker, HVF, and future
      Windows backends can select compatible packs without host-named images.
- [x] Add `mvm`'s single checked-in image lock and generate consumers from it.
      It pins the trains that exist today; the image-set digest joins it when
      the first set is published (W6).
- [ ] Define guest/host protocol compatibility and refuse incompatible sets
      before boot. Defined and negatively tested, and `verify_image_set`
      refuses a non-overlapping range when given the host's; no acquisition
      path consumes an image set yet, so the before-boot refusal is wired in W6.
- [x] Include source commits, Nix inputs, SBOM references, sizes, and digests.
- [x] Add offline verification tooling that needs only the manifest, bundle,
      and artifacts (plus the lock that pins them): `mvmctl image boot verify`.

Acceptance: tampering, wrong repository/workflow identity, wrong architecture,
partial sets, incompatible protocol ranges, replayed superseded metadata, and
revoked packs all have negative tests.

Design constraints found while scoping (inventory taken 2026-09-17):

- **Reuse the pack model; do not add a third manifest.** `mvm_core::packs::PackManifest`
  is already strict (`deny_unknown_fields`), arch-typed, content-hashed, signed
  (ed25519 or keyless) and carries inputs, SBOM references and trust metadata.
  `crypto::image_verify::SignedManifest` and its `RevocationList` were a second,
  string-typed model whose only caller was an example binary — which
  `pack-signing-smoke.yml` ran, so it was a live witness rather than dead code
  (retired in W3d). The image set is a
  signed index over member packs — each member names its role, guest
  architecture, boot protocol and `pack_hash` — and the unused model is removed
  rather than kept beside it.
- **Guest contract, not host.** Selection keys are guest architecture, boot
  protocol, artifact format and required capabilities. Backends declare what
  they satisfy; no member is named after a host OS, and no Windows variant is
  added until a backend and native witness exist.
- **Compatibility before boot.** Today the guest-agent protocol range is checked
  only at the vsock handshake, after boot, and the builder image is gated only
  by an exact `cache_contract_version`. The set declares its protocol ranges and
  the host refuses a non-overlapping set before acquisition.
- **One lock, generated consumers.** The boot-image tag is hand-kept in at least
  eight places (the Rust default, a second copy in the Stage 0 kernel pin, CI
  workflows, tests, and a Nix `getEnv`), and two workflows plus a script select
  the QEMU-wasm smoke pack by "latest", which trust invariant 7 forbids. The
  existing checked-in value → `build.rs` → compile-time constant path
  (`[workspace.metadata.mvm.toolchain]`) and `xtask release-boot-image tag`
  are the mechanisms to extend.
- **Revocation channel is not live.** No runtime path fetches a revocation list
  and the `revocations` release has never been published, so the revocation
  check is built and negatively tested here but enabling it on the fetch path is
  gated on W6 publishing a signed list.

Delivery slices, one PR each:

- [x] W3a — image-set manifest and lock types, pure validation (completeness,
      architecture, boot protocol, capabilities, protocol range, supersession),
      round-trip and negative tests. `mvm_core::image_set`; semver parsing
      consolidated into `mvm_core::release_version`, shared with the updater.
- [x] W3b — offline verification of a signed set against the lock identity and
      digest, member pack and artifact digests, and revocation.
      `mvm_core::image_set::verify_image_set`; the "try each accepted identity"
      loop the packs and revocation paths had each hand-rolled is now one
      function.
- [x] W3c — the checked-in lock, generated tag/identity/Stage 0 pins, an xtask
      gate over workflow and script copies, and removal of "latest" selection.
      `crates/mvm-core/images.lock` pins what exists today: the repository, the
      boot-image tag, and the Stage 0 kernel tag and per-arch digests. It
      carries no `manifest_sha256`, because no image set has been published;
      `ImageLock` joins the file when one is. The signing identity is derived
      from the locked tag rather than pinned separately.
- [x] W3d — an offline verifier command over manifest, bundle and artifacts,
      and with it the retirement of `image_verify::SignedManifest` /
      `RevocationList`. That family looked dead, but
      `.github/workflows/pack-signing-smoke.yml` runs the
      `verify-signed-manifest` example against a real cosign bundle as a live
      witness, so retiring it means moving that lane onto the new verifier
      rather than deleting an unused type. Landed as `mvmctl image boot
      verify`; the smoke lane signs a real image set and runs it, fully on a
      release-tag push and as a signature-stage refusal nightly, because a lock
      cannot name the branch identity a nightly run signs under.

### W4 — Move image sources and reproduce current bytes (#3362)

- [x] Inventory the exact image-owned paths and shared helper edges.
- [ ] Move image flakes, locks, assembly scripts, and image-specific tests to
      `mvm-images` without copying product runtime source.
- [ ] Build guest/builder binaries from an explicit `mvm` source commit.
- [ ] Compare the new repository's outputs with the existing release for file
      set, boot behavior, manifest semantics, and explained byte differences.
- [ ] Preserve both x86_64 and aarch64 builds and live boot evidence.

Acceptance: both architecture sets build, verify, and boot; every unexplained
byte or closure difference blocks publication.

Inventory taken 2026-09-18 against `main` at `713bf1c172`. The ownership lists
above are its result; what follows is what shapes the order of work.

- **The image flakes import `mvm` by path, not by flake input.** Every one
  resolves `workspaceRoot` (`../../..`, or `$MVM_WORKSPACE_PATH`) and imports
  `nix/lib` and `nix/packages` files from it. Moving a flake means rewriting
  each of those imports onto a pinned `mvm` input. `nix/flake.nix` does not
  export the guest recipes today — its `packages` are `mvmctl`, the tpm2
  variants, libkrun and the QEMU-wasm outputs — so `mvm` has to export them
  before anything can move.
- **Three builder binaries are built outside Nix.** `release-boot-image.yml`
  runs `cargo zigbuild` for `mvm-host-vm-init`, `mvm-egress-proxy` and
  `mvm-builderd`, and the builder-vm flake reads them from `MVM_HOST_BIN_DIR`
  under `--impure`.
- **Two published image assets are not on the boot-image train.** The
  initramfs is built by `release.yml`, and kernels are published by
  `kernel-build.yml` into the CLI release. Both join the image set.
- **Changing `mvmSrc` from a filtered path to a flake-input store path changes
  derivation inputs.** Whether that reaches the output bytes is the question
  the comparison below answers; it is not assumed.
- **The builder-vm flake is also a "source checkout" marker for things that
  are not images**, such as the libkrun supervisor auto-build
  (`libkrun_builder.rs`). Removing the flake before W5 would quietly turn a
  contributor build into an installed build.
- **The builder cache fingerprint misses inputs today.** It does not hash the
  kernel configs, the runtime-overlay flake or the setpriv recipe the
  builder-vm flake imports. That is a current bug (#3447), fixed in `mvm`
  independently of this migration.
- `xtask build-dev-image` targets `nix/images/builder`, which does not exist.
  It is removed rather than moved.

Rust code that builds from `nix/images/*` in a source checkout, all of which W5
must route through the explicit sibling selector before W8 deletes anything:
`find_builder_vm_flake` / `builder_vm_is_source_checkout` and their callers
(bootstrap, default microVM, kernel acquisition, doctor, `image boot update`,
`up`), the `MVM_BOOT_IMAGE=build|fetch` resolver, the builder source
fingerprint in `stage0_cache.rs`, the hard-coded flake references in
`stage0-init.rs`, the kernel and image attribute-name contract,
`default_microvm.rs`'s default-tenant reference, both SDK sidecar build paths,
runtime-overlay checkout detection (`commands/runtime_overlay.rs` and its
duplicate in `mvm-build/src/runtime_overlay.rs`), and
`builder_vm_source_checkout_root` in `libkrun_builder.rs`.

Gates and tests: the kernel config budget, `check-runtime-overlay-version`, the
image tests in `tests/nix_flake_structure.rs`, and the `tests/release_assets.rs`
tests that read `release-boot-image.yml` move with the images.
`check-kernel-pin-freshness` splits (libkrunfw stays, the kernel flake moves).
The guest-image, guest-agent, host-binary-sync and guest-init parity gates stay
in `mvm` as contract checks.

No open PR touches `nix/`. Two local branches without PRs do
(`fix/3330-extended-ci-privilege` on `workspace-filter.nix`, and
`fix/github-actions-issues-20260915` on `kernel/base.nix` and `libkrunfw.nix`);
nothing is deleted from `mvm` until W8, but the copy into `mvm-images` should be
taken after they land or are abandoned.

Delivery slices, one PR each:

- [x] W4a (`mvm`) — export the guest recipes from `nix/flake.nix` for Linux
      systems, and have the in-tree image flakes consume those outputs, so the
      interface `mvm-images` will pin is the one `mvm` already builds through.
      Landed as `packages.<linux-system>.*` (agent, static agent, setpriv,
      runner, egress client, addon DNS, exit report, SDK cdylib glibc/musl) and
      `lib.<system>.hostBinaries`. For the same source, all 52 image and check
      `drvPath`s are identical on both systems under the old and new wiring.
- [x] W4b (`mvm-images`) — the image flakes, kernel, initramfs and QEMU-wasm
      pack, with every `mvm` import rewritten onto an `mvm` input pinned to an
      exact commit, plus a no-publish build workflow for both architectures.
      Landed as tinylabscom/mvm-images#4, pinned to `6717e2451e`.
- [ ] W4c (`mvm-images`) — compare the outputs against the published
      `boot-image/v0.1.5` set: file set, digests, closures, and boot on
      Firecracker (x86_64 and aarch64) and HVF, with every difference explained.
      Comparison done; aarch64 Firecracker boot outstanding
      (`specs/sprint/delivery/3362-w4c-image-comparison.md`). Every byte
      difference from `v0.1.5` traces to a named `mvm` commit or to the
      `generatorRev` rewrite. None is unexplained, and none comes from the build
      environment. Built from mvm's in-tree flakes at the pinned commit, the
      builder and default images have the same `drvPath`s as `mvm-images`
      (tinylabscom/mvm-images#5). Two builds of one derivation still differ in
      ext4 hash seeds, verity UUIDs and cpio inode numbers, with identical file
      trees (#3499). Until that is fixed, equivalence is checked file by file.
      Development-tier boots from an isolated `MVM_HOME`: x86_64 Firecracker ran
      the dev and prod default images, and built and booted a sealed workload
      through the `mvm-images` builder. On HVF the dev and prod default images
      ran, and the `mvm-images` builder booted, but its build did not finish
      within 90 minutes on the loaded host. The aarch64 Firecracker host was
      unreachable. Also found: #3500 (the Nix initramfs
      says `VERSION` `0.18.0`, which an rc CLI refuses) and #3502 (a Firecracker
      run rewrites the cached dev rootfs).

### W5 — Ship the sibling-checkout developer workflow (#3364)

- [ ] Add the explicit local image-source selector and paired-checkout wrapper.
- [ ] Scope mutable build/runtime state and VM/TAP/socket identities to the
      paired worktrees while sharing only atomically published immutable cache
      entries.
- [ ] Make cache keys include both repository commits, dirty fingerprints, the
      artifact role, architecture, and relevant toolchain/lock digests.
- [ ] Route local and released packs through the same resolver after trust
      classification.
- [ ] Add `doctor` output for source, commits, dirty state, digests, and tier.
- [ ] Add contributor documentation and a two-repository example change.

Acceptance:

- a developer can change an image in a sibling worktree and boot it without
  publishing;
- a second run reuses the content-addressed result;
- changing either repository invalidates only the affected cache entries;
- two paired changes can run concurrently without sharing mutable state or VM
  identities;
- a release binary and production admission refuse the unsigned local pack;
- path traversal, symlink substitution, stale manifest, and wrong-architecture
  tests fail safely.

Design, taken 2026-09-19 against `main` at `fd555b5ef9`.

- **Selector.** `MVM_IMAGES_DIR`, an environment variable, resolved in
  `mvm_build::image_source`. Not a config key: `~/.mvm` configuration is shared
  by every worktree, and the complexity budget forbids editing global config.
  Not only a flag: it has to reach every child `mvmctl` a build spawns, the way
  `MVM_BOOT_IMAGE` and `MVM_BUILDER_BACKEND` do. A global `--images-dir` flag
  may be added later as sugar that sets the variable (as `--builder` does).
  The path is canonicalized, must be a directory, must be the root of its git
  work tree, and must carry the `mvm-images` layout (`flake.nix`, `flake.lock`,
  `kernel/flake.nix`, `images/<role>/image.nix` for all four roles) as regular
  files, not symlinks. Selection records the canonical root, the commit, and
  the working-tree state (clean, or a fingerprint over the tracked diff, the
  status listing and every untracked file). `reverify` re-resolves the path and
  re-reads the identity before anything built from it is trusted, so a
  retargeted symlink or an edit after selection is refused. Nothing searches
  for a sibling.
- **Sources and tiers.** `ImageSource` is `Released`, `LocalCheckout`, or
  `InTree` (the mvm checkout's own `nix/images`, the contributor default until
  W8). `mvm_core::image_set::ImageTrustTier` has two values with no conversion
  between them: `verified-release`, produced only by verifying a signed,
  lock-pinned manifest, and `local-dev`, for anything built locally in either
  checkout. A configured selector that cannot be used is an error; it never
  falls back to the in-tree flakes or to the released set.
- **Release binaries and production.** A binary built with the
  `release-channel` feature (`artifact_acquisition::compiled_channel()`, the
  existing contributor-versus-release switch) refuses `MVM_IMAGES_DIR` before
  any verb runs, whether or not the path is valid; `doctor` is exempt so it can
  report the refusal. A sealed-production admission (`Variant::Prod`) refuses
  while the variable is set. Once consumers record the tier of what they built
  (W5k), admission refuses a `local-dev` image under `Variant::Prod` however it
  was selected; comparing against a signed release during development is
  `MVM_BOOT_IMAGE=fetch` with the selector unset.
- **Building.** Host Nix is never used. A local image is built inside the
  builder VM, as the in-tree images are today: both checkouts are staged into
  the guest and the build is
  `nix build path:<images>#legacyPackages.<sys>.<role>.<attr> --override-input mvm path:<mvm>`,
  with the three host binaries built from the paired mvm checkout rather than
  the pinned commit. `mvm-images` has to accept that override (W5b).
- **Cache identity.** One key per artifact: both repository identities (commit
  plus dirty fingerprint), role, guest architecture, and the digests of the
  pinned toolchain (`rust-toolchain.toml`, the zig pin) and of each flake lock
  the role evaluates. Outputs are content-addressed under `mvm_cache_dir()` and
  published atomically through `cache_install`, so they are the only state two
  pairs share. A change in one repository invalidates only the keys that
  include it.
- **Pair-scoped state.** The wrapper derives `MVM_HOME`, `CARGO_TARGET_DIR`,
  image staging and Stage 0 work directories from the pair's two canonical
  roots, and VM, TAP and socket names from `MVM_HOME` as today, so two pairs
  never share mutable state.
- **The in-tree window.** From W5a to W8 the in-tree flakes keep working
  unchanged for a contributor build that leaves the selector unset. A consumer
  moved onto the selector builds only from the checkout it names when set; a
  consumer not yet moved keeps using the in-tree flake and `doctor` says so. W8
  deletes `InTree`; after that an unset selector means the released set, and
  `MVM_BOOT_IMAGE=build` requires the selector.

Delivery slices, one PR each:

- [x] W5a (`mvm`) — the selector, `ImageTrustTier`, the release-build refusal at
      CLI entry, the production-admission refusal, and a `doctor` line
      (`image source`) reporting tier, source and both repositories' commits
      and working-tree state. Negative tests: traversal, a symlinked marker, a
      retargeted selection symlink, a non-directory, a non-checkout, a
      subdirectory of a checkout, a copy with no repository, and the release
      refusal. No consumer reads the selection yet.
- [ ] W5b (`mvm-images`) — accept a local `mvm` through `--override-input`,
      build the host binaries from a given mvm checkout, and emit a local
      image-set manifest recording both identities.
- [ ] W5c (`mvm`) — the local manifest in the released schema and parser, with
      a provenance that is either a release producer or the two checkout
      identities; classification refuses a local manifest that claims a
      release producer, a manifest whose identities disagree with a
      re-verified checkout (stale), a missing role, and the wrong
      architecture.
- [ ] W5d (`mvm`) — the cache key above and atomic, content-addressed publish of
      local outputs.
- [ ] W5e (`mvm`) — a `mvmctl build` subcommand that builds one role from the
      selected checkout inside the builder VM, plus the `bin/dev` wrapper that
      sets the selector and the pair-scoped `MVM_HOME` and `CARGO_TARGET_DIR`.
- [ ] W5f (`mvm`) — the builder VM: `find_builder_vm_flake`,
      `builder_vm_is_source_checkout` and their callers, the Stage 0 source
      fingerprint in `stage0_cache.rs`, the flake references `stage0-init.rs`
      hard-codes, and the kernel and image attribute-name contract.
- [ ] W5g (`mvm`) — the default workload image (`default_microvm.rs`) and the
      `MVM_BOOT_IMAGE=build|fetch` resolver.
- [ ] W5h (`mvm`) — kernel acquisition and the initramfs.
- [ ] W5i (`mvm`) — the runtime overlay and both SDK sidecar build paths, with
      the duplicate checkout detection in `commands/runtime_overlay.rs` and
      `mvm-build/src/runtime_overlay.rs` collapsed into the selector.
- [ ] W5j (`mvm`) — key the libkrun supervisor auto-build on
      `mvm_source_checkout` instead of `builder_vm_source_checkout_root`, so
      deleting `nix/images` does not turn a contributor build into an
      installed one.
- [ ] W5k (`mvm`) — `image boot update`, `up` and admission read the tier
      recorded with the image they boot; production refuses `local-dev`; the
      `doctor` line adds artifact digests.
- [ ] W5l — contributor documentation, the two-repository example change, and
      a paired-change CI job checking out both repositories at explicit SHAs.
- [ ] W5m — the acceptance witnesses: cache reuse and single-sided
      invalidation, two concurrent pairs, stale manifest, wrong architecture,
      and a live boot from a sibling checkout.

### W6 — Publish from `mvm-images` and migrate consumer trust (#3369)

- [ ] Publish a complete candidate image set from the protected image workflow.
- [ ] Update verifier identities and revocation URLs through an explicit
      old-plus-new trust window.
- [ ] Refuse an image set whose protocol range does not overlap the host's
      before acquisition, on every path that consumes one (carried from W3).
- [ ] Update Stage 0 kernel acquisition, default-image resolution, image update
      commands, CI downloads, and WebLinux consumers to the lock file.
- [ ] Boot every pack through its intended backend before advancing the pin.
- [ ] Add a bot or workflow that opens, but never auto-merges, an `mvm` pin
      update with manifest/compatibility evidence.

Acceptance: a clean machine installs `mvm`, downloads only from `mvm-images`,
verifies the new identity and digest, and boots on Linux/Firecracker and
macOS/HVF.

### W7 — Dual-publish compatibility window (#3368)

- [ ] For at least one image and CLI release, publish canonical assets from
      `mvm-images` while mirroring the required legacy assets to `mvm` releases.
- [ ] Prove old CLIs use legacy URLs and new CLIs use the locked image manifest.
- [ ] Compare canonical and mirrored digests automatically.
- [ ] Exercise rollback to the previous image-set pin without rebuilding a CLI.
- [ ] Publish migration and support-window documentation.

Acceptance: no supported CLI version receives a 404 or accepts differently
signed bytes during the transition.

### W8 — Cut over, remove duplication, and shrink the remaining suite (#3366)

- [ ] Remove image construction and canonical image hosting from `mvm` only
      after the compatibility window and telemetry/monitoring show the new path
      healthy.
- [ ] Retire duplicated signing and dual-publish steps without deleting
      historical releases.
- [ ] Keep contract, resolver, compatibility, and live-boot tests in `mvm`.
- [ ] Re-measure release duration, storage, download volume, and failure rate.
- [ ] Separately shard the 313-scenario documented-surface suite if its live
      phase remains the critical path.

Acceptance: normal host-only changes do not rebuild an image; an image-only
change does not require a CLI release; the release gate is at least 25 minutes
faster than the baseline; and rollback remains a lock-file change to a verified
existing release.

### W9 — Optionally compact `mvm` history after cutover (#3373)

History rewriting is not required for the image-repository cutover and must not
share a PR or rollout window with it. Moving files in the current tree does not
remove their old blobs: reducing a full clone requires rewriting every affected
commit and force-updating affected refs. That invalidates existing commit IDs,
signed tags, forks, open branches, worktrees, attestations, and external links.

An initial local inventory shows this is worth measuring: the shared object
database is approximately 5.4 GiB, and reachable history includes generated
`target-warn` blobs as large as 46 MB that were later removed from the tree.
That is not a fresh-clone measurement because the local database includes extra
refs and worktrees; W9 must measure the remote branch/tag surface independently
before deciding to rewrite anything.

- [ ] After W8 and the compatibility window, inventory the largest blobs
      reachable from the remote default branch and published tags; distinguish
      image/build artifacts from normal source and measure fresh full and
      blobless clone sizes.
- [ ] Record a go/no-go decision with an explicit minimum worthwhile reduction;
      prefer documented partial/blobless clones if a rewrite would save little.
- [ ] If approved, freeze merges, create and verify a permanent read-only
      archival mirror/object bundle, and publish an old-to-new commit mapping.
- [ ] Use a reviewed `git filter-repo` path policy that removes only confirmed
      generated image/build blobs. Do not delete GitHub release assets or the
      archival source of historical release provenance.
- [ ] Coordinate force-updated branches/tags, invalidate or replace affected
      signatures and attestations, require fresh clones, and provide explicit
      recovery instructions for contributors and forks.
- [ ] Verify the rewritten repository, tags, release-source mapping, fresh clone
      size, build/test gates, and protected-branch settings before reopening
      merges.

Acceptance: either the measured no-go decision is recorded, or the owner
separately approves the destructive rewrite and the archive, mapping, recovery
instructions, provenance checks, and before/after clone measurements are all
public and verified. No history rewrite is performed merely as a side effect of
moving the image sources.

## Test matrix

Every workstream selects the applicable rows; W6–W8 require all rows.

| Mode | Source | Expected trust | Required witness |
|---|---|---|---|
| source build | sibling checkout | local-dev | both repos dirty/clean identities reported; boot succeeds only in dev tier |
| source build | signed release | verified-release | digest/signature/compatibility checks and live boot |
| release binary | sibling checkout | refused | negative test before image materialization/boot |
| release binary | signed release | verified-release | clean-cache download and live boot |
| Linux | builder + workload packs | verified-release | Firecracker/KVM build and workload boot |
| macOS | builder + workload packs | verified-release | physical Apple Silicon HVF build and workload boot |
| offline | cached signed set | verified-release | no network and full re-verification |
| rollback | previous signed set | verified-release | explicit pin rollback and boot |
| revoked | any cache state | refused | cached and fresh acquisitions both reject |

## Rollout and rollback

The migration advances by lock-file updates. The old producer remains intact
through W7. At each boundary, rollback means restoring the previous verified
lock entry, not rebuilding or mutating an existing release.

Never delete or overwrite historical GitHub releases. If an image set is bad,
publish revocation/supersession metadata and a new immutable set, then advance
the pin through review.

## Definition of done

- [ ] W1–W8 issues are closed with their acceptance evidence linked; W9 has a
      measured go/no-go decision and, if approved, its separate migration is
      complete.
- [ ] `mvm-images` is the canonical producer and host for the complete image
      set.
- [ ] `mvm` has one image lock and no scattered canonical repository/tag pins.
- [ ] Production accepts only signed, compatible, unrevoked image sets from the
      new trust root.
- [ ] Sibling development is documented, tested, explicit, and impossible to
      enable in a release/production binary.
- [ ] Old supported CLIs remain functional for the declared support window.
- [ ] Linux/Firecracker and physical macOS/HVF clean-cache witnesses pass.
- [ ] The measured release critical path improves by at least 25 minutes, and
      remaining scenario time is separately visible.
- [ ] `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` match this plan.

## Kickoff prompt

Use the prompt below after this plan and its issues land:

> Start issue #3363 (W1) of
> `specs/plans/2026-09-16-image-repository-extraction.md` from a
> synchronized `main` in its own worktree. First confirm the current RC release
> is complete and do not invalidate an in-flight exact-tree release witness.
> Make the Linux documented-surface release lane fetch the pinned signed builder
> image, and move the cold source/Stage-0 bootstrap proof into a focused trusted
> nightly job. Preserve every existing live scenario and all fail-closed
> signature, digest, architecture, and revocation behavior. Add structural and
> negative tests first, emit phase timings, run the required workspace and
> workflow gates, update the plan/sprint/refactor rollup together, and ship the
> PR through the merge queue. Compare two post-merge runs against the recorded
> 2026-09-15 baseline; do not claim the speedup without measured evidence.
