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

- `nix/images/builder-vm/`;
- `nix/images/default-tenant/` and the production workload kernel build;
- `nix/images/runtime-overlay/`;
- `nix/images/sdk-sidecar/`;
- image-specific Nix libraries and lock files;
- image assembly, boot tests, SBOM generation, signing, and publication;
- the immutable image-set manifest and revocation documents; and
- reproducibility instructions for every published artifact.

The exact file inventory is established mechanically before any move. Shared
Nix helpers move only if all remaining consumers are image concerns; otherwise
they become a small versioned interface rather than being copied.

### `mvm` continues to own

- host CLI/runtime source and guest-agent source;
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
- [ ] Compare two post-merge runs against the 2026-09-15 baseline (10 minutes
      of build, 37 minutes of source image preparation, 67 minutes of
      scenarios; 118-minute job) and record the result on #3363.

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

- [ ] Add a versioned image-set manifest schema and round-trip/negative tests.
- [ ] Model guest architecture, boot protocol, artifact format, and required
      capabilities independently of the host OS so Firecracker, HVF, and future
      Windows backends can select compatible packs without host-named images.
- [ ] Add `mvm`'s single checked-in image lock and generate consumers from it.
- [ ] Define guest/host protocol compatibility and refuse incompatible sets
      before boot.
- [ ] Include source commits, Nix inputs, SBOM references, sizes, and digests.
- [ ] Add offline verification tooling that needs only the manifest, bundle,
      and artifacts.

Acceptance: tampering, wrong repository/workflow identity, wrong architecture,
partial sets, incompatible protocol ranges, replayed superseded metadata, and
revoked packs all have negative tests.

### W4 — Move image sources and reproduce current bytes (#3362)

- [ ] Inventory the exact image-owned paths and shared helper edges.
- [ ] Move image flakes, locks, assembly scripts, and image-specific tests to
      `mvm-images` without copying product runtime source.
- [ ] Build guest/builder binaries from an explicit `mvm` source commit.
- [ ] Compare the new repository's outputs with the existing release for file
      set, boot behavior, manifest semantics, and explained byte differences.
- [ ] Preserve both x86_64 and aarch64 builds and live boot evidence.

Acceptance: both architecture sets build, verify, and boot; every unexplained
byte or closure difference blocks publication.

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

### W6 — Publish from `mvm-images` and migrate consumer trust (#3369)

- [ ] Publish a complete candidate image set from the protected image workflow.
- [ ] Update verifier identities and revocation URLs through an explicit
      old-plus-new trust window.
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
