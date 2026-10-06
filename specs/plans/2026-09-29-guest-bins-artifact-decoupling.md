# Decouple mvm-images from the mvm source tree via a guest-bins artifact

> **Superseded (2026-10-05)** by ADR-054
> (`specs/adrs/054-image-boundary-linux-layer.md`) and its design attachment
> `specs/plans/2026-10-05-image-boundary-linux-layer.md`; tracking issue
> [#4100](https://github.com/tinylabscom/mvm/issues/4100). The producer half
> survives: `mvmctl build guest-bins` and its archive carry over, now as a
> signed CLI release asset that `mvmctl` itself consumes. The consumer half
> does not: `mvm-images` stops depending on mvm entirely instead of building
> from the archive, so the bump job, `guest-bins.nix`, vendoring `mkGuest`,
> fetch-when-unchanged across the decoupling and `image-set/v0.3.0` built on
> the artifact are all dropped. The body below is kept as history and is not
> current work.

Backing: historical
Validation: each box ticks only with the live evidence its text names;
unchecked boxes remain in progress.

**Status:** IN PROGRESS (2026-10-02) — the producer verb and a dispatch-only
dev-copy workflow exist; the release attachment, bump job, and consumer have
not started. Until the consumer cuts over, the current flake input remains the
supported build path.
**Date opened:** 2026-09-29

## The pattern this completes

`mvm` is the control plane: traceable, auditable, attestable, trusted. The
images a guest boots are built only in `mvm-images`. The two trains release
independently — a kernel or security fix ships as a new image set without a
CLI release; an mvm feature ships without rebuilding an image. That separation
is real today (v0.18.3 published no image bytes; image-set/v0.2.2 needed no
CLI); the one coupling left is that `mvm-images` *builds* the guest binaries
from the `mvm` source tree through a flake input. This plan removes it: the
binaries become a published artifact, and `mvm-images` consumes that artifact
like any upstream — the same version + sha256 pattern the image lock already
uses, with the same auto-bump ergonomics.

Coupling after this plan: published artifacts only. `mvm` → consumes signed
image sets (`images.lock`). `mvm-images` → consumes `mvm-guest-bins` (version +
sha256). Both directions digest-verified and identity-checked; the
compatibility contract (guest-agent protocol range, builder cache contract,
boot ABI) keeps the trains safe to version independently.

## Work

- [ ] **Producer: `mvm` ships a guest-bins artifact.** A `mvmctl build
      guest-bins` verb (and a CI job) assemble `mvm-guest-bins-v{version}.tar.gz`:
      every guest binary for both guest architectures, built from the one
      workspace `Cargo.lock` (host and guest binaries stay one-build — this is
      why the source does not move), plus a manifest recording each binary's
      sha256, the workspace version, and the cdylib source fingerprint. CLI
      releases attach it; a workflow_dispatch builds a dev copy.
      *Landed (2026-10-02):* `mvmctl build guest-bins [--out] [--arch]`
      (`mvm_build::guest_bins`) packages the ten static musl executables the
      existing host-side guest builds produce — the runtime-overlay set plus
      `mvm-oci-entrypoint` — for both arches, as `<arch>/<bin>` beside a
      `manifest.json` (per-member sha256, version, guest-source and cdylib
      source fingerprints) and a `.sha256`. The archive is deterministic and
      re-verified after writing. `.github/workflows/guest-bins.yml` builds the
      dev copy on dispatch. *Not yet:* (1) CLI releases do not attach it —
      `release.yml`'s asset set is pinned to the signed checksum manifest, the
      installer, and `tests/release_assets.rs`, so adding an asset is its own
      change; (2) the shared objects `mvm-images` also takes from this tree —
      `libmvm_host_services.so` (glibc + musl) and the GPU shims — and the
      static `mvm-setpriv` are not in the archive, because no host-side build
      path produces them today (this tree's Nix recipes build them during the
      `mvm-images` image build). The consumer cannot drop the flake input until
      they are.
- [ ] **The bump job.** `mvm`'s release workflow opens a PR in `mvm-images`
      advancing the guest-bins `version`/`sha256` pair (needs the
      "Actions can open PRs" setting or a token; until then a maintainer opens
      the pushed branch by hand, as the image-pin proposals are today).
- [ ] **Consumer: `mvm-images` builds from the artifact.** The `mvm` flake
      input is replaced by a `guest-bins.nix` recipe holding the version and
      per-arch sha256; images unpack the pinned artifact instead of building
      the source tree. The deep Nix coupling (flake input, workspace-filter,
      host-binary manifest) goes away.
- [ ] **The `mkGuest` decision.** `mkGuest` is user-facing API (workload
      authors use it from `mvm`), so it stays there; `mvm-images` vendors its
      image-assembly copy and a fixture test pins the two to the same output
      for a fixed input. (Alternative, rejected unless the fixture becomes
      painful: keep a narrow nix-lib import — a coupling this plan exists to
      remove.)
- [ ] **Paired development stays one step.** `mvmctl build guest-bins` writes
      a local tarball; `mvm-images` accepts an override (env var or nix arg)
      naming it, equivalent to today's `--override-input mvm path:…`. Changing
      agent + image together must not need a publish.
- [ ] **Compatibility and freshness.** The SDK sidecar's `source_fingerprint`
      compares against the fingerprint recorded in the guest-bins manifest, so
      fetch-when-unchanged keeps working across the decoupling. The set's
      declared protocol range remains the before-boot gate.
- [ ] **Cut over.** The first set built entirely on the artifact publishes as
      `image-set/v0.3.0`; mvm advances its pin through the normal proposal
      flow. The legacy flake-input path is deleted from `mvm-images` in the
      same change, per its AGENTS.md rule that transitional mirrors must not
      become permanent reverse dependencies.

## The developer-experience contract

The owner-level requirement this design serves: developing a feature for the
binaries that run inside a microVM must not feel like a two-repo workflow.

- **A guest-binary-only feature touches only `mvm`.** The recipe is unchanged;
  the dev-tier build arms rebuild and boot the new binaries from the checkout
  (the runtime overlay's source arm today, rootfs images through one pair-build
  verb), with no `mvm-images` checkout required.
- **`mvm` is the front door.** One clone of `mvm` is a complete environment:
  `bin/dev` auto-provisions the sibling `mvm-images` checkout on the first
  image-touching use (shallow, at the pin), so the second repo is a build
  detail, not a workplace. Crossing into `mvm-images` happens deliberately,
  for image-definition work only.
- **One verb drives every image operation from `mvm`**
  (`bin/dev build image-set <role>`), and under this plan the guest-bins
  freshness step happens inside it — no hand-wired paths.
- **CI owns `mvm-images` day to day**; the bump jobs, not humans, carry the
  version + sha pairs across the boundary.

## Tests

- `mvm`: the artifact's manifest digests verify against the bytes; the
  fingerprint in the manifest equals `sdk_cdylib_source_fingerprint` of the
  producing tree.
- `mvm-images`: a wrong sha256 refuses the build by path; the local-override
  arm builds the same image as the pinned artifact for the same bytes.
- Cross-repo: a fixture pins vendored `mkGuest` and `mvm`'s to identical
  output for one fixed input.

## The decision tripwire

The repo split survives on two promises; if either fails, the decision
re-opens — revert to a single repo included, without sentiment.

- **Queue wall.** After the in-flight merge-queue levers land (#3841's
      boot-lane scope, the workspace sharding, and any successor), the
      merge-group wall must hold below **20 minutes** when runners are free,
      measured over at least ten merge-group runs. If it does not, the
      split's remaining performance justification is weak and the topology
      decision is revisited with the data.
- **One-clone bootstrap.** A new contributor clones only `mvm`, follows the
      quickstart, and never needs to know `mvm-images` exists unless they
      change an image definition. The auto-provisioned sibling checkout and
      the single front-door verb are the acceptance test; if they are not
      real, DX becomes the reason to reconsider.

Both measurements are recorded in the follow-up plan
(`2026-09-27-release-e2e-under-image-target.md`) when the v0.18.4
re-measurement and the bootstrap land.

## Non-goals

Moving agent or protocol source out of `mvm` (the host links those crates;
that inversion would cost protocol co-development its one-Cargo.lock
guarantee). Dropping or weakening `images.lock` — the pin is the unforgeable
form of "trust the checksums"; a dev-tier auto-adopt knob is a separate, small
decision if wanted.

## Open questions

- Guest-bins on every CLI release, or only when guest-relevant inputs change
  (fingerprint-driven)? Leaning: every release — simplicity beats thrift here.
- Does the bump job live in `release.yml` or a small dedicated workflow?
  Leaning: dedicated, mirroring `update-image-pin.yml`.
