# Decouple mvm-images from the mvm source tree via a guest-bins artifact

Backing: preview
Validation: each box ticks only with the live evidence its text names;
unchecked boxes remain in progress.

**Status:** NOT STARTED — sequences after the in-flight chain (image-set/v0.2.3,
the mvm pin to it, and the v0.18.4 re-measure). Until then the current flake
input remains the supported build path.
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
      for a fixed input. (Alternative, rejected unless the fixture proves
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

## Tests

- `mvm`: the artifact's manifest digests verify against the bytes; the
  fingerprint in the manifest equals `sdk_cdylib_source_fingerprint` of the
  producing tree.
- `mvm-images`: a wrong sha256 refuses the build by path; the local-override
  arm builds the same image as the pinned artifact for the same bytes.
- Cross-repo: a fixture pins vendored `mkGuest` and `mvm`'s to identical
  output for one fixed input.

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
