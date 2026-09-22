# Contributor documentation and the paired-change CI job

Backing: shipped-source
Validation: cargo run -p xtask -- check-workflow-paths && cargo run -p xtask -- check-doc-links

Slice W5l of the sibling-checkout workflow (#3364): the developer-facing
documentation for working on images through a sibling checkout, a complete
two-repository example, and a CI job that validates the pair with both
repositories at explicit SHAs.

## What changed

- New guide `public/src/content/docs/guides/image-sibling-checkout.md`:
  the one explicit-selector rule (an unusable path is an error, never a
  fall-back), `bin/dev` as the paired entry point, `mvmctl build image-set`
  for each role and both SDK sidecar attributes, what consumes the
  selection (builder VM, default image, kernel, overlay, sidecars), the
  trust-tier enforcement (release builds refuse the variable; production
  admission refuses local-dev however the bytes were selected), and a
  complete worked example from a fresh sibling layout through an image edit
  to a reboot on the changed bytes. Sidebar entry added; the
  building-microvm-images guide cross-links it for anyone who lands there
  first.
- New workflow `.github/workflows/image-pair.yml`: nightly and on demand,
  checks out mvm and mvm-images each at an explicit SHA (dispatch inputs
  default to `main`), then runs the sibling's own
  `scripts/check-source-drift.sh --against <mvm sha> --mvm-git-dir <clone>`
  — the same gate mvm-images CI runs when its pin advances. The dispatch
  form is the tool for testing a paired change against a specific companion
  commit before either side lands; the nightly keeps both mains honest.
  The heavy pair build stays in mvm-images' own build workflow; this job is
  the cheap git-level gate, and it introduces no secrets and no mutable
  refs.

## Evidence

- `check-workflow-paths` clean (29 workflow files, all action refs pinned
  per repository convention); `check-doc-links` clean (400 hermetic links,
  including the new guide and sidebar entry).
- The workflow's drift gate is the sibling's existing, CI-proven script; the
  nightly first run will exercise the checked-out pair end to end.

## Not done

- W5m — the acceptance witnesses: cache reuse and single-sided
  invalidation, two concurrent pairs, stale manifest, wrong architecture,
  a live boot from a sibling checkout, and the same pair-built base image
  booted by every Linux-direct backend.
