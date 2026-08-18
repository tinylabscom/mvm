# An `image =` manifest builds now

**Plans:** `specs/plans/329-run-first-cli-and-upstream-adoption.md` Phase 4 and
`specs/plans/255-vsock-first-snapshot-egress-adoption.md` Phase 4 — both of
which specified this as `mvmctl template build --image <ref>`.

## The spelling in both plans is pre-plan-38

`mvmctl template build` does not exist. PR #62 ("Manifest-driven template DX",
plans 38–40, 2026-05-04) collapsed `template init NAME → template create NAME →
template build NAME` into a single manifest file discovered by path, with slot
keys becoming `sha256(canonical_manifest_path)` instead of user-invented names.
What survives under `template` is a read-only registry browser.

So the capability did not vanish, it moved — and the plans kept describing the
old front door. The post-38 spelling is `mvmctl machine build <path>`.

## What was actually missing

`mvm.toml` has carried `image = "..."` as a validated source selector, mutually
exclusive with `flake`, since the manifest primitive was introduced. The build
path refused it:

    manifest selects an `image` source ("alpine:3.20"); `build` only handles
    flake sources today — image-backed builds are not wired yet

That refusal is now the other arm.

## Why it is small

The hard parts existed. `mvm-client`'s materialization already turns an OCI
reference into a `rootfs.ext4` with the overlay-aware `mvm-meta.json` sidecar
written beside it, and the workload kernel is the one every OCI run boots. So
the new code assembles those into a slot revision through the *same*
`install_revision_artifacts` the flake arm uses.

That sameness is the design constraint, not an implementation detail: after the
build returns, `--manifest` cannot tell which arm produced the slot. One
revision layout, one `current` symlink, one `revision.json`.

`mvm_client::local::materialize_image_rootfs` is exported rather than
reimplemented for the same reason — a second materializer would be a second
answer to "what does this image become", and the two would drift.

## Decisions worth recording

- **The revision is keyed by rootfs content**, so rebuilding a pinned reference
  is idempotent and a changed image gets a new revision without the caller
  tracking anything.
- **A materialization with no sidecar refuses.** The sidecar carries the
  overlay-awareness the backend reads at boot; installing without it yields a
  slot that boots differently from the `run --image` it is supposed to mirror.
- **`revision.json` records the image reference in `flake_ref`.** The field is
  the on-disk source slot; writing a fabricated flake path there would imply a
  flake that never existed. The field name is now wrong for half its uses and
  is worth renaming to `source_ref` — deliberately not done here, since it is a
  schema change touching the flake path and every existing slot.

## Coverage

Four unit tests in `mvm_runtime::vm::template::lifecycle::build_image`. Two are
mutation-checked red: keying the revision by something other than content, and
accepting a missing sidecar.

A BDD scenario was written and then deleted — it asserted `machine build --help`
mentions "manifest", which passes with the feature reverted. Real BDD coverage
needs a registry pull the hermetic suite does not do.

Verified by hand end to end: `machine build` on an `image = "alpine:3.20"`
manifest produces a revision holding `rootfs.ext4` (10.6 MB), `vmlinux`,
`mvm-meta.json`, `fc-base.json` and `revision.json`; a second build reuses the
revision hash; and `machine run --manifest ./mvm.toml --dry-run` resolves it.

One process note: the first version of these tests took a `TestEnv` without
calling `isolate_mvm_home`, so they shared the real `MVM_HOME` and passed alone
but failed in the full parallel suite. That is the hazard `TestEnv`'s own doc
comment warns about.
