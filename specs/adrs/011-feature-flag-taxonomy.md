# ADR-011: Exactly two root feature surfaces — `host` and `user`

## Status

Accepted.

## Context

A workspace this size risks feature-namespace sprawl: every contributor
inventing a new per-capability flag ad hoc, with no mechanical way to
tell a dev-only capability apart from a shipped one, or a platform knob
apart from product behavior.

## Decision

### Two, and only two, consumer-facing product surfaces

```toml
[features]
host = [ ... ]  # everything the host machine runs to provision/build/secure/run sandboxes
user = [ ... ]  # everything a user runs to drive them
```

Every capability folds into one of these two. There is no third
consumer-facing product surface, ever.

- **`host`** — platform-neutral; backends auto-detect at runtime through
  the `VmBackend` trait. Forwards to the sub-crate features that give it
  builder-VM dispatch, in-process rootfs materialization, custom DNS, and
  the gated hostd IPC transport.
- **`user`** — forwards to cosign manifest verification for `--prod` and
  `build --watch`.
- **`default`** — the lean host-runtime core the shipped `mvmctl` binary
  gets with no opt-in: a strict subset of `host`.
- **`dev`** — the local-development meta-feature: the `host` + `user`
  union plus a contributor-bootstrap forward, so a contributor's laptop
  builds one `mvmctl` that runs every documented example.

### A short, fixed internal allowlist

The only other root features are knobs that cannot be unconditional and
are not product behavior:

- `libkrun-sys` / `libkrun-live` — link the libkrun C VMM. Absent on a
  macOS-26 HVF host, where there is no libkrun to link against.
- `template-registry-s3` — an optional, heavy S3 storage backend for the
  template registry (fleet-only, not part of the local host runtime).
- `hostd-transport` — a lean library knob: `mvm-core`'s gated hostd IPC
  transport, exposed standalone so a downstream host-side daemon can
  flip just the transport without pulling in the rest of `host`.
- `release-artifact-bootstrap` — release-only: lets an installed binary
  download mvm-published prebuilt images on a cache miss. Off for source
  checkouts, which always build locally.

### Mechanical enforcement

`xtask check-two-surfaces` parses the root `Cargo.toml` `[features]`
table and fails CI if `host` or `user` is missing, if `dev` stops
aggregating both, or if any root feature exists that is neither `host`,
`user`, nor on the internal allowlist above. Adding a new root feature
therefore forces an explicit decision in the same PR: fold it into
`host` or `user` because it is product behavior, or justify its addition
to the allowlist in `xtask/src/check_two_surfaces.rs` because it
genuinely cannot be unconditional.

Individual per-crate feature names (the sub-crate features `host`/`user`
forward to) are not independently selectable at the root — a contributor
building `mvmctl` directly reasons about two names, not the sub-crate
graph behind them.

## Consequences

The feature namespace cannot sprawl: "exactly two surfaces" is a
structural fact enforced by `check-two-surfaces`, not a style guideline
a reviewer has to remember to apply. A PR that adds a third
consumer-facing knob fails a named CI step.

A genuinely platform-specific or build-only knob that isn't clearly
`host`, `user`, or already on the allowlist needs a real design decision
and an `xtask` code change before it can land — there is no "just add a
flag" escape hatch.

`mvm-core`'s own feature gates (`hostd-transport`, `manifest-verify`) are
unaffected by this taxonomy beyond being forward targets — this ADR
governs the root facade crate's `[features]` table, not what any
individual library crate chooses to gate internally.
