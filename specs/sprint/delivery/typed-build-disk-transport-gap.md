# The typed persistent route reads back an empty export

`/job` had two consumers and #3061 migrated one of them.

`persistent_builder_spec` now declares no shares, so a persistent HVF session
exchanges everything over the transport disks. The CLI dispatch path was updated
with it (`repack_dispatch_input` / `read_dispatch_artifacts`), and the install
arm was made to refuse outright, because the transport collects `/out` and not
`/job/<job_id>/out`.

`dev_build.rs` was not touched, and it is the other consumer.
`try_typed_persistent_build` still creates `<job_dir>/<uuid>/out` on the host and
tells `mvm-builderd` to export to the guest path `/job/<uuid>/out` — a path the
session record's own field doc now describes as one "the guest never sees" when
`disk_transport` is set.

## Why it failed silently rather than loudly

`copy_staged_artifacts` iterates the export directory. Over an empty directory
the loop body never runs and it returned `Ok(())`. `finalize_typed_persistent_build`
then composed `vmlinux` and `rootfs.ext4` paths as strings without checking they
exist, logged "Builder VM build complete (typed)", and returned a
`DevBuildResult`.

Two consequences, and the second is the worse one:

- The failure surfaced later, at boot, far from its cause.
- Returning `Ok` **bypassed the single-shot fallback**, which only triggers on an
  `Err`. The safety net was there and could not fire.

## The fix, in two parts

**Fall through when the session uses the transport.** `try_typed_persistent_build`
returns `None` — the "no typed route available" signal — with a warning naming
the reason. Falling through rather than refusing is deliberate and differs from
the install arm: that one fails closed because a claim-11 sealed volume would
silently lose its SBOM and CVE sidecars, whereas this route has a working
single-shot fallback and taking it costs build time, not correctness.

**Make an empty export an error everywhere.** `copy_staged_artifacts` counts what
it copied and bails on zero. This is the part that matters beyond this bug: any
future path that exports nothing now fails loudly at the point of failure instead
of producing a `DevBuildResult` naming files that were never written.

## Scope and what is not claimed

Found by reading, not by reproducing. Confirming it live means starting a
persistent HVF session and running a build through it, which needs the hidden
`mvmctl persistent-builder` subcommand; the reasoning is `disk_transport.is_some()`
on one side and no writer for `host_out` on the other, both verifiable in the
tree. The empty-export half is directly unit-tested.

The persistent route is opt-in, hidden, and falls back, so the blast radius is
build time on an explicitly-started session — not a broken default build.

## Verification

`cargo fmt --all --check`, `just check-gated`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo nextest run --workspace` (12,965 passed),
`cargo test --workspace --doc`, `cargo run -p xtask -- check-all` (67 gates).
