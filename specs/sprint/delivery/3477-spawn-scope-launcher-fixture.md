# Issue 3477: stable unresponsive-manager witness

## Outcome

The scope launcher is resolved from `PATH` once, canonicalized to an absolute
path, and carried through both spawn renderings. A later environment change can
no longer select a different executable between the mechanism probe and spawn.

The Linux timeout regression keeps the executable blocking script published by
the fixture at the canonical `systemd-run` path. It must not overwrite that
path with an unrelated program: the process-name watcher treats any name other
than `systemd-run` as proof that the launcher exec'd its payload. The test
verifies the exact path before spawning and keeps stdout and stderr closed while
the fake launcher waits to be killed.

## Validation

- `cargo fmt --all -- --check`
- `cargo test -p mvm-core spawn_scope::tests::`: 47 passed
- `cargo clippy -p mvm-core --all-targets -- -D warnings`

The first queued consumer exposed the overwritten-program regression on both
Linux architectures. The corrected Linux-only witness needs `/proc` and is
therefore left to the repository's Linux CI lane. Merge-queue delivery remains
open until that witness and the full required checks pass.
