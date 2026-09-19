# Issue 3477: stable unresponsive-manager witness

## Outcome

The scope launcher is resolved from `PATH` once, canonicalized to an absolute
path, and carried through both spawn renderings. A later environment change can
no longer select a different executable between the mechanism probe and spawn.

The Linux timeout regression no longer uses a shell script. The kernel may
expose an interpreter-backed script as `sh` before its body opens, which makes
the process-name watcher believe `systemd-run` has already exec'd its payload.
The fixture now installs a real executable at the `systemd-run` path, verifies
that path exists, asserts that the bound command uses its canonical path, and
keeps stdout and stderr closed while the fake launcher waits to be killed.

## Validation

- `cargo fmt --all -- --check`
- `cargo test -p mvm-core spawn_scope::tests::`: 47 passed
- `cargo clippy -p mvm-core --all-targets -- -D warnings`

The Linux-only unresponsive-manager test needs `/proc` and is therefore left to
the repository's Linux CI lane. Merge-queue delivery remains open until that
witness and the full required checks pass.
