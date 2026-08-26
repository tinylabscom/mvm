# Pre-commit clippy 4m37s → 60s, stable toolchain 1.96.0 → 1.97.1

Taking `mvm-cli`'s build script off the inner loop (PR #2883) left the
pre-commit hook as the dominant per-commit cost. Measured after a one-line
`mvm-core` edit against a warm stable target dir:

| invocation | cost |
|---|---|
| `--workspace --all-targets` (what the hook ran) | **4m37s** |
| `--workspace` (libs + bins only) | 54s |
| `--workspace`, then `-p mvm-core --all-targets` | **60s** |

`--all-targets` is 5x the whole cost, not a trim on it — it builds every
integration-test binary and dev-dependency in the tree. The hook widened to it
whenever a staged crate had dependents, which `mvm-core` always does, so its
`is_leaf_package` shortcut could never fire for the crates people actually edit.

The non-leaf path now runs two narrower passes: every crate's libs and bins
(which is what catches a change to a depended-on crate breaking a dependent),
plus the full target set of just the staged crates (where your own test-code
lint drift lives). What that gives up is test-target lints in crates the commit
did not touch; CI still runs the full `--workspace --all-targets` sweep.

## Stable toolchain 1.96.0 → 1.97.1

32 references across 17 files — it is the project-wide stable toolchain, not
only the lint lane (release, security, boot-image and pages workflows pin it
too). `clippy --workspace --all-targets -- -D warnings` passes clean on 1.97.1
with no new lints.

## Two things found on the way

`check-fast-cargo` — the gate pinning the entire nightly-fast/stable-lint split
— **was red on unmodified main** (`c8cd9c4245`): `rust-toolchain.toml` had been
bumped to `nightly-2026-08-25` while `.github/workflows/bdd.yml` stayed on
`nightly-2026-08-08`. It went unnoticed because **nothing in CI ran it**; it is
a shell script, so `xtask check-all` does not reach it, and no workflow invoked
it. Both fixed here: `bdd.yml` re-pinned, and the gate wired into the CI lint
job as a step beside `check-all` so it cannot rot again.
