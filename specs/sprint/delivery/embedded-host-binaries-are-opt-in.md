# `mvm-cli(build)` no longer runs on the inner loop

Plan: `specs/plans/2026-08-28-embedded-host-binaries-are-opt-in.md`

Deleting the aux-helper leg took a build-script key miss from 60.37s to 0.13s
but did not stop the script running — the musl cross-compile was still
unconditional, so cargo re-executed `mvm-cli(build)` on every edit touching any
of its 648 watched files. That leg is now behind the `embed-host-bins` feature,
default off. With it off the script writes an empty `EMBEDDED` table, watches
four files and returns; verified that `touch crates/mvm-core/src/lib.rs` +
`cargo build -p mvmctl --bin mvmctl -vv` produces zero build-script executions.

The non-obvious part: emitting *no* `rerun-if-*` line does not mean "never
re-run", it restores cargo's default of re-running on any change to the
package's 251 files. The unembedded arm emits four explicit watches for exactly
the inputs that can change what it writes.

An unembedded `mvmctl` runs every host-side verb but cannot bootstrap a builder
VM, so `ensure_extracted` refuses before creating the cache directory and names
`just embed`. Gating the payload tests on the feature is paired with a new
`tests/unembedded_host_binaries.rs` asserting the default configuration's
contract, so neither arm is left asserting nothing. `lint-features` in `ci.yml`
(which already installs the pinned zig) runs the feature-on lane, so a break is
caught on the PR rather than by a tag-push release.

`MVMCTL_RELEASE_FEATURES` in `release.yml` gains the feature, so shipped
binaries are unchanged. The five scripts that boot VMs build with it;
`test-app-deps-ci-gate.sh` does not, because it boots nothing.
