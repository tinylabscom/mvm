# 334 — `mvm-cli` build script off the inner loop

Reuse already-cross-compiled musl host binaries in the debug profile instead of
re-running `cargo-zigbuild` on every edit that touches their transitive sources.

**Measured:** an `mvm-core` one-line edit went **288s -> 15s**. The build script
was 175.9s of a 178.9s rebuild (98%); the musl leg was ~93% of that.

Release and every non-debug profile rebuild from source unchanged, so shipped
binaries and the single-download property are unaffected. The native per-VM
supervisors still rebuild every time (13s) because that is the class where stale
binaries fail silently.

Added `just embed-refresh` to drop the cache on demand, and exported
`MVM_EMBEDDED_BINS_REUSED` so a reused set is observable.

Full measurement log, including five refuted hypotheses, in
`specs/plans/334-build-critical-path.md`.
