# Live BDD merge-queue witness

Issue #2657 identified three separate gaps: live scenarios were silently
skipped, no CI lane opted into them, and the README contract stopped at command
parsing. The skipped-scenario report addresses the first gap. This closeout
addresses the other two without turning every PR update into a registry and
microVM integration run.

## Scope

- [x] Add a merge-queue/manual-only KVM-backed BDD job on `ubuntu-latest`.
- [x] Select a narrow `@ci_live` witness instead of running registry-, Nix-,
      bundle-, and performance-heavy scenarios in one lane.
- [x] Exercise the README persistent lifecycle against one real Firecracker
      guest: create, start, exec, logs, inspect, stop, and remove.
- [x] Pin the workflow, recipe, and command sequence with structural tests.
- [x] Run formatting, focused tests, workspace checks, Clippy, and gated checks.
- [x] Update delivery and refactor status, then queue PR #2727.
