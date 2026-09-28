# Pack signing smoke input isolation

Backing: shipped-source
Validation: check-workflow-paths

**Status: IN PROGRESS**

Issue: #3794. Worktree: `mvm-3794-pack-signing`.

The release-tag signing smoke passes `smoke/vmlinux` and its sibling artifacts
as both pack inputs and outputs. `builder_pack::copy_file` uses `fs::copy`,
which truncates same-file copies on Linux. The later image-set structure gate
correctly refuses the now-empty kernel. Keep immutable fixtures under
`smoke/inputs` and generated packs under `smoke`.

- [x] Reproduce the input/output collision with the workflow regression.
- [x] Separate inputs and outputs; regression and actionlint pass.
- [x] Pass host workspace Clippy with warnings denied and the Cargo regression test.
- [ ] Pass full workspace tests and Linux builder all-targets Clippy.
- [x] Pass the real signing workflow: run 36472914601 on the fix branch.
- [ ] Pass remaining PR checks, merge, and verify issue closure.

The standalone regression failed against the original workflow and passed
after the path change. The focused Cargo regression and host workspace Clippy passed. Full workspace
tests and Linux builder validation remain pending. The real signing workflow
passed; the initial PR invariant failure was a missing plan evidence header.
