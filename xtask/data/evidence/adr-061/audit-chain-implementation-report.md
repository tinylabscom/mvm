# Audit-chain ownership implementation report

Backing: preview
Validation: none

Historical source basis: `62603aeffe78be79728ef347204872ae0344fb79`.
Recovery source basis: `d7727419166b6ba7cfd47f603d523624f637318a`.
Scope and approval: [prerequisite plan](audit-chain-prerequisite-plan.md),
accepted ADR-061 / #5510 and the explicit recovery instruction.

The combined recovered candidate has now passed scoped integration tests,
workspace check and clippy, gated-target compilation, all 88 aggregate policy
gates, and the serialized workspace test suite. Exact commands, the concurrent
HVF test failure, interruption history and evidence limits are recorded in the
[combined validation report](../audit-directory-policy-report.md#combined-recovery-validation).
The isolated and archived results below retain their original scope.

## Current recovery evidence

The archived edit-tool transcript supplied as
`/tmp/mvm-audit-recovery-transcript.json` was read without modification.
Recovery uses its actual patches, not a reconstructed summary, for the
compatibility tests and relocation scope. Production files are moved from the
current source basis, not replaced with historical source.

This isolated portion moves `signer`, `audit_recorder` (including `bound`),
`audit_mirror`, `audit_dedup`, `transcript_sink` and `bound_sink` (including
tests). Audit-owned imports are canonicalized, except `emitter.rs`, owned by
the parallel directory-policy recovery. Supervisor's nested compatibility
reexports and existing flattened exports retain concrete identities. The
current `denial_stage` producer declaration is preserved.

The method `record_audit_context_direct` remains restricted to the common
owning audit module (`pub(in crate::audit)`), not widened crate-wide.
There are no new algorithms, dependencies, features or signing semantics.

Current source-equivalence check: **41 files matched, zero mismatches** against
the recovery HEAD after explicit path substitutions and rustfmt normalization.
This includes all eight files moved in this portion and the other audit-owned
source/test files, excluding `mod.rs` and the three separately owned files.
The comparison includes comments, strings and tests; it does not strip bodies.
Allowed substitutions:

- `crate::supervisor::audit::` → `crate::audit::`.
- `pub(in crate::supervisor::audit)` → `pub(in crate::audit)`.
- Flattened file-signer/verifier/rotation names → `audit::audit_file`.
- Flattened signer/entry/envelope/entry-constructor names → `audit::signer`.
- Mixed test imports split between `audit_file` and `signer`.

The recovered compatibility test is an exact match, modulo rustfmt, to the
archived Add patch and its subsequent `emit_mirror_event` correction.
It tests module/flattened type identities, trait-object assignment in both
directions, alternating appends to one chain, verification from both namespaces,
and wrong-key refusal.

Current checks are source comparison, scoped rustfmt and diff hygiene only.
No current cargo compilation, tests, clippy, gated target checks, `check-all`
or live backend checks were run in this isolated portion. Integration owns
those checks after the separately owned file/checkpoint moves and emitter
changes are combined. The temporary missing module targets are not a claimed
compiling result. No commit or push was performed.

## Historical implementation and review

The following evidence is recovered from the archived implementation report
patches. **It describes the historical checkout, not this recovery revision.**

The original relocation moved ten complete files for eight modules, with
supervisor reexports rather than wrappers. All audit-owned references used
canonical audit paths. The original normalized comparison recorded **44 matches,
zero mismatches**, including the file/checkpoint/emitter files excluded from
the current isolated portion. Supervisor flattened exports, frozen fixtures
and manifests were recorded unchanged.

A historical independent source-only review reported no blocking findings
after comparing the ten moved files, audit imports, visibility, legacy facade
and shared-chain test. It ran no independent builds. This is not a fresh review
of the recovery.

Runtime resource ownership was unchanged: the trusted host supplies signing
authority; the file signer serializes append/rotation with its sidecar lock;
callers own durability waits; Drop best-effort flushes deferred entries;
endpoint startup owns registration; the bound sink owns epoch-local health.
Expired weak bindings refuse rather than falling back to unbound recording.
No new backend isolation or malicious-host guarantee is claimed.

## Historical validation environment and baseline

The historical host was macOS with an isolated target directory. Build shells
sourced `scripts/dev-env.sh`, set `TMPDIR=/tmp`, and reused the existing registry
with `CARGO_HOME="$HOME/.cargo" MVM_DEV_ENV_KEEP_INHERITED=1`. Baseline/scoped
Cargo commands used `--offline`. Long checks ran in background jobs; Git reads
ran from the central checkout with `-C` selecting the isolated checkout.

| Historical exact command | Archived result |
| --- | --- |
| `cargo test --offline -p mvm-hostd --lib supervisor::audit` | 138 passed before relocation |
| `cargo test --offline -p mvm-hostd --test audit_chain_frozen_bytes --test audit_chain_rotation --test audit_chain_prune --test audit_prune_pins --test audit_verify_incremental --test audit_chain_spine --test audit_chain_concurrent_writers` | 61 passed: 6 frozen bytes, 19 rotation, 10 prune, 13 prune pins, 10 incremental, 2 spine, 1 concurrent writers |
| `cargo test --offline -p mvm-hostd --lib audit::` | 441 passed, zero ignored after correction |
| `cargo test --offline -p mvm-hostd --test audit_chain_compat --test audit_chain_frozen_bytes --test audit_chain_rotation --test audit_chain_prune --test audit_prune_pins --test audit_verify_incremental --test audit_chain_spine --test audit_chain_concurrent_writers` | 63 passed: 61 original and 2 compatibility; zero ignored |
| `cargo test --offline -p mvm-hostd --test network_endpoint_bin audit` | 3 passed; missing binding/key refused before readiness; 20 fresh endpoint sessions recorded bound denials |
| `cargo clippy --offline -p mvm-hostd --all-targets -- -D warnings` | Passed |

Historical witnesses included deterministic signing bytes, barrier/deferred
behavior, batching/Drop, sidecar flock, torn-tail refusal, rotation/recovery,
prune pins, retirement refusal after failed append/fsync and bound-sink expiry.
The library run specifically passed
`actual_audit_append_and_fsync_failure_never_authorize_unlink`,
`staged_recovery_retries_after_seal_append_fsync_failure_without_duplicate`,
and `assembled_async_consumers_share_binding_and_never_fall_back_after_sink_expiry`.

## Historical failure journal and broad gates

The initial historical nested `Move to` operations reported success while
leaving `audit_recorder/bound.rs` and `bound_sink/tests.rs` at the old location.
Rustfmt could not resolve the child module; the initial library/integration/
endpoint/clippy batch failed to compile. Exact-content Add/Delete operations
corrected the two children; equivalence checking then confirmed no source loss.
The same nested-move issue occurred during recovery and was corrected with
Add/Delete before the current 41-file comparison.

Historical broad checks ran serially with `CARGO_NET_OFFLINE=true`:

| Historical exact command | Archived result |
| --- | --- |
| `cargo check --workspace` | Passed |
| `cargo test --workspace` | Failed in xtask's `check_private_mvm_dirs::tests::passes_on_this_workspace`; that binary reported 1,071 passed / 1 failed. Full workspace was not green. |
| `cargo clippy --workspace -- -D warnings` | Passed |
| `just check::gated` | Passed: Linux x86_64 all-targets cross-check and feature-gated conformance check |
| `cargo run -p xtask -- check-all` | Incomplete: footprint check failed on unstaged moved files, then stopped when schema generation invoked non-Cargo uv/npm dependency resolution |
| `cargo run -p xtask -- check-rust-footprint` | Passed with a temporary Git index containing scoped moves/new files; real index unchanged; ratchet measurement-only/suspended |
| `cargo fmt --all -- --check` | Passed separately after stopping check-all |

The historical private-directory gate watched `src/audit` and scanned test
bodies too. Relocation exposed existing `create_dir_all` calls at historical
`audit_checkpoint.rs:56`, `audit_file.rs:280,311,1008,1905`,
`audit_mirror.rs:209`, and `transcript_sink.rs:146`. This was a
relocation-triggered failure, not a green result to ignore. Directory behavior
and gate corrections required separate review; they are not silently folded
into this mechanical source-equivalence claim.

The footprint gate enumerated Git-index paths and read files from disk.
Unstaged moves left removed old paths in the index and omitted new paths.
The historical temporary-index follow-up used `read-tree HEAD` and only
authorized paths, recording 2,892 files / 1,272,165 physical lines /
1,002,476 SLOC. Those are historical measurements, not current counts.

Cargo offline mode did not govern check-all's uv/npm children. Historical
output showed dependency resolution and a cached Python generator; the job
was stopped when that activity was discovered. No complete check-all pass,
fully offline non-Cargo run, live backend, Linux syscall or hardware witness
is implied by these historical results.
