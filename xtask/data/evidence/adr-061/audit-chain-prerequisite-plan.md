# Audit-chain ownership prerequisite

Backing: preview
Validation: none

Historical source basis: `62603aeffe78be79728ef347204872ae0344fb79`.
Recovery source basis: `d7727419166b6ba7cfd47f603d523624f637318a`.
Design authority: accepted ADR-061, issue #5510, and explicit task approval
for this prerequisite only. This recovered plan preserves the archived scope;
its validation sequence is not evidence of checks on the recovery revision.

## Boundary

Move the eight chain implementation modules (`signer`, `audit_file`,
`audit_checkpoint`, `audit_recorder`, `audit_mirror`, `audit_dedup`,
`transcript_sink`, `bound_sink`) from `supervisor::audit` to `audit`.
Move the recorder's `bound` and bound sink's test submodules intact.
Keep public module reexports in `supervisor::audit`; the existing flattened
`supervisor` exports must resolve to the same concrete types and traits.
Canonicalize audit-owned references to these modules rather than referring
upward through supervisor aliases.

The direct journal operation remains restricted to the common owning audit
module: `pub(in crate::audit)`, not crate-wide or public. Moving the bound sink
with its recorder preserves this privacy boundary. No duplicate implementation,
wrapper, conversion, trait, manifest, feature or dependency is needed.

## Preserved contracts

This is Rust module ownership, not a runtime ownership or security upgrade.
The trusted host retains signing keys and chain authority; ADR-001's adversary
and backend claims remain unchanged. Preserve canonical bytes, event vocabulary,
barrier/deferred decisions, batching, Drop flush, per-chain sidecar flock,
cursor/torn-tail refusal, rotation recovery, prune pins, failed append/fsync
handling and expiry refusal. Existing tests and frozen fixtures remain intact.

Producer adapters (DNS, ICMP, gateway and secrets), endpoint registration,
native completion, stream vocabulary, the combined signer-helper process and
`audit_signer::Chain` are excluded. Existing unrelated higher edges are not a
reason to broaden this prerequisite. No mailbox implementation is included.

## Validation sequence

1. Run the original `supervisor::audit` library filter and frozen-byte,
   rotation, prune, prune-pin, incremental, spine and concurrent-writer tests.
2. Preserve each moved source, allowing only explicit module-path substitutions
   and the reviewed restricted visibility; declare modules at their new owner.
3. Add compile-time cross-path API/type/trait checks and append through both
   namespaces to a single chain, then verify through both.
4. Compare normalized sources with HEAD, admitting only enumerated path edits,
   declarations and documentation. Check unchanged adapters and out-of-scope files.
5. Run audit, endpoint binding, retirement and compatibility witnesses, hostd
   clippy, workspace check/test/clippy, `just check::gated` and
   `cargo run -p xtask -- check-all` serially where supported. Record failures
   and unavailable checks without weakening a gate.

Each build shell sources `scripts/dev-env.sh`; UDS fixtures use `TMPDIR=/tmp`.
The isolated target directory is retained; the existing Cargo registry may be
used through the supported inherited-environment override. Results belong in
the separate implementation report.

## Recovery integration boundary

The mechanical recovery owns six modules and their two child files, imports,
compatibility tests and this evidence. A separate change owns `audit_file.rs`,
`audit_checkpoint.rs`, `emitter.rs` and directory-policy corrections. Module
declarations may await those files during isolated recovery. Combined compilation,
tests and gates belong to integration; historical results below do not waive them.
