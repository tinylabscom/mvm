# AuditEmitter library hoist — design

**Date:** 2026-06-11
**Status:** design approved; ready for implementation-plan authoring
**Why:** Closes the audit-binding gap from Plan 159 WS-2 PR2 (option b). The
checkpoint *operations* are already library API in `mvm-backend::checkpoint`,
reachable by `mvmd`. The *audit binding* (host signer + plan + `emit_*`) still
lives in `mvm-cli` (a binary crate `mvmd` cannot consume). This hoists the
binding into a library crate so `mvmd`-driven checkpoints emit identical
chain-signed `checkpoint.*` events.

## Goal

Move `AuditEmitter` + the host-keypair loader + plan persistence + the
checkpoint bind helpers out of `mvm-cli` into `mvm-hostd`, behind a clean
`pub` surface, with **zero behavior change** and **zero churn** to the ~100
existing `mvm-cli` call sites (via re-export shims).

## Why `mvm-hostd` is the home

- `AuditEmitter` is a thin tokio-runtime wrapper around `mvm-hostd`'s **own**
  audit core: `supervisor::{AuditEntry, AuditSigner, FileAuditSigner,
  verify_audit_chain}` (already `pub`-re-exported from `mvm-hostd`).
- `mvm-hostd` already carries full (non-optional) `tokio`; `AuditEmitter::emit`
  builds a current-thread runtime per call, so it cannot live in the
  runtime-free `mvm-core`.
- **Cycle-free:** `mvm-cli` already depends on `mvm-hostd`; nothing depends on
  `mvm-cli`. `mvm-hostd` depends only on `mvm-core`/`mvm-backend`/… — moving
  these modules up into `mvm-hostd` introduces no cycle.
- `mvmd` already depends on `mvm-hostd` (consumes `mvmctl::*` facades), so the
  hoisted surface becomes reachable with no new dependency.

## Architecture

A new module group **`mvm_hostd::audit`** (top-level in `mvm-hostd`, distinct
from the supervisor-internal audit core it reuses). `mvm-cli` keeps thin
`pub use mvm_hostd::audit::…` re-export shims at the old paths
(`commands/vm/audit_chain.rs`, `host_signer.rs`, `plan_persist.rs` become
re-export modules) so every existing call site compiles unchanged.

### New module layout: `crates/mvm-hostd/src/audit/`

- **`emitter.rs`** — `AuditEmitter` (+ every `emit_*`: `admitted`, `launched`,
  `policy_resolved`, `shares_admitted`, `oci_provenance`, `vm_snapshot_*`,
  `exited`, `failed`, `checkpoint_*`), `default_audit_dir`,
  `audit_path_for_tenant`, `find_snapshot_saved_sha`, `SnapshotChainMatch`.
  Verbatim move from `mvm-cli/commands/vm/audit_chain.rs`, repointing
  `mvm_hostd::supervisor::…` imports to `crate::supervisor::…`.
- **`host_keypair.rs`** — the host Ed25519 keypair file manager (`load_or_init`,
  `load_or_init_at`, `host_signer_id`, `default_keys_dir`, `HostSigner`,
  the filename/mode consts). Moved from `mvm-cli/commands/vm/host_signer.rs`,
  **renamed `host_signer` → `host_keypair`** to avoid colliding with the
  existing `mvm_hostd::host_signer/` module (the per-VM signing *subprocess*
  moat — a different concern: in-memory OsRng key + RPC server).
- **`plan_persist.rs`** — `read_plan`/`write_plan`/`plan_path`/`vm_state_dir`
  (`~/.mvm/vms/<vm>/plan.json`, mode 0600, atomic write). Verbatim move.
- **`bind.rs`** — the **pure** checkpoint bind helpers (see below).

`mvm-hostd/src/lib.rs` adds `pub mod audit;`.

### The two-layer bind split (the key design point)

- **Library layer (`mvm_hostd::audit::bind`)** — pure, caller-supplied
  dependencies, no I/O policy:
  ```
  pub fn bind_checkpoint_created(emitter: &AuditEmitter, plan: &ExecutionPlan, meta: &CheckpointMeta) -> Result<()>
  pub fn bind_checkpoint_restored(emitter: &AuditEmitter, plan: &ExecutionPlan, meta: &CheckpointMeta) -> Result<()>
  pub fn bind_checkpoint_forked(emitter: &AuditEmitter, plan: &ExecutionPlan, parent: &CheckpointId, child: &CheckpointMeta) -> Result<()>
  ```
  Each extracts the labels from the `CheckpointMeta` (class string via a small
  `class_str(CheckpointClass)`; the content hash from `meta.content.first()`;
  lineage ids) and calls the matching `emitter.emit_checkpoint_*`. This is the
  one-call API `mvmd` uses: it supplies its own `AuditEmitter` + `ExecutionPlan`
  + `CheckpointMeta` and chooses its own error policy.
- **CLI policy layer (`mvm-cli`, stays)** — the existing
  `bind_checkpoint_{created,restored,forked}(vm_name, meta)` wrappers keep their
  current behavior: best-effort warn-and-continue for create/restore,
  fatal-on-signing-error for fork, and the read-from-`~/.mvm` plan/signer
  loading (`plan_persist::read_plan` + `host_keypair::load_or_init` +
  `AuditEmitter::new`). They now delegate the actual emit to the library's pure
  `bind_checkpoint_*`. So CLI UX policy stays in the CLI; the reusable
  composition lives in the library.

## The one decoupling: `emit_oci_provenance`

`emit_oci_provenance` currently takes `crate::commands::image::OciProvenance`
— an `mvm-cli` type that cannot follow `AuditEmitter` into `mvm-hostd`. Resolve
by **decoupling**: change the method signature to take the provenance fields as
primitives (matching how every other `emit_*` takes plain args), e.g.
`emit_oci_provenance(&self, plan, registry_host, repo, reference, manifest_digest, layer_digests: &[String], trust_policy, cosign_verdict)`. The single CLI
call site (`commands/vm/exec.rs`) maps its `OciProvenance` struct → those args.
(Rejected alternative: moving `OciProvenance` to `mvm-oci` — more churn, and the
emitter only needs the flat label values.)

## Re-export shims (blast-radius containment)

The ~11 `mvm-cli` files / ~100 call sites that use `audit_chain::`,
`host_signer::`, `plan_persist::` keep compiling because the old module files
become re-exports:
- `commands/vm/audit_chain.rs` → `pub use mvm_hostd::audit::emitter::*;`
- `commands/vm/host_signer.rs` → `pub use mvm_hostd::audit::host_keypair::*;`
  (the shim preserves the old `host_signer` path even though the lib module is
  `host_keypair`, so call sites like `host_signer::load_or_init()` are
  unchanged).
- `commands/vm/plan_persist.rs` → `pub use mvm_hostd::audit::plan_persist::*;`

The only non-shim CLI edits: the `exec.rs` `emit_oci_provenance` call site
(decoupled args), and the checkpoint `bind_*` wrappers delegating to the library
pure helpers.

## Error handling / testing

- **No behavior change** — pure relocation + the one decouple. The existing
  unit tests for `AuditEmitter`, `host_signer`, `plan_persist` move with their
  modules and run under `mvm-hostd`.
- Add one `mvm-hostd` test exercising a `bind_checkpoint_*` pure helper
  end-to-end: build an `AuditEmitter::with_dir`, call `bind_checkpoint_created`,
  assert the `checkpoint.created` entry lands and `verify_audit_chain` passes.
- `mvm-cli`'s `audit_total_coverage` + checkpoint + snapshot tests stay green
  via the shims; the CLI `bind_*` policy wrappers keep their existing tests.
- Gate: `cargo xtask check-core-runtime-free` is unaffected (nothing moves into
  `mvm-core`); `mvm-hostd` already has tokio.

## Scope guard (YAGNI)

This is a **pure refactor + the `emit_oci_provenance` decouple**. Explicitly
out of scope: any new audit semantics; the actual `mvmd`-side consumption (a
separate change in the `mvmd` repo); touching the existing
`mvm_hostd::host_signer/` subprocess. The deliverable is only: the audit
binding surface reachable as library API.

## Crate placement summary

| Module | From | To |
|--------|------|-----|
| `AuditEmitter` + `emit_*` + helpers | `mvm-cli/commands/vm/audit_chain.rs` | `mvm-hostd/src/audit/emitter.rs` |
| host keypair loader | `mvm-cli/commands/vm/host_signer.rs` | `mvm-hostd/src/audit/host_keypair.rs` |
| plan persistence | `mvm-cli/commands/vm/plan_persist.rs` | `mvm-hostd/src/audit/plan_persist.rs` |
| pure checkpoint bind helpers | (new) | `mvm-hostd/src/audit/bind.rs` |
| CLI `bind_*` policy wrappers | `mvm-cli/commands/vm/checkpoint.rs` | stay (delegate to lib) |
| re-export shims | — | `mvm-cli/commands/vm/{audit_chain,host_signer,plan_persist}.rs` |
