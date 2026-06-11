# AuditEmitter library hoist — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `AuditEmitter` + the host-keypair loader + plan persistence + new pure checkpoint bind helpers from `mvm-cli` into `mvm_hostd::audit`, so library consumers (mvmd) can drive chain-signed checkpoint/audit binding — with re-export shims keeping the ~100 `mvm-cli` call sites untouched.

**Architecture:** A new `mvm_hostd::audit` module group reusing `mvm-hostd`'s own audit core (`supervisor::{AuditEntry, FileAuditSigner, verify_audit_chain}`). `mvm-cli`'s old module files become `pub use` shims. One decouple: `emit_oci_provenance` takes pre-computed labels instead of the `mvm-cli` `OciProvenance` type. Pure refactor — no behavior change.

**Tech Stack:** Rust 2024; `mvm-hostd` already has `anyhow`/`ed25519-dalek`/`rand`/`serde_json`/`chrono`/`tokio` (no Cargo.toml changes for deps).

**Design doc:** `specs/notes/audit-emitter-hoist-design.md`
**Worktree:** `../mvm-audit-hoist` (branch `feat/audit-emitter-hoist`).

**Standing rules:** no `Co-Authored-By` trailer; no spec/PR/plan refs in code comments; `cargo fmt --all`; clippy `-D warnings`; reuse-first. `mvm-backend` SIGKILLs under nextest on this macOS host — use plain `cargo test` for targeted runs; known `HOME_TEST_LOCK`/fs2-flock parallel flakes pass single-threaded.

**Ordering note:** the `emit_oci_provenance` decouple (Task 3) MUST precede the `audit_chain` move (Task 4) — `audit_chain` can't move while it imports the `mvm-cli` `OciProvenance` type.

---

## File Structure

| File | Change |
|------|--------|
| `crates/mvm-hostd/src/audit/mod.rs` *(create)* | `pub mod emitter; pub mod host_keypair; pub mod plan_persist; pub mod bind;` |
| `crates/mvm-hostd/src/audit/plan_persist.rs` *(create, moved)* | verbatim from mvm-cli |
| `crates/mvm-hostd/src/audit/host_keypair.rs` *(create, moved+renamed)* | from mvm-cli `host_signer.rs` |
| `crates/mvm-hostd/src/audit/emitter.rs` *(create, moved)* | from mvm-cli `audit_chain.rs`, imports repointed |
| `crates/mvm-hostd/src/audit/bind.rs` *(create)* | new pure `bind_checkpoint_*` helpers |
| `crates/mvm-hostd/src/lib.rs` *(modify)* | add `pub mod audit;` |
| `crates/mvm-cli/src/commands/vm/plan_persist.rs` *(replace with shim)* | `pub use mvm_hostd::audit::plan_persist::*;` |
| `crates/mvm-cli/src/commands/vm/host_signer.rs` *(replace with shim)* | `pub use mvm_hostd::audit::host_keypair::*;` |
| `crates/mvm-cli/src/commands/vm/audit_chain.rs` *(replace with shim)* | `pub use mvm_hostd::audit::emitter::*;` |
| `crates/mvm-cli/src/commands/image.rs` *(modify)* | (no move) — call site passes `audit_labels()` |
| `crates/mvm-cli/src/commands/vm/exec.rs` *(modify)* | `emit_oci_provenance` call site |
| `crates/mvm-cli/src/commands/vm/checkpoint.rs` *(modify)* | `bind_*` wrappers delegate to lib |

---

## Task 1: Move `plan_persist` into `mvm_hostd::audit`

The cleanest module (no `crate::commands::` imports). Establishes the `audit/` group + the shim pattern.

**Files:**
- Create: `crates/mvm-hostd/src/audit/mod.rs`, `crates/mvm-hostd/src/audit/plan_persist.rs`
- Modify: `crates/mvm-hostd/src/lib.rs`
- Replace: `crates/mvm-cli/src/commands/vm/plan_persist.rs` (→ shim)

- [ ] **Step 1: Move the file.**
```bash
cd /Users/auser/work/tinylabs/mvmco/mvm-audit-hoist
mkdir -p crates/mvm-hostd/src/audit
git mv crates/mvm-cli/src/commands/vm/plan_persist.rs crates/mvm-hostd/src/audit/plan_persist.rs
```

- [ ] **Step 2: Create `crates/mvm-hostd/src/audit/mod.rs`:**
```rust
//! Host-side audit binding: the chain-signed `AuditEmitter`, the host signing
//! keypair, plan persistence, and the checkpoint bind helpers. Library API so
//! both the CLI and fleet consumers emit identical chain entries.

pub mod bind;
pub mod emitter;
pub mod host_keypair;
pub mod plan_persist;
```
(`bind`/`emitter`/`host_keypair` modules are created in later tasks; for this task, temporarily declare ONLY `pub mod plan_persist;` so it compiles, and add the others as their tasks land. Replace the body above with just `pub mod plan_persist;` for now.)

- [ ] **Step 3: Register in `crates/mvm-hostd/src/lib.rs`** — add `pub mod audit;` among the existing `pub mod` lines (alphabetical: after `audit_signer`).

- [ ] **Step 4: The moved `plan_persist.rs` needs no import changes** (its imports are `anyhow`, `mvm_core::plan::ExecutionPlan`, `std::*`, `serde_json` — all available in mvm-hostd). Confirm it compiles:
```bash
cargo build -p mvm-hostd 2>&1 | tail -5
```

- [ ] **Step 5: Replace the mvm-cli file with a shim** — `crates/mvm-cli/src/commands/vm/plan_persist.rs`:
```rust
//! Re-export shim: plan persistence now lives in `mvm_hostd::audit::plan_persist`.
pub use mvm_hostd::audit::plan_persist::*;
```
The `mod.rs` declaration (`pub(super) mod plan_persist;`) stays — it now points at the shim file.

- [ ] **Step 6: Verify both crates** (the moved tests run under mvm-hostd now):
```bash
cargo test -p mvm-hostd --lib plan_persist 2>&1 | grep -E "test result: (ok|FAILED)"
cargo build -p mvm-cli 2>&1 | tail -3
cargo clippy -p mvm-hostd -p mvm-cli -- -D warnings 2>&1 | tail -5
```
Expected: plan_persist tests pass in mvm-hostd; mvm-cli builds via the shim; zero warnings.

- [ ] **Step 7: Commit**
```bash
git add -A && git commit -m "refactor(audit): move plan_persist into mvm_hostd::audit with cli shim"
```

---

## Task 2: Move `host_signer` → `mvm_hostd::audit::host_keypair`

**Files:**
- Create: `crates/mvm-hostd/src/audit/host_keypair.rs` (moved + test fix)
- Modify: `crates/mvm-hostd/src/audit/mod.rs` (add `pub mod host_keypair;`)
- Replace: `crates/mvm-cli/src/commands/vm/host_signer.rs` (→ shim)

- [ ] **Step 1: Move the file** (renamed to dodge the existing top-level `mvm_hostd::host_signer` subprocess module — nesting under `audit::host_keypair` avoids any collision):
```bash
git mv crates/mvm-cli/src/commands/vm/host_signer.rs crates/mvm-hostd/src/audit/host_keypair.rs
```
Add `pub mod host_keypair;` to `audit/mod.rs`.

- [ ] **Step 2: Fix the one mvm-cli-internal test dependency.** The moved file's `#[cfg(test)]` module imports `use super::super::plan_builder::{SynthesisInput, synthesize_plan};` (mvm-cli-only) and uses `synthesize_plan()` to get a plan to sign/verify. That won't compile in mvm-hostd. REPLACE that test's plan construction with a local fixture. Read the moved file's test module; find the test using `synthesize_plan` (it signs a plan with the host key then verifies). Replace the `synthesize_plan(...)` call with a minimal `ExecutionPlan` fixture — copy the `fixture_plan` helper from `crates/mvm-hostd/src/audit/plan_persist.rs`'s test module (it builds a full `ExecutionPlan` with `chrono::Utc::now()`), or from the soon-to-move `emitter.rs` tests. Remove the `use super::super::plan_builder::...` import. The test's INTENT (sign with host key → verify_plan succeeds) is preserved; only the plan source changes.

- [ ] **Step 3: Production code needs no import changes** (host_keypair's prod imports are `anyhow`, `ed25519_dalek`, `rand`, `std::*`, `mvm_core::config` — all in mvm-hostd). Build:
```bash
cargo build -p mvm-hostd 2>&1 | tail -5
```

- [ ] **Step 4: Replace the mvm-cli file with a shim** — `crates/mvm-cli/src/commands/vm/host_signer.rs`:
```rust
//! Re-export shim: the host signing keypair now lives in
//! `mvm_hostd::audit::host_keypair`. The `host_signer` path here is preserved so
//! existing call sites compile unchanged.
pub use mvm_hostd::audit::host_keypair::*;
```

- [ ] **Step 5: Verify** (the `*` glob re-exports `load_or_init`, `load_or_init_at`, `host_signer_id`, `default_keys_dir`, `HostSigner`, `SECRET_FILENAME`, `PUBLIC_FILENAME`, `KEY_BYTES`, etc. — every call site like `host_signer::KEY_BYTES` resolves):
```bash
cargo test -p mvm-hostd --lib host_keypair 2>&1 | grep -E "test result: (ok|FAILED)"
cargo build -p mvm-cli 2>&1 | tail -3
cargo clippy -p mvm-hostd -p mvm-cli -- -D warnings 2>&1 | tail -5
```
Expected: host_keypair tests pass; mvm-cli builds (the ~12 `host_signer::` call sites resolve through the shim).

- [ ] **Step 6: Commit**
```bash
git add -A && git commit -m "refactor(audit): move host signer keypair into mvm_hostd::audit::host_keypair with cli shim"
```

---

## Task 3: Decouple `emit_oci_provenance` from the CLI `OciProvenance` type

Must land BEFORE moving `audit_chain` (Task 4). `OciProvenance` already has `audit_labels() -> Vec<(String,String)>`, so this is a thin signature change.

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/audit_chain.rs` (the method — still in mvm-cli at this point)
- Modify: `crates/mvm-cli/src/commands/vm/exec.rs` (the call site)

- [ ] **Step 1: Change the method signature.** In `audit_chain.rs`, replace `emit_oci_provenance`:
```rust
    /// Emit `plan.oci_provenance` — binds an OCI image admission to the same
    /// plan id as the launch decision. The caller supplies the digest-oriented
    /// labels; raw registry credentials are never recorded.
    pub fn emit_oci_provenance(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "plan.oci_provenance", labels)
    }
```
Remove `use crate::commands::image::OciProvenance;` (line 46) — it's no longer referenced.

- [ ] **Step 2: Update the call site** in `crates/mvm-cli/src/commands/vm/exec.rs` (~line 562):
```rust
    emitter.emit_oci_provenance(&admitted.plan, image.provenance.audit_labels())?;
```
(`audit_labels()` already returns `Vec<(String,String)>`; it's `pub(in crate::commands)` so reachable from `exec.rs`.)

- [ ] **Step 3: Verify** (no behavior change — the same labels are emitted; existing audit tests + the OCI provenance CI lane cover it):
```bash
cargo build -p mvm-cli 2>&1 | tail -3
cargo test -p mvm-cli --lib audit_chain 2>&1 | grep -E "test result: (ok|FAILED)"
cargo clippy -p mvm-cli -- -D warnings 2>&1 | tail -5
```
Confirm `OciProvenance` no longer appears in `audit_chain.rs`: `rg -n "OciProvenance" crates/mvm-cli/src/commands/vm/audit_chain.rs` → zero hits.

- [ ] **Step 4: Commit**
```bash
git add -A && git commit -m "refactor(audit): emit_oci_provenance takes labels, decoupled from the CLI type"
```

---

## Task 4: Move `audit_chain` → `mvm_hostd::audit::emitter`

The big one — but the shim keeps the ~100 call sites unchanged.

**Files:**
- Create: `crates/mvm-hostd/src/audit/emitter.rs` (moved, imports repointed)
- Modify: `crates/mvm-hostd/src/audit/mod.rs` (add `pub mod emitter;`)
- Replace: `crates/mvm-cli/src/commands/vm/audit_chain.rs` (→ shim)

- [ ] **Step 1: Move the file.**
```bash
git mv crates/mvm-cli/src/commands/vm/audit_chain.rs crates/mvm-hostd/src/audit/emitter.rs
```
Add `pub mod emitter;` to `audit/mod.rs`.

- [ ] **Step 2: Repoint the imports** in `emitter.rs`. Change the two `mvm_hostd::supervisor::...` imports to `crate::supervisor::...`:
  - prod import (was line 44): `use crate::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};`
  - test import (was line 333): `use crate::supervisor::verify_audit_chain;`
  - The `use crate::commands::image::OciProvenance;` line was already removed in Task 3.
  - All other imports (`anyhow`, `ed25519_dalek`, `mvm_core::plan`, `mvm_core::policy`, `tokio`, `serde_json`, `std::*`, `rand` in tests, `chrono` via fixture) are available in mvm-hostd.

- [ ] **Step 3: Build mvm-hostd:**
```bash
cargo build -p mvm-hostd 2>&1 | tail -8
```
Expected: clean (the emitter + its tests compile against `crate::supervisor`).

- [ ] **Step 4: Replace the mvm-cli file with a shim** — `crates/mvm-cli/src/commands/vm/audit_chain.rs`:
```rust
//! Re-export shim: the chain-signed `AuditEmitter` now lives in
//! `mvm_hostd::audit::emitter`.
pub use mvm_hostd::audit::emitter::*;
```

- [ ] **Step 5: Verify the whole CLI builds through the shim** (this is the real test — `up.rs`/`pause.rs`/`exec.rs`/`cmd_audit.rs`/`ops/*` all use `audit_chain::{AuditEmitter, default_audit_dir, SnapshotChainMatch, audit_path_for_tenant, find_snapshot_saved_sha}`):
```bash
cargo build -p mvm-cli 2>&1 | tail -8
cargo test -p mvm-hostd --lib audit::emitter 2>&1 | grep -E "test result: (ok|FAILED)"
cargo clippy -p mvm-hostd -p mvm-cli -- -D warnings 2>&1 | tail -8
```
Expected: mvm-cli builds; emitter tests pass in mvm-hostd; zero warnings. If any mvm-cli call site fails to resolve, the `*` glob missed a non-`pub` item — make that item `pub` in the moved `emitter.rs` (the original was `pub fn`/`pub struct`, so this should not occur).

- [ ] **Step 6: Commit**
```bash
git add -A && git commit -m "refactor(audit): move AuditEmitter into mvm_hostd::audit::emitter with cli shim"
```

---

## Task 5: Add pure `bind_checkpoint_*` helpers + delegate the CLI wrappers

**Files:**
- Create: `crates/mvm-hostd/src/audit/bind.rs`
- Modify: `crates/mvm-hostd/src/audit/mod.rs` (add `pub mod bind;`)
- Modify: `crates/mvm-cli/src/commands/vm/checkpoint.rs` (delegate the wrappers)

- [ ] **Step 1: Write the failing test** — create `crates/mvm-hostd/src/audit/bind.rs` with ONLY the test module first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::emitter::AuditEmitter;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};
    use rand::rngs::OsRng;

    // Reuse the emitter test's plan fixture shape. A minimal admitted plan is
    // enough for the audit entry; copy `fixture_plan` from the emitter tests.
    fn fixture_plan(tenant: &str, plan_id: &str) -> mvm_core::plan::ExecutionPlan {
        crate::audit::emitter::tests_support_fixture_plan(tenant, plan_id)
    }

    fn vm_full_meta(id: &str, vm: &str) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::VmFull, vm)
            .content(vec![ContentBlob { name: "rootfs.ext4".into(), sha256: "abcd".into() }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build()
    }

    #[test]
    fn bind_created_emits_a_verifiable_entry() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-B");
        let meta = vm_full_meta("ckpt-1", "myvm");
        bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("vm_full"));   // class derived from meta
        assert!(content.contains("abcd"));        // content hash from meta.content.first()
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
}
```
**Note for the implementer:** the test calls `crate::audit::emitter::tests_support_fixture_plan` — the emitter test module's `fixture_plan` is `#[cfg(test)]`-private. EITHER (a) add a `#[cfg(test)] pub(crate) fn tests_support_fixture_plan(...)` in `emitter.rs` exposing the existing fixture, OR (b) inline a local `fixture_plan` in `bind.rs`'s test (copy the body from `emitter.rs`'s test fixture). Pick (b) if simpler — just duplicate the small fixture in the test module. Adjust the test accordingly.

Run `cargo test -p mvm-hostd --lib audit::bind 2>&1 | tail -10` → fails (bind fns absent).

- [ ] **Step 2: Implement `bind.rs`** (prepend above the test module):
```rust
//! Pure checkpoint audit-binding helpers. The caller supplies the emitter +
//! the admitted plan + the checkpoint metadata; these extract the labels and
//! emit. Error policy (best-effort vs fatal) belongs to the caller.

use anyhow::Result;
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;

/// Stable on-the-wire string for a checkpoint class.
pub fn class_str(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::FsQuick => "fs_quick",
        CheckpointClass::VmFull => "vm_full",
    }
}

/// Emit `checkpoint.created` for a freshly captured checkpoint.
pub fn bind_checkpoint_created(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
) -> Result<()> {
    let content_sha = meta.content.first().map(|b| b.sha256.as_str()).unwrap_or("");
    emitter.emit_checkpoint_created(
        plan,
        meta.id.as_str(),
        class_str(meta.class),
        content_sha,
        &meta.vm_name,
    )
}

/// Emit `checkpoint.restored` for a same-identity resume.
pub fn bind_checkpoint_restored(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
) -> Result<()> {
    emitter.emit_checkpoint_restored(plan, meta.id.as_str(), &meta.vm_name)
}

/// Emit `checkpoint.forked` recording the parent→child lineage.
pub fn bind_checkpoint_forked(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    parent: &CheckpointId,
    child: &CheckpointMeta,
    child_vm_name: &str,
) -> Result<()> {
    emitter.emit_checkpoint_forked(plan, parent.as_str(), child.id.as_str(), child_vm_name)
}
```
Add `pub mod bind;` to `audit/mod.rs`. Run the test → green.

- [ ] **Step 3: Delegate the CLI wrappers** in `crates/mvm-cli/src/commands/vm/checkpoint.rs`. The three `bind_checkpoint_*` functions keep their read-plan/load-signer/policy logic but replace the inline `emitter.emit_checkpoint_*(...)` + the local `checkpoint_class_str` with calls to the library helpers. Example for `bind_checkpoint_created`:
```rust
pub(crate) fn bind_checkpoint_created(name: &str, meta: &mvm_core::checkpoint::CheckpointMeta) {
    let plan = match super::plan_persist::read_plan(name) {
        Ok(p) => p,
        Err(e) => { tracing::warn!(error = %e, vm = name,
            "no persisted plan; checkpoint.created emitted without chain binding"); return; }
    };
    let signer = match super::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => { tracing::warn!(error = %e, "host signer unavailable; chain entry skipped"); return; }
    };
    let emitter = match super::audit_chain::AuditEmitter::new(signer.signing) {
        Ok(e) => e,
        Err(e) => { tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped"); return; }
    };
    if let Err(e) = mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, meta) {
        tracing::warn!(error = %e, "audit emit_checkpoint_created failed (non-fatal)");
    }
}
```
Do the same for `bind_checkpoint_restored` (delegate to `mvm_hostd::audit::bind::bind_checkpoint_restored(&emitter, &plan, meta)` — note the lib helper takes the full `meta`, so the CLI wrapper must be passed the meta; today `bind_checkpoint_restored(vm_name, checkpoint_id)` only has the id — change its signature to take `meta: &CheckpointMeta` and update its one caller in `checkpoint.rs::restore` to pass `&meta` which it already reads via `store.read_meta`). For `bind_checkpoint_forked`, keep the parent-plan fallback + fatal `?` policy, delegating the emit to `mvm_hostd::audit::bind::bind_checkpoint_forked(&emitter, &plan, parent, child, child_vm_name)`. DELETE the now-unused local `checkpoint_class_str` (the lib's `class_str` replaces it) — if `checkpoint_class_str` is still used elsewhere (e.g. `ls`), keep it or repoint to `mvm_hostd::audit::bind::class_str`.

- [ ] **Step 4: Verify:**
```bash
cargo test -p mvm-hostd --lib audit::bind 2>&1 | grep -E "test result: (ok|FAILED)"
cargo test -p mvm-cli --lib checkpoint 2>&1 | grep -E "test result: (ok|FAILED)"
cargo build -p mvm-cli 2>&1 | tail -3
cargo clippy -p mvm-hostd -p mvm-cli -- -D warnings 2>&1 | tail -8
```
Expected: lib bind test passes; CLI checkpoint tests pass; zero warnings.

- [ ] **Step 5: Commit**
```bash
git add -A && git commit -m "feat(audit): pure checkpoint bind helpers in mvm_hostd; CLI wrappers delegate"
```

---

## Task 6: Full gates + rollup + PR

- [ ] **Step 1: Workspace gates.**
```bash
cargo fmt --all && cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
cargo nextest run --workspace -E 'not package(mvm-backend)' 2>&1 | tail -20
cargo test -p mvm-backend checkpoint:: 2>&1 | tail -6   # plain cargo test (nextest SIGKILLs mvm-backend here)
cargo test --workspace --doc 2>&1 | tail -10
```
Fix any REAL failure in the moved code. The audit/host_signer/plan_persist tests now live in mvm-hostd — confirm they pass there. Known `HOME_TEST_LOCK`/fs2-flock flakes pass single-threaded; confirm, don't chase.

- [ ] **Step 2: Sanity-grep the hoist.**
```bash
rg -n "OciProvenance" crates/mvm-hostd/src/audit/   # zero hits (decoupled)
rg -n "mvm_cli|crate::commands" crates/mvm-hostd/src/audit/  # zero hits (no upward dep)
```

- [ ] **Step 3: Update `specs/REFACTOR-STATUS.md`** — under PLAN 159, mark the AuditEmitter library-hoist follow-up done (it was tracked as the next item after PR2). Add a short line, e.g. under the WS-2 entry or a follow-ups note: `AuditEmitter/host_keypair/plan_persist + pure checkpoint bind helpers hoisted to mvm_hostd::audit (mvmd-reachable); CLI shimmed`. Bump `**Last updated:**` to 2026-06-11. Don't touch other plans.

- [ ] **Step 4: Commit + push + open PR** (the controller runs the final review + finishing-a-development-branch).
```bash
git add -A && git commit -m "docs(refactor-status): AuditEmitter library hoist landed"
```

---

## Notes for the implementer
- This is a **pure relocation + one decouple** — there must be NO behavior change. The proof is: the moved modules' own tests pass in mvm-hostd, and `mvm-cli` builds + its audit/checkpoint/snapshot tests pass through the shims.
- The shims are `pub use …::*;` — if a call site fails to resolve after a move, the cause is a non-`pub` item the glob didn't carry; make it `pub` in the moved module (all the originals were already `pub`).
- Keep the CLI's error policy (best-effort warn for created/restored, fatal for forked) in the CLI wrappers; the library helpers are pure emit.
- No `Co-Authored-By`; no plan/PR refs in code comments.
