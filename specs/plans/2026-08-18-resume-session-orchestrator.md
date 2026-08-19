# Resume Session Orchestrator Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a parked session back into an admitted one — resolve and verify
its resume point, synthesize a fresh signed `ExecutionPlan`, admit it, and only
then transition the record.

**Architecture:** This lives in `mvm-hostd`, not `mvm-runtime`, and the crate
graph decides that: `mvm-hostd` depends on `mvm-runtime`, never the reverse, so
`mvm-hostd` is the lowest crate that can reach both `mvm_runtime::agent_session`
and its own `plan_admission::admit_for_run`. A resume is a *re-admission*: it
builds a new plan naming the session and its new generation rather than
inheriting the parent's. `AdmittedPlan` has only private fields and a test
pinning it as unfabricable outside `plan_admission`, so a resume goes through
admission rather than around it.

**Ordering is the load-bearing property:** admission runs BEFORE the record
transition. A refused admission leaves the session parked, resumable, and
unchanged — never half-resumed.

**Tech Stack:** Rust, `anyhow`, `tempfile`, `cargo nextest`.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` D5. Builds on the
substrate, park, and approval-head plans on this branch.

## Global Constraints

- **In every shell, including the one you commit from, put
  `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`
  in the SAME command as the cargo or git invocation.** The Bash tool does not
  persist exports. Do not point it elsewhere or create a fresh one — the shared
  default is corrupted by other concurrent sessions and costs an hour.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- `#[allow(clippy::too_many_arguments)]` is banned. Both entry points here take
  a params struct for that reason.
- No plan, PR, or ADR references in code comments — gated by
  `xtask check-no-spec-refs-in-comments`. Explain reasoning directly.
- Let the pre-commit hook run; a guard blocks any attempt to skip it.
- Gate before each commit: `cargo fmt --all -- --check`, then
  `cargo nextest run -p mvm-core -p mvm-runtime -p mvm-hostd`, then
  `cargo clippy --workspace --all-targets -- -D warnings`.

## What this plan does NOT do

It stops at an admitted plan. It does not start a backend, restore a memory
image, or send `PostRestore` — that is where the VM begins, and it needs a live
guest to test against. The deliverable: a parked session becomes a session
holding a fresh `AdmittedPlan` at generation+1, with its resume point verified.

## Interfaces produced by this plan

```rust
// mvm_hostd::session_resume
pub struct ResumePlanMaterial {
    pub backend_name: String,
    pub image_name: String,
    pub image_sha256: String,
    pub kernel_sha256: Option<String>,
    pub cpus: u8,
    pub mem_mib: u64,
}

pub struct ResumeRequest<'a> { /* see Task 2 */ }
pub struct ResumedSession { /* record + admitted plan */ }

pub fn synthesis_for_resume<'a>(
    record: &'a AgentSessionRecord,
    material: &'a ResumePlanMaterial,
) -> SynthesisInput<'a>;

pub fn resume_session(...) -> anyhow::Result<ResumedSession>;
```

---

### Task 1: `ResumePlanMaterial` and `synthesis_for_resume`

**Files:**
- Create: `crates/mvm-hostd/src/session_resume.rs`
- Modify: `crates/mvm-hostd/src/lib.rs` (add `pub mod session_resume;`, matching
  the file's existing ordering convention — check whether it is alphabetical
  before inserting)
- Test: inline `mod tests` in the new file

**Interfaces:**
- Consumes: `AgentSessionRecord` (mvm-runtime), `SynthesisInput` (mvm-core).
- Produces: `ResumePlanMaterial`, `synthesis_for_resume`.

**Why a material struct:** a session record knows the *session* — its id,
generation, journal cursor, approval head, resume point. It does not know the
image digest, kernel digest, or vcpu count, and should not: those describe the
workload, change independently of the session, and would make the record a
second copy of the plan. The caller supplies them; the record supplies the
session identity. Keeping that split explicit is what stops the record drifting
into a duplicate plan.

**Mirror, do not invent:** `crates/mvm-hostd/src/run.rs:180` builds a
`SynthesisInput` for the local run path. Read it and follow its field choices
for everything a resume does not deliberately differ on. It uses a struct
literal rather than the builder, so a literal is the consistent choice here.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> ResumePlanMaterial {
        ResumePlanMaterial {
            backend_name: "hvf".to_string(),
            image_name: "demo".to_string(),
            image_sha256: "ab".repeat(32),
            kernel_sha256: Some("cd".repeat(32)),
            cpus: 2,
            mem_mib: 512,
        }
    }

    #[test]
    fn the_plan_is_named_for_the_session_not_the_parent() {
        // A resume must not inherit the parent's identity: the plan it admits
        // names this session, so anything the resumed sandbox does is
        // attributable to this residency rather than the one before it.
        let rec = parked_record("sess-alpha");
        let m = material();
        let input = synthesis_for_resume(&rec, &m);
        assert_eq!(input.vm_name, "sess-alpha");
    }

    #[test]
    fn the_material_fields_reach_the_plan_input() {
        let rec = parked_record("sess-alpha");
        let m = material();
        let input = synthesis_for_resume(&rec, &m);
        assert_eq!(input.backend_name, "hvf");
        assert_eq!(input.image_sha256, m.image_sha256);
        assert_eq!(input.kernel_sha256, m.kernel_sha256.as_deref());
        assert_eq!(input.cpus, 2);
        assert_eq!(input.mem_mib, 512);
    }
}
```

You will need a `parked_record(id)` helper building an `AgentSessionRecord` in
`SandboxResidency::Hibernated` with a `parent_checkpoint` set. Write the
smallest one serving this task and Task 2, using `mvm_runtime::agent_session`'s
public surface rather than reaching for private state.

- [ ] **Step 2: Run tests to verify they fail**

Run: `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target && ~/.cargo/bin/cargo nextest run -p mvm-hostd session_resume`

Expected: FAIL to compile — the module does not exist.

- [ ] **Step 3: Write the implementation**

Create the module with `ResumePlanMaterial` and `synthesis_for_resume`. Mirror
`run.rs`'s field choices, with these deliberate differences, each carrying a
comment saying why:

- `vm_name` is the session id, not the parent's vm name.
- `tenant`: the same local tenant constant `run.rs` uses.
- `destroy_on_exit: false` — a resumed session is not a run-to-completion
  workload; it outlives the admitting call.

Everything else follows `run.rs`. Read the real `SynthesisInput` field list and
fill every field. If a field's right value for a resume is genuinely unclear,
take `run.rs`'s value, comment that you did, and flag it in your report rather
than choosing silently.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-hostd/src/session_resume.rs crates/mvm-hostd/src/lib.rs
git commit -m "feat(hostd): synthesize a resume plan from a session record"
```

---

### Task 2: `resume_session`

**Files:**
- Modify: `crates/mvm-hostd/src/session_resume.rs`
- Test: inline `mod tests`

**Interfaces:**
- Consumes: Task 1's types; `AgentSessionStore`, `CheckpointStore`,
  `verify_content` (mvm-runtime); `admit_for_run` (this crate).
- Produces: `ResumeRequest`, `ResumedSession`, `resume_session`.

**The ordering property, which the tests pin:** load → require hibernated →
resolve parent → verify content → synthesize → **admit** → transition.
Admission is the last thing that can fail, so a refusal leaves the record
exactly as it was: parked and resumable. A transition committed before
admission would leave a session claiming a residency nothing authorized.

- [ ] **Step 1: Write the failing tests**

Five tests, described rather than written out because each needs fixtures for a
checkpoint store with a real content blob and for a signer directory. Read the
existing tests in `crates/mvm-runtime/src/checkpoint/mod.rs` for how a
checkpoint with verifiable content is staged, and those in
`crates/mvm-hostd/src/plan_admission.rs` for how a signer dir, clock, and nonce
ledger are set up. Reuse those patterns; do not invent a third style. If they
are not reusable across the crate boundary, say so in your report and build the
smallest local equivalent.

1. `a_resume_admits_a_plan_and_advances_the_generation` — positive control, real
   signer dir under a tempdir. Assert the returned record is `Active` at
   generation+1 and that a plan came back.
2. `a_missing_parent_checkpoint_refuses_before_admission` — the record names a
   resume point absent from the store. Refuse; assert still parked at the
   original generation.
3. `a_tampered_parent_checkpoint_refuses_before_admission` — corrupt a content
   blob so `verify_content` fails. Refuse; assert still parked.
4. `an_active_session_cannot_be_resumed` — not hibernated: refuse.
5. `a_refused_admission_leaves_the_session_parked` — force admission itself to
   fail. This is the ordering property and the one test worth writing most
   carefully.

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Write the implementation**

```rust
/// Turn a parked session back into an admitted one.
///
/// Admission runs before the record transition, deliberately: it is the last
/// step that can fail, so a refusal leaves the session parked and resumable
/// rather than half-resumed. A record advanced to a generation that no admitted
/// plan corresponds to would be worse than no resume at all — the session would
/// claim a residency nothing authorized.
pub fn resume_session(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    req: &ResumeRequest<'_>,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
) -> Result<ResumedSession> {
    let record = sessions.load(req.session_id)?;
    if record.state != SandboxResidency::Hibernated {
        anyhow::bail!(
            "session {} is not parked, so it cannot be resumed",
            req.session_id.as_str()
        );
    }

    // Resolve and verify the resume point before building anything from it.
    let digest = record.parent_checkpoint.as_ref().ok_or_else(|| {
        anyhow::anyhow!("session {} records no resume point", req.session_id.as_str())
    })?;
    let parent = checkpoints
        .by_digest(digest)?
        .ok_or_else(|| anyhow::anyhow!("resume point {digest} is not in the checkpoint store"))?;
    mvm_runtime::checkpoint::verify_content(checkpoints, &parent)?;

    let input = synthesis_for_resume(&record, req.material);
    let admitted = crate::plan_admission::admit_for_run(
        &input,
        clock,
        ledger,
        req.host_signer_keys_dir,
        None,
        posture,
    )?;

    // Only now: the transition. Everything above can refuse without having
    // moved the record.
    let record = sessions.resume(
        req.session_id,
        req.expected_generation,
        req.current_approval_head,
        req.now_unix,
    )?;

    Ok(ResumedSession { record, admitted })
}
```

Read `RunPosture` and choose the variant that fits a non-production resume; say
which you used and why in your report. If a production posture is the safer
default, argue that in the report rather than choosing silently. Define
`ResumeRequest` as a params struct carrying `session_id`,
`expected_generation`, `current_approval_head`, `material`,
`host_signer_keys_dir`, and `now_unix` — the argument count is exactly why it
is a struct.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Verify the ordering property is not vacuous**

Temporarily move the `sessions.resume(...)` call to just after the
`state != Hibernated` check — before verification and admission — and confirm
`a_refused_admission_leaves_the_session_parked` and
`a_tampered_parent_checkpoint_refuses_before_admission` both go RED. Then
restore. Report both REDs with commands and output. If either does not go red,
say so and stop rather than reporting one you did not observe.

- [ ] **Step 6: Run the full gate and commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-core -p mvm-runtime -p mvm-hostd
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
git add crates/mvm-hostd/src/session_resume.rs
git commit -m "feat(hostd): admit a fresh plan when resuming a parked session"
```

---

### Task 3: Update the specs and the delivery record

**Files:**
- Modify: `specs/plans/2026-08-18-durable-agent-sessions.md` (D5, WS4 state)
- Modify: `specs/REFACTOR-STATUS.md`
- Create: `specs/sprint/delivery/resume-session-orchestrator.md`
- Modify: this plan's checkboxes

- [ ] **Step 1: Update D5 accurately**

D5's numbered steps are now partly real: load, the approval-head comparison,
synthesizing a fresh plan, and admitting it all exist. Absent: tier selection,
any `PolicySet::evaluate` call, lineage verification against a signed anchor
(only `verify_content` runs), `PostRestore` with a fresh VMGenID, minting
credentials at the substitution endpoint, and the chain entry. Say which is
which, precisely, rather than describing D5 as done.

- [ ] **Step 2: Mark WS4's state, naming what remains**

Do not tick WS4. Verify each remaining absence with an **exhaustive** search —
`| wc -l` first, or read the whole result. Do not pipe a search establishing
absence through `head`: two false claims reached committed documents on this
branch exactly that way. Cite each command in your report.

- [ ] **Step 3: Update `specs/REFACTOR-STATUS.md`** and its "Last updated".

- [ ] **Step 4: Write `specs/sprint/delivery/resume-session-orchestrator.md`**,
style-matching that directory. Do NOT append to `specs/SPRINT.md` —
`xtask check-sprint-append` fails if its delivery section grows.

- [ ] **Step 5: Tick this plan's checkboxes and run the doc gates**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo run -p xtask -- check-plan-names
~/.cargo/bin/cargo run -p xtask -- check-declared-backing
~/.cargo/bin/cargo run -p xtask -- check-sprint-append
~/.cargo/bin/cargo run -p xtask -- check-no-spec-refs-in-comments
```

These files carry `Backing: preview`, which bars a short list of assertive verbs
matched as whole words — quoting one in prose trips the gate too. Write about
what the code does; the gate names the word it found if it refuses.

- [ ] **Step 6: Commit**

```bash
git add specs/
git commit -m "docs: record the resume orchestrator slice"
```

---

## Deferred to later plans

- **Booting the resumed session**: selecting the storage tier, restoring the
  memory image or replaying the journal, and starting the backend.
- **`PostRestore` fabric re-registration** with a fresh VMGenID, and minting
  credentials at the per-VM substitution endpoint.
- **Lineage verification against a signed anchor.** `verify_lineage` needs a
  `CheckpointChainAnchor`; this plan verifies content integrity only, which
  catches a tampered blob but not a checkpoint that was never audited.
- **Chain records (WS7)** for `session.parked` / `session.resumed`.
- **Retention ladder and GC (WS5)**.
