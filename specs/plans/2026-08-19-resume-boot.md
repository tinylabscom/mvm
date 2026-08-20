# Resume Boot Implementation Plan

Backing: preview
Validation: none

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `mvmctl agent-session resume` actually boot a microVM, through the
same post-admission gates every other admitted boot passes, and witness it on a
real KVM host.

**Architecture:** `resume_session` currently stops at an `AdmittedPlan`. It
cannot boot, because everything `admit_and_start` does *after* admission —
`run_post_admission_gates`, `backend.start`, `apply_admitted_grants`, and the
undo-on-failure — is private to `plan_admission`, and `admit_and_start` itself
re-synthesizes and re-admits from a `SynthesisInput`. A resume calling it would
admit twice: two nonces, two signed plans, and the second one silently becoming
the real authority.

The fix is to extract that post-admission tail into one shared function that
both `admit_and_start` and the resume path call. That is the reuse-first answer
and it also makes the safety property structural: a resume cannot boot on a path
that skipped a gate, because there is only one path.

**Tech Stack:** Rust, `anyhow`, `cargo nextest`; a real Firecracker boot on
Linux/KVM for the witness.

**Spec:** `specs/plans/2026-08-18-durable-agent-sessions.md` D5 steps 6-7.

## Global Constraints

- **Local worktree:** `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions`.
  In every shell, including the one you commit from, put
  `export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target`
  in the SAME command as the cargo or git invocation. The Bash tool does not
  persist exports. The machine is near-full on disk; an ENOSPC is a host
  condition from other worktrees — wait and retry.
- Use `~/.cargo/bin/cargo`, never Homebrew's rustc.
- `#[allow(clippy::too_many_arguments)]` is banned; use a params struct. The
  extracted function takes one.
- No plan, PR, or ADR references in code comments — CI-gated.
- Let the pre-commit hook run; a guard blocks skipping it.
- **This touches `cfg(target_os = "linux")` code paths.** A macOS check does not
  see them. Task 4's host validation is not optional garnish — it is the only
  thing that compiles and runs the Firecracker path.

## The KVM host

```
ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
    -i ~/.ssh/hetzner-rvproxy root@88.99.197.234
```

8 cores, 62 GB RAM, `/dev/kvm` present, 1.1 TB free, `firecracker` at
`/usr/local/bin/firecracker`. A worktree is already prepared at `/root/wt-sess`
with a warmed target dir at `/root/sess-target` — `export
PATH=$HOME/.cargo/bin:$PATH` and `export CARGO_TARGET_DIR=/root/sess-target`.
Prior real boots exist under `~/.mvm/vms/` (`bootprobe*`, `probe7`, `probe8`).
**Do not disturb `/root/mvm`** — it has unrelated dirty files from another
session.

## What this plan does and does not cover

Covers: booting a resumed session at the **`Cold`** tier — a fresh VM start from
the resume point's rootfs, under the resumed session's admitted plan.

Does NOT cover: restoring a `Parked` memory image, or claiming a `Resident`
standby. Those need the snapshot-restore path wired to a session, which is a
larger change with its own failure modes, and `Cold` is the tier that must work
first because it is the one that survives a host reboot. Task 3 must refuse the
other two tiers explicitly rather than silently treating them as `Cold`.

## Interfaces produced by this plan

```rust
// mvm_hostd::plan_admission
pub struct StartAdmittedParams<'a> {
    pub backend: &'a AnyBackend,
    pub admitted: &'a AdmittedPlan,
    pub config: VmStartConfig,
    pub policy_bundle: Option<&'a PolicyBundle>,
    pub emitter: Option<&'a AuditEmitter>,
}
/// The post-admission tail every admitted boot shares.
pub fn start_admitted(params: StartAdmittedParams<'_>) -> Result<StartedMachine>;

// mvm_hostd::session_resume
pub struct ResumeBootRequest<'a> { /* see Task 3 */ }
pub fn resume_and_boot(...) -> Result<(ResumedSession, StartedMachine)>;
```

---

### Task 1: Extract `start_admitted`

Pure refactor. No behaviour change, and the existing tests are the evidence.

**Files:**
- Modify: `crates/mvm-hostd/src/plan_admission.rs`

**Interfaces:**
- Produces: `StartAdmittedParams`, `start_admitted`.

**Read first:** `admit_and_start` (from ~line 1411) end to end. Everything from
`run_post_admission_gates` through the `backend.start` match — including
`apply_admitted_grants` and the undo-the-launch arm on grant failure — moves
into the new function. Everything before it (synthesize, admit, `record_admission`)
stays in `admit_and_start`.

**Do not change behaviour.** Same order, same fail-closed posture, same audit
emissions, same undo. If you find yourself wanting to improve something while
moving it, don't — note it in your report instead. A refactor that also changes
behaviour cannot be reviewed as either.

- [x] **Step 1: Confirm the current tests cover the moved code**

Before touching anything, run the existing admission suite and record the count:

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo nextest run -p mvm-hostd plan_admission
```

Note the number. That same set must pass unchanged after the extraction — that
is what makes this a safe refactor rather than a rewrite. Report both numbers.

- [x] **Step 2: Extract the function**

Move the post-admission tail into `start_admitted`, taking a
`StartAdmittedParams` struct (the argument count is exactly why). Have
`admit_and_start` call it. Keep every doc comment with the code it describes —
`admit_and_start`'s doc explains the whole order, so split it: the ordering
prose that now lives in `start_admitted` moves with it, and `admit_and_start`
keeps a line saying it admits and then delegates.

- [x] **Step 3: Run the same suite; the count must match**

Any change in the number is a bug in the extraction. Report both.

- [x] **Step 4: Verify the extraction is real**

`grep -c "run_post_admission_gates" crates/mvm-hostd/src/plan_admission.rs`
must show it called from exactly one place. If `admit_and_start` still contains
a `backend.start(` call, the extraction is incomplete.

- [x] **Step 5: Commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all
git add crates/mvm-hostd/src/plan_admission.rs
git commit -m "refactor(hostd): extract the post-admission boot tail into start_admitted"
```

---

### Task 2: `Cold`-tier boot config from a resume point

**Files:**
- Modify: `crates/mvm-hostd/src/session_resume.rs`
- Test: inline

**Interfaces:**
- Produces: a function turning a verified parent `CheckpointMeta` + the session
  record into a `VmStartConfig` for a cold boot.

**The rootfs question, which you must answer from the code rather than guess:**
a `CheckpointMeta`'s `content` names its blobs. Read
`crates/mvm-runtime/src/checkpoint/mod.rs` for how `fork_checkpoint` and
`fork_vm_full` locate a child's rootfs from a parent's content manifest, and
follow whichever of those a cold boot corresponds to. If neither fits, say so in
your report and stop rather than inventing a third way to find a rootfs.

- [x] **Step 1: Write the failing tests**

- a cold-boot config names the resume point's rootfs, not an arbitrary path;
- the config's `name` is the session id, matching the admitted plan's `vm_name`,
  so the started VM and the plan agree on identity;
- a checkpoint whose content manifest lacks a rootfs blob is refused with a
  message naming what was missing, rather than producing a config that fails
  later at `backend.start` with something opaque.

Use the fixtures already in `session_resume.rs`'s `mod tests` (`seed_checkpoint`,
`parked_record`); do not invent a second fixture style.

- [x] **Step 2: Run tests to verify they fail**

- [x] **Step 3: Write the implementation**

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/session_resume.rs
git commit -m "feat(hostd): build a cold-boot config from a verified resume point"
```

---

### Task 3: `resume_and_boot`

**Files:**
- Modify: `crates/mvm-hostd/src/session_resume.rs`
- Modify: `crates/mvm-cli/src/commands/agent_session.rs` (a `--boot` flag on
  `resume`)
- Test: inline in both

**Interfaces:**
- Consumes: `resume_session` (Task 0, already built), `start_admitted` (Task 1),
  the cold-boot config (Task 2).
- Produces: `ResumeBootRequest`, `resume_and_boot`, `resume --boot`.

**Ordering, which the tests must pin:** admit → transition → **then** boot. The
record moves before the VM starts, because a started VM that the record does not
know about is an orphan nothing will ever reap, whereas a transitioned record
whose boot failed is a parked-then-active session an operator can see and retry.
Say which failure you chose in the doc comment and why.

**Tier handling:** only `Cold` boots. `Parked` and `Resident` must refuse with a
message naming the tier and saying the path is not built, not silently cold-boot
— a `Parked` session cold-booted would discard a memory image the operator
believes is being restored, which is data loss disguised as success.

- [x] **Step 1: Write the failing tests**

- a `Cold`-tier resume with `--boot` reaches `start_admitted` (use the mock
  backend — read how `plan_admission`'s tests drive `AnyBackend::Mock`);
- a `Parked`-tier resume with `--boot` is refused, naming the tier, and the
  session is left in whatever state the ordering decision specifies — assert it
  explicitly either way;
- a `Resident`-tier resume with `--boot` is refused the same way;
- `resume` without `--boot` still admits and transitions without starting
  anything, exactly as today.

- [x] **Step 2: Run tests to verify they fail**

- [x] **Step 3: Write the implementation**

- [x] **Step 4: Run tests to verify they pass**

- [x] **Step 5: Verify the tier refusal is not vacuous**

Temporarily let `Parked` fall through to the cold path, confirm that test goes
RED, restore. Report the RED with command and output; if it does not go red, say
so and stop rather than reporting one you did not observe.

- [x] **Step 6: Full gate and commit**

```bash
export CARGO_TARGET_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-durable-sessions/target
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo nextest run -p mvm-runtime -p mvm-hostd -p mvm-cli
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
git add crates/mvm-hostd/src/session_resume.rs crates/mvm-cli/src/commands/agent_session.rs
git commit -m "feat(hostd): boot a cold-tier session on resume"
```

---

### Task 4: Witness a real boot on KVM

Mock-backend tests do not exercise Firecracker. This task is the evidence that
the path works.

**Files:** none in the repo — this produces a report.

- [x] **Step 1: Build on the host**

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
    -i ~/.ssh/hetzner-rvproxy root@88.99.197.234
```

Then, on the host: fetch your branch into `/root/wt-sess`, and

```bash
export PATH=$HOME/.cargo/bin:$PATH
export CARGO_TARGET_DIR=/root/sess-target
cargo build -p mvm-cli
```

Do not disturb `/root/mvm`.

- [x] **Step 2: Run the Linux-gated tests that a macOS check cannot see**

```bash
cargo nextest run -p mvm-hostd -p mvm-runtime -p mvm-cli
```

Report the count and any failure. A macOS-green / Linux-red difference is the
finding this task exists to catch.

- [x] **Step 3: Drive the real lifecycle**

Using the built `mvmctl`, on the host:
1. produce a checkpoint that can serve as a resume point (reuse whatever
   `~/.mvm/vms/bootprobe*` was produced by, or capture a fresh one — read
   `mvmctl machine --help` on the host and use what exists);
2. `mvmctl agent-session open` naming that checkpoint as `--resume-point`;
3. `mvmctl agent-session park` it;
4. `mvmctl agent-session resume --boot` it;
5. confirm a Firecracker process actually started and the guest booted —
   `~/.mvm/vms/<name>/console.log` is the evidence, and a pid marker.

Capture the console log and the exit status. **If any step fails, that is the
result** — report it exactly rather than working around it. A failure here is
worth more than a green mock test.

- [x] **Step 4: Write the witness report**

Record it under `specs/sprint/delivery/` with the commands, the console
evidence, and what did and did not work. If the boot did not happen, say so
plainly in the title.

---

### Task 5: Specs and delivery record

- [x] **Step 1** Update D5 steps 6-7 state in
`specs/plans/2026-08-18-durable-agent-sessions.md` — what boots, what refuses,
and that `Parked`/`Resident` are unbuilt.
- [x] **Step 2** Update `specs/REFACTOR-STATUS.md` and its "Last updated".
- [x] **Step 3** Create `specs/sprint/delivery/resume-boot.md`.
- [x] **Step 4** Tick this plan's checkboxes and run the doc gates:
`check-plan-names`, `check-declared-backing`, `check-sprint-append`,
`check-no-spec-refs-in-comments`, `check-cli-help-matches-docs` (the `--boot`
flag may need a reference row).
- [x] **Step 5** Commit.

These spec files carry `Backing: preview`, which bars a short list of assertive
verbs matched as whole words — quoting one trips the gate. Prefer "introduces",
"records", "sets up".

---

## Deferred to later plans

- **`Parked`-tier restore**: wiring the snapshot-restore path to a session so a
  memory image is restored rather than cold-booted.
- **`Resident`-tier claim**: claiming a standby for a session.
- **`PostRestore` re-registration and credential minting** on a resumed guest.
- **Journal replay**: a cold boot starts the workload fresh; nothing replays the
  session journal into it, so a resumed workload does not yet recover its own
  in-guest state.
