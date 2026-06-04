# Plan 151 — In-guest filesystem-access evidence (advisory observability)

> **For agentic workers:** use `superpowers:subagent-driven-development` or
> `superpowers:executing-plans` to implement task-by-task. Steps use `- [ ]` for tracking.

> **Spec number:** 151 chosen free at authoring. Numbering is actively raced across
> parallel worktrees ([[feedback_always_use_git_worktrees]]) — re-confirm against `main`
> + open PRs before merge (`xtask check-spec-numbers` is a Lint gate). Sibling branch-local
> plans were renumbered off merged-`main` collisions in the same pass: 144→153, 146→154,
> 147→155.

> **Sequencing:** Follow-on to the Plan 120 line, not a blocker for it. Gated behind Plan
> 120 `core_demo_e2e` green (it touches the workload-guest boot path — a bad monitor init
> presents as "agent never answered", Plan 120 Task 4's exact symptom) and lands *on top
> of* Plan 143 R1 (shares the in-guest seccomp-apply boot path — don't race it). The live
> surfacing depends on this-branch Plan 149 (`mvmctl watch` category filter).

## Context

mvm audits **network** access at the host boundary: the gateway audit substrate emits
`FlowOpened/Closed/Bytes/PolicyDecision` over `~/.mvm/audit/gateway-<vm>.sock`
(`crates/mvm-supervisor/src/gateway_audit.rs`; wire shape `FlowEventWire` in
`gateway_bridge.rs`), and Plan 149 merges that into `mvmctl watch`. mvm has
**no filesystem-access evidence** — nothing records which paths a workload read, which
writes it attempted, or which opens escaped its shares.

A peer single-purpose sandbox ships exactly this as developer DX ("what files did this run
touch"). It gets it cheaply because it serves VirtioFS on the *host* and logs every FUSE
request at that boundary. mvm cannot copy that: for both real backends the virtiofs server
lives inside libkrun (C) and Apple Virtualization.framework — not interceptable in-process,
the same untrusted-input-surface-is-upstream situation as the network frame parsers
(ADR-055 §"New untrusted-input surfaces"). The host boundary is unavailable to us, so
capture must happen **inside the guest** — which makes this feature **advisory
observability, not a security control**: the in-guest reporter is within the workload's own
trust domain and a hostile guest can evade it. The enforcement boundary is unchanged and
stays the control — hardware VM + dm-verity rootfs (claim 3) + read-only virtiofs shares
(claim 1) + default-deny egress (claim 10). This is the filesystem sibling of the network
flow audit, deliberately scoped as a *visibility layer*, the same way Plan 143 framed
in-guest hardening as layered niceties over the hardware boundary, never a replacement.

So: an **opt-in, dev-tier** fs-access evidence stream that reuses the in-guest
seccomp/agent infra (Plan 143) and the audit substrate + `mvmctl watch` (Plan 149),
surfaced as a live category and a per-run digest. Off by default; never on the hardened
admitted path.

## Architecture (what already exists)

- **Network evidence to mirror:** `FlowEventWire` (`gateway_bridge.rs`), `EventCategory`
  (`crates/mvm-supervisor/src/audit_recorder.rs`), per-VM bounded/lossy live socket
  (`gateway_audit.rs`, 256-event drop-oldest, 0700). `mvmctl watch --categories flow`
  (Plan 149) is the consumer.
- **In-guest seccomp/agent path:** the agent execs the workload; `mvm-seccomp-apply`
  (`crates/mvm-guest/src/bin/mvm-seccomp-apply.rs`) applies the workload filter at boot,
  built via `crates/mvm-security/src/seccomp.rs` (`seccompiler` dep). Plan 143 R1 extends
  it with `ioctl` arg filtering. This is the privileged-before-exec hook a monitor installs
  into.
- **Guest↔host channel:** framed vsock (`crates/mvm-guest/src/vsock.rs`); the agent already
  speaks it to the host.
- **Mount model (what is even observable):** the workload rootfs is a **read-only
  dm-verity block device** — host can't see reads into it, and neither can a guest monitor
  add much value there. Shared host dirs arrive as **read-only virtiofs** (`work`,
  `mvm-bins`, and `mvmctl exec --add-dir`). Writable scratch is a guest-local overlay/tmpfs,
  not host-visible. So the *meaningful* evidence is: reads/opens under the virtiofs share
  roots, **write attempts denied with EROFS** on the read-only mounts, and opens that
  resolve outside a share root.
- **Digest-render pattern to reuse:** `mvmctl deps inspect`'s `build_report` →
  `CveSummary` histogram output (`crates/mvm-cli/src/commands/deps/inspect.rs`).

## Tech Stack

Rust; `crates/mvm-guest` (agent + monitor), capture via `fanotify` or
`mvm-security`/`seccompiler` seccomp-notify (decided in A1 — prefer existing `libc`/
`seccompiler` over a new crate, [[feedback_limit_dependencies]]); `crates/mvm-supervisor`
audit substrate; `clap` under `crates/mvm-cli`; `tests/cli.rs`; `cargo test --workspace`.

---

## Workstream A — Capture mechanism + in-guest monitor

### Task A1: ADR-071 — capture mechanism + advisory framing
- [ ] Write `specs/adrs/071-filesystem-access-evidence.md` (confirm 070/071 free before
      authoring — claim the next open ADR number). Decide and record:
  - **Capture mechanism, with the feasibility result, not a guess:**
    - *Candidate A — fanotify* on each share-root subtree inside the guest
      (`FAN_OPEN`/`FAN_ACCESS`/`FAN_MODIFY`/`FAN_OPEN_EXEC`, `FAN_REPORT_DFID_NAME` for
      paths), non-permissive (observe-only). Purpose-built for "watch a tree", low overhead,
      path-accurate. **Risk to verify in A2:** fanotify mark support on a virtiofs/FUSE
      mount inside our guest kernel.
    - *Candidate B — agent-applied seccomp user-notification* on path syscalls
      (`openat`/`openat2`, `unlinkat`, `renameat2`, `mkdirat`, `linkat`, `symlinkat`,
      `truncate`). The agent (more privileged; `no_new_privs` stops the workload removing
      the filter) receives notifications, logs the path, and `CONTINUE`s. Higher overhead;
      the path read is racy — **acceptable here because we only log** (unlike Plan 143 R2,
      which needed `openat2(RESOLVE_BENEATH)` precisely because it makes an *enforcement*
      decision; evidence makes none).
    - Decision rule: fanotify if A2 shows virtiofs accepts marks (cheaper, path-accurate);
      else seccomp-notify scoped to the syscalls above with in-guest aggregation.
  - **This is advisory, NOT a security claim.** In-guest reporter ⇒ guest-trust ⇒ evadable;
    it does **not** enter the ADR-002 numbered claims and does **not** touch
    `specs/claims/catalog.md`. State the enforcement boundary that *is* the control (VM +
    verity + RO virtiofs + egress) and that this never weakens it.
  - **Dev-tier only**, off by default — it must not run on, or perturb, the hardened
    admitted boot path ([[feedback_dev_vm_vs_prod_security_tiers]]).
  - Out-of-scope line: host-side virtiofs request logging (the boundary-accurate capture)
    needs a virtiofs server we don't own; deferred (see Deferred). Record so the in-guest
    choice is deliberate.

### Task A2: fanotify-on-virtiofs feasibility probe (folded into A1's decision)
- [ ] Inside the guest, mark a virtiofs share root with fanotify and confirm events fire
      with usable paths; record pass/fail in ADR-071. On fail, A1 selects seccomp-notify.
      (Guest-side Linux behaviour — backend-agnostic; runnable on the local Vz dev host,
      [[project_dev_host_runs_builder_via_vz]].)

### Task A3: in-guest monitor + aggregation
- [ ] Implement the monitor as a mode of the agent (or a sibling binary mirroring
      `mvm-seccomp-apply`): install fanotify marks on each share root (or the seccomp-notify
      filter) **before** exec'ing the workload.
- [ ] Aggregate in-guest — never per-syscall to the host: a map keyed `(path, kind)` →
      `{count, first_ts, last_ts, access: ro|rw, denied: bool}`, with a **bounded
      distinct-path cap**; on overflow, drop and increment a `dropped_paths` counter that
      ships in the rollup (no silent truncation). Emit a rollup over vsock on a fixed
      interval and on workload exit.

### Task A4: gating + safety
- [ ] Active only under dev-tier **and** `--fs-evidence` (CLI) / `MVM_FS_EVIDENCE=1`; a
      **no-op** on the hardened/admitted path (no marks, no filter, no channel). Best-effort:
      the monitor must never block or fail the workload — capture errors degrade to "evidence
      unavailable", logged once, workload proceeds.

---

## Workstream B — Host substrate + surfacing

### Task B1: `Fs` event category + wire shape
- [ ] Add `EventCategory::Fs` (`audit_recorder.rs`) and `FsEventWire { kind:
      open|read|write|create|unlink|rename|denied, path, mount: <share-tag|rootfs>, access:
      ro|rw, count, ts }` mirroring `FlowEventWire` (`gateway_bridge.rs`). Receive the
      agent's rollup frames, normalize to `FsEventWire`, and broadcast on the per-VM live
      socket reusing the existing bounded/lossy 256-event broadcast (drop-oldest) — fs
      events are high-volume; lossy-live is correct.

### Task B2: live stream (`mvmctl watch --categories fs`)
- [ ] Add the fs source to `mvmctl watch` (Plan 149) so `--categories fs` streams
      `FsEventWire`; one-line human formatter
      (`… fs_open  ro  /work/src/main.py  vm=web`) + raw record under `--json`. If Plan 149
      has not landed, gate this task on it rather than duplicating the merge reader.

### Task B3: per-run digest
- [ ] On workload exit emit a digest rendered like `deps inspect`'s report:
      `fs evidence: 42 distinct paths read under /work; 3 write attempts denied (EROFS) on
      /app; 0 opens outside shares; 0 paths dropped`. `--json` emits the structured rollup.
      Write it to the run dir (`<vm_state_dir>/fs-evidence.json`), **not** the chain-signed
      audit log — advisory + high-volume; keeping it out of the Ed25519 chain avoids
      implying it is a trust artifact (state this in ADR-071).

### Task B4: backend coverage
- [ ] libkrun + Vz first; Firecracker / Apple-Container deferred, mirroring the
      gateway-audit substrate coverage boundary ([[project_gateway_audit_substrate_backend_coverage]]).
      The monitor is guest-side so it is largely backend-agnostic; the gating is which
      backends wire the host receiver + watch source in v1.

---

## Workstream C — Docs + tests

### Task C1: docs + ADR cross-ref
- [ ] `public/src/content/docs/reference/cli-commands.md`: document `--fs-evidence` and
      `watch --categories fs`. One-line cross-ref in ADR-002 / the `CLAUDE.md` security
      section that fs evidence is **advisory observability, not a claim** (mirrors Plan 143
      R3's ADR-002 reconcile). `development.md`: note the dev-tier, opt-in nature.

### Task C2: tests
- [ ] `FsEventWire` serde roundtrip; aggregator unit (dedup, the distinct-path cap +
      `dropped_paths` counter, rollup-on-interval/exit).
- [ ] Guest integration: touch N files under a share + attempt one write to a RO mount;
      assert the digest reports the right read count and the write as `denied` (EROFS), and
      `opens outside shares = 0`.
- [ ] `tests/cli.rs`: `--fs-evidence` arg parse + `watch --categories fs`; assert
      flag-off / prod-tier is a strict no-op (no socket, no events).

---

## Out of scope / deferred

- [ ] **Host-side virtiofs request log** — the boundary-accurate capture the peer tool uses.
      Needs a virtiofs server mvm owns in-process; not available with libkrun/Vz today.
      Revisit only if mvm internalizes a rust-vmm virtiofs (relates to the deferred
      rust-vmm-internalization plans). Recorded so the in-guest choice is deliberate.
- [ ] **Filesystem *enforcement*** (deny opens by policy, Landlock-for-workloads) — Plan
      143 already rejected this on hardware-boundary grounds. This plan is evidence-only.
- [ ] **Chain-binding / signing the fs digest** — no; it is advisory, kept out of the
      signed chain on purpose (B3).
- [ ] **Firecracker / Apple-Container coverage** — deferred with the gateway-audit substrate
      boundary; revisit per-backend.
- [ ] **Reads *into* the dm-verity rootfs** — block-device, not host-mediated; low value and
      not captured. Shares + escape-attempts are the signal.
- [ ] **A GUI** — `--json` digest + `watch --categories fs` are the substrate a UI consumes.

## Acceptance (this plan is done when)

- [ ] `mvmctl run --fs-evidence <workload>` (dev tier) prints a per-run fs digest — distinct
      reads under shares, EROFS-denied writes, opens-outside-shares, dropped-paths — and
      `--json` emits the structured rollup; flag-off / prod-tier is a strict no-op.
- [ ] `mvmctl watch --categories fs` streams `FsEventWire` live for a running dev workload
      (once Plan 149 lands).
- [ ] libkrun + Vz covered; the monitor never blocks the workload; capture failure degrades
      to "evidence unavailable", not a boot failure.
- [ ] ADR-071 merged stating advisory-not-a-claim + dev-tier-only + the chosen capture
      mechanism with its feasibility result; `specs/claims/catalog.md` unchanged;
      `xtask check-spec-numbers` passes.
- [ ] `cargo fmt --all -- --check` (nightly — [[reference_ci_lint_uses_nightly_rustfmt]]),
      `cargo test --workspace`, `cargo clippy --workspace -- -D warnings` green.

## Self-review

- **Honest about trust:** in-guest reporter ⇒ guest-trust ⇒ evadable; ADR-071 says so;
  no claim, no chain binding, dev-tier-only — the hardware boundary stays the control
  (same posture as Plan 143).
- **Reuses, does not rebuild:** the seccomp-apply boot hook, vsock, the gateway audit
  substrate + bounded live socket, `mvmctl watch`, and the `deps inspect` digest shape all
  exist — this adds an `Fs` category + a guest monitor over them.
- **Proportionate:** opt-in, dev-only, in-guest aggregated, bounded distinct-path cap with a
  visible drop counter, best-effort — it does not tax the workload or flood the chain.
- **Boundary-ideal deferred deliberately:** host virtiofs request logging is named as the
  future accurate capture, not silently omitted.
- **Dependencies explicit:** after Plan 120 green + Plan 143 R1 (shared boot path);
  live surfacing needs Plan 149; libkrun + Vz first.
