# Vz deprecation — flip the macOS-26 default to the hvf VMM and delete Vz

Date: 2026-07-02
Umbrella: Plan 214 (clean-replacement architecture). This is the "flip default
+ delete Vz" tail of that plan.
Status: design approved; implementation plan pending.

## Problem

On macOS 26 Apple Silicon a bare `mvmctl machine run` still lands on the Vz
backend. `AnyBackend::auto_select` (`crates/mvm-backend/src/backend.rs:566`,
`is_vz_default_tier`) hard-returns `Self::Vz(VzBackend)`, and the builder VMM
auto-detect (`crates/mvm-build/src/builder_backend_select.rs:91`,
`auto_detect_default_for`) returns `Vz` on the same tier. The hvf VMM
(driven through `WorkloadRunner` over the `VmmDriver` seam, and
`InHouseBuilderVm` for the builder) is reachable only via explicit
`--hypervisor hvf` / `MVM_BUILDER_BACKEND`. The additive comment in
`backend.rs` states the intent outright: "Vz remains the macOS-26 default until
HVF reaches workload parity."

Vz is the transitional macOS backend; the hvf Hypervisor.framework VMM is
the destination (ADR-098, ADR-100). We are removing Vz entirely: the backend,
its supervisor (Rust + Swift), its transport, its selection tiers, and every
Vz case.

## Non-negotiable gate (Step 0): the hvf path must be a proven replacement

The flip and the deletions are cheap and low-risk. The only real risk is
whether the hvf VMM is a *proven* replacement. Nothing flips until, on a
macOS-26 Apple Silicon host:

1. **Workload reachability** — `machine run --name X --hypervisor hvf -d`
   boots a real OCI/mkGuest workload (e.g. alpine) to a **reachable agent**:
   `vm wait` / doctor reports `ready`, and an `invoke` / agent-ping round-trip
   succeeds.
2. **Production host→guest input round-trip (channel 1 inbound).** NOTE: the
   surface is `--entrypoint --stdin` against a **`--manifest`/`--flake`**
   workload (or the SDK `invoke --input` path) — NOT `machine run --image X
   --stdin`. `--stdin` is entrypoint-only (`requires = "entrypoint"`), and
   `--entrypoint` is unavailable for OCI `--image` (an OCI image runs its baked
   CMD via inline argv with no host→guest stdin wiring). The proof: a flake
   entrypoint that reads stdin and echoes it, run under `--hypervisor hvf`,
   returns the payload — establishing inbound delivery over the hvf
   `agent.sock`.
3. **Builder reachability** — the hvf builder (`InHouseBuilderVm`) boots
   and runs a `nix build` (Stage 0 → workload kernel) to a usable artifact.

### Step-0 results (2026-07-02, macOS 26 Apple Silicon)

- **Reachability + channel-1 outbound: PROVEN.** `machine run --image alpine
  --hypervisor hvf --json -- /bin/echo step0-hvf-ok` returned
  `exit_code: 0, success: true, stdout_bytes: 17`, and the reported
  `stdout_sha256` matched `sha256("step0-hvf-ok\n")` exactly. The run
  reported `network_posture: deny-all, egress_enforcement: flow-drop`, so
  claim-10 is enforced on the hvf path. This is the load-bearing fact:
  the hvf VMM boots a real OCI workload to a reachable agent that runs a
  command and returns stdout/exit. **The plan's "flip + delete" shape is
  therefore valid** (the alternative "finish boot first" shape is ruled out).
- **Channel-1 inbound: PROVEN (2026-07-02, worktree bins).** `echo STDIN-RT-42 | machine run --image alpine --hypervisor hvf --json -- /bin/cat` returned stdout 11 bytes, sha256 81fce04b... == sha256("STDIN-RT-42"), via Plan 220 (drop --stdin, auto-detect non-TTY stdin). Prior note retained for history:
- **(historical) Channel-1 inbound was NOT YET PROVEN via the invalid --image --stdin combo.** The first attempt used the
  invalid `--image … --stdin` combination and (as expected) delivered no stdin;
  this is CLI behavior, not an hvf defect. Inbound rides the same
  backend-agnostic runner path (`runner/mod.rs`: "pipes the captured stdin to
  the child's stdin") over the same `agent.sock` that outbound proved alive, so
  the residual risk is low. It is deferred to Step-1 implementation testing,
  where a flake build is already in scope — proven via `--entrypoint --stdin`
  on a flake entrypoint. A separate minor finding: clap does not reject
  `--stdin` given without `--entrypoint`; it silently ignores it (small CLI
  bug, tracked independently).
- **Step-2 interactive `-it` shell: PROVEN (2026-07-13).** `MVM_DATA_DIR=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-interactive-oci-dev-console/.mvm-test /private/tmp/mvm-interactive-oci-dev-console-target/debug/mvmctl machine run --image alpine -it --allow-host google.com -- /bin/sh` reached a live `~ #` prompt on the default HVF path, accepted `echo READY_FROM_ALPINE` plus `uname -a`, and exited cleanly. The closeout fix was not another console-protocol change; it was eliminating long macOS Unix-socket-path overflows by moving the host-side HVF/direct-vsock UDS endpoints onto a short hashed `/tmp/mvm-sock/...` fallback when the worktree-local state dir is too deep.
- **Builder reachability: deferred** (does not affect the plan's shape; part of
  the builder-flip proof).

## The three host↔guest channels (the security boundary we must not blur)

A production microVM is **not** mute. There are three distinct channels with
three different postures. The Vz-deprecation console work touches only the
third.

1. **Runner batch stdio — production, bidirectional, NOT gated.**
   `crates/mvm-guest/src/runner/mod.rs:20-34`: stdin is piped in (one-shot,
   hard-capped at 1 MiB in v1), the workload runs, and the child writes
   stdout/stderr back. Prod-hardened (`PR_SET_DUMPABLE=0` before the first
   stdin byte, `runner/hardening.rs`). This is how a production workload
   receives input and returns output. On the hvf runner it flows over the
   `agent.sock` the runner already stands up unconditionally
   (`workload_runner/runner.rs:92-98`). **Unchanged by this work.**

2. **Kernel/boot console — write-only capture, no host input fd.**
   `open_console_capture` (`crates/mvm-backend/src/libkrun.rs:119`) opens
   `console.log` write-only; `prod_console_attachment_has_no_input`
   (`libkrun.rs:1137`) asserts there is no guest console input path in prod.
   Guest→host only. The hvf runner already stands up write-only
   `console.log`. **Unchanged by this work.**

3. **Interactive PTY shell — dev-only (claim 15).** The live, bidirectional
   keystroke↔screen shell served by the agent's PTY-over-vsock console
   (`crates/mvm-guest/src/console.rs`, `run_console_relay`) plus `do_exec`.
   Feature-gated behind `dev-shell`; a sealed prod agent links no console
   symbol. This is the *only* channel that is dev-only, and the only one this
   work adds to the hvf backend.

Naming rule for the whole effort: the gate is on **serving an interactive
shell**, never on "the console" as a concept, and never on channels 1–2. A
production microVM keeps full non-interactive host↔guest I/O.

## Design: dev-only interactive PTY shell on the hvf runner

**Guest side:** unchanged. The agent's PTY console and `do_exec` are already
`dev-shell`-gated (claims 4, 15).

**Host side — runner gains a dev-gated `dev_console` pre-open.** When
`VmStartConfig` requests a dev console (the same signal libkrun/vz already
consume) *and* the image is not sealed, the hvf `WorkloadRunner` pre-opens
the console data-port range as host Unix sockets under
`<vm_state_dir>/vsock/vsock-<port>.sock` — the Vz path *shape* (one subdir
deep), but backend-neutral. This mirrors the existing `dev_console` pre-open
asserted by `vz.rs:3128` and `libkrun.rs:1311` ("first/last console data port
must be pre-opened when dev_console is set"). The write-only `console.log`
(channel 2) is untouched; this adds the interactive data ports (channel 3)
only in dev.

**Transport:** rename `VzTransport` → `DevConsoleTransport` (identical
behavior — dial `<dir>/vsock-<port>.sock`; the rename drops the name of the
backend we are deleting). `pick_console_transport`
(`crates/mvm-cli/src/commands/vm/console.rs:31`) gets an hvf probe gated
on `is_dev_mode()` + the state-dir carrying the hvf marker, slotted where
the Vz probe is today. It **extends** the two existing boundary tests
(`pick_console_transport_does_not_route_workload_to_dev_socket`,
`pick_console_transport_selects_dev_socket_for_dev_vm`) rather than inventing
the boundary. `enforce_accessible_gate` still refuses attach on a sealed image,
so claim 15's five layers are intact.

**Rejected alternative:** muxing the interactive PTY over the single
`agent.sock` with an in-band port handshake (à la `NestingHopTransport`) is
more faithful to "one socket," but it modifies the guest agent wire protocol
(fuzzed; claim 5) for a dev-only affordance. Not worth it — mirror the existing
`dev_console` pre-open instead, keeping the change host-side.

**Open question for the plan, not the design:** whether the hvf runner's
host-side vsock bridge (`crates/mvm-backend/src/vmm/vsock.rs`) can pre-open
arbitrary guest ports on demand or needs the port set fixed at boot. Settle
with a short spike in Step 0; it only affects how the pre-open is wired, not
the boundary.

## Companion: drop `--stdin`, auto-detect non-TTY stdin (channel-1 inbound DX)

`--stdin` is bad *nix DX. The guest protocol already carries stdin in both run
verbs (`crates/mvm-guest/src/vsock.rs`): `RunEntrypoint { stdin: Vec<u8> }`
(production-safe baked program) and `Exec { stdin: Option<String> }` (inline
argv, `dev-shell`-gated, claim 4). The flag was an entrypoint-only wrapper over
plumbing that already exists.

**Change:** delete the `--stdin` flag (and its file-path form; `< file` covers
it). When mvmctl's own stdin is **not a TTY** (`!stdin.is_terminal()`), read it
— buffered, capped via the runner's existing `read_stdin_capped` (1 MiB in v1)
— and route the bytes into whichever verb the run resolves to:

- `--entrypoint` / production → `RunEntrypoint.stdin`.
- inline argv (`-- <cmd>`, dev) → `Exec.stdin`.

TTY stdin → no payload (or, with `-t`, the interactive PTY path). This is a
CLI-side change: the protocol and guest agent already handle `stdin` in both
verbs, so no new guest surface and no fuzzed-type change.

**Why it's safe by construction:** piping to inline argv only works in dev
(`Exec` is `dev-shell`-gated, and inline argv is already the dev surface).
Production stdin flows to the sealed `RunEntrypoint`, unchanged. So this adds no
production capability — it only removes a flag.

**v1 bound:** buffered + 1 MiB cap (the runner's existing contract); a larger
pipe fails closed with the existing `StdinTooLarge` error. Unbounded/live
streaming stdin is an explicit Level-2 follow-up, out of scope here.

**Side benefit:** it makes the channel-1 inbound Step-0 proof idiomatic —
`echo STDIN-RT-42 | machine run --image alpine --hypervisor hvf -- /bin/cat`
must echo the payload back (dev `Exec` path). This lands as the first
workstream so it also serves as the inbound proof for the flip.

**Also fixes:** the noticed clap nit (today `--stdin` given without
`--entrypoint` is silently ignored) disappears with the flag.

## Two flips, not one

`mvm-vz-supervisor` serves **both** the workload VMM and the builder VMM, so
both defaults must flip (and both be proven) before the supervisor can be
deleted.

- **Workload VMM:** `AnyBackend::auto_select` macOS-26 tier → hvf runner
  (`backend.rs:566`).
- **Builder VMM:** `builder_backend_select::auto_detect_default_for(macos_26)`
  → hvf builder (`builder_backend_select.rs:91`). Note
  `builder_backend_select.rs:180-185`: Stage 0 is implemented for libkrun/QEMU;
  the Vz builder has a Stage-0 fallback quirk today. The hvf builder must
  carry Stage 0 to parity (part of Step-0 builder reachability).
- **`mvmctl dev` interactive shell** runs on the *builder* VM, not the
  workload — so the builder flip must preserve the dev shell.

## Collapse `hvf` → `hvf`

Today `--hypervisor hvf` resolves to `HvfBackend` (its own `start()` at
`crates/mvm-backend/src/hvf_backend.rs:174`) and `--hypervisor hvf`
resolves to the `WorkloadRunner` path — same VMM, two entrypoints. As part of
the tail, make the runner the macOS-26 default and delete `HvfBackend`'s
separate `start()` copy so we do not ship two hvf code paths. `hvf`/
`hvf` selectors converge on the runner.

## Sequenced plan (refined "B")

- **Step 0 — gate (mostly done).** Workload reachability + channel-1 outbound:
  PROVEN (see Step-0 results). Spike the vsock pre-open question. Builder
  reachability proof and the idiomatic inbound-stdin proof land with Steps 1–2.
- **Step 1 — stdin DX companion.** Drop `--stdin`; auto-detect non-TTY stdin
  (see companion section). Independent of the backend, ships DX value alone,
  and its acceptance test IS the channel-1 inbound proof
  (`echo … | machine run --hypervisor hvf -- /bin/cat`). Lands first.
- **Step 2 — flip + wire. PROVEN (2026-07-13).** Flip both defaults (workload `auto_select` +
  builder `auto_detect`) to the hvf runner / builder. Keep Vz reachable
  via explicit `--hypervisor vz` / `MVM_BUILDER_BACKEND=vz` for this step. Wire
  the dev-only interactive PTY shell (the console design above). Collapse
  `hvf` → runner as the default. After this, no non-interactive `machine run`
  or `dev` command touches Vz; `-it` works over the hvf runner in dev.
- **Step 3 — delete Vz.** Remove `vz.rs`, `vz_control.rs`, `VzTransport`
  (now `DevConsoleTransport`, kept), `mvm-vz-supervisor` (Rust bin + Swift),
  `is_vz_default_tier`, the Vz builder path (`vz_builder.rs`,
  `BuilderBackendChoice::Vz`), and Vz cases across `catalog` / `console` /
  `for_started_vm` / doctor. `HvfBackend`'s duplicate `start()` goes here too.

## Cross-repo caution (why B, not a one-pass hard delete)

The Vz deletion touches the `mvmctl::runtime::*` re-export surface that **mvmd**
(separate repo) consumes. Staging (Step 1 lands + proves the flip with Vz still
present, Step 2 deletes) gives a checkpoint to confirm mvmd still builds against
the intermediate state before the code is gone. Coordinate the Step-2 deletion
with mvmd's build. A single-pass delete (approach A) has no such checkpoint.

## Out of scope

- Interactive-shell-over-hvf in **production** (forbidden by claim 15 —
  channel 3 stays dev-only).
- KVM/WHP backends and the broader multi-backend seam (ADR-099) beyond what the
  `hvf`→`hvf` collapse requires.
- Changing channels 1–2 (production I/O and boot-console capture).
