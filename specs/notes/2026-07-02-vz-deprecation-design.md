# Vz deprecation — flip the macOS-26 default to the in-house VMM and delete Vz

Date: 2026-07-02
Umbrella: Plan 214 (clean-replacement architecture). This is the "flip default
+ delete Vz" tail of that plan.
Status: design approved; implementation plan pending.

## Problem

On macOS 26 Apple Silicon a bare `mvmctl machine run` still lands on the Vz
backend. `AnyBackend::auto_select` (`crates/mvm-backend/src/backend.rs:566`,
`is_vz_default_tier`) hard-returns `Self::Vz(VzBackend)`, and the builder VMM
auto-detect (`crates/mvm-build/src/builder_backend_select.rs:91`,
`auto_detect_default_for`) returns `Vz` on the same tier. The in-house VMM
(driven through `WorkloadRunner` over the `VmmDriver` seam, and
`InHouseBuilderVm` for the builder) is reachable only via explicit
`--hypervisor inhouse` / `MVM_BUILDER_BACKEND`. The additive comment in
`backend.rs` states the intent outright: "Vz remains the macOS-26 default until
HVF reaches workload parity."

Vz is the transitional macOS backend; the in-house Hypervisor.framework VMM is
the destination (ADR-098, ADR-100). We are removing Vz entirely: the backend,
its supervisor (Rust + Swift), its transport, its selection tiers, and every
Vz case.

## Non-negotiable gate (Step 0): the in-house path must be a proven replacement

The flip and the deletions are cheap and low-risk. The only real risk is
whether the in-house VMM is a *proven* replacement. Nothing flips until, on a
macOS-26 Apple Silicon host:

1. **Workload reachability** — `machine run --name X --hypervisor inhouse -d`
   boots a real OCI/mkGuest workload (e.g. alpine) to a **reachable agent**:
   `vm wait` / doctor reports `ready`, and an `invoke` / agent-ping round-trip
   succeeds.
2. **Production I/O round-trip (channel 1, below)** — a *production* run
   (`machine run --image X --stdin <payload> -- <cmd>`) delivers the stdin
   payload to the workload and returns stdout/stderr/exit over the in-house
   `agent.sock`. This proves the production host↔guest I/O channel works,
   independent of any dev shell.
3. **Builder reachability** — the in-house builder (`InHouseBuilderVm`) boots
   and runs a `nix build` (Stage 0 → workload kernel) to a usable artifact.

Prior verification (this investigation) only proved the *builder chain runs and
the workload console-attach fails*; it did **not** prove agent reachability or
the production I/O round-trip. Those are the gate.

## The three host↔guest channels (the security boundary we must not blur)

A production microVM is **not** mute. There are three distinct channels with
three different postures. The Vz-deprecation console work touches only the
third.

1. **Runner batch stdio — production, bidirectional, NOT gated.**
   `crates/mvm-guest/src/runner/mod.rs:20-34`: stdin is piped in (one-shot,
   hard-capped at 1 MiB in v1), the workload runs, and the child writes
   stdout/stderr back. Prod-hardened (`PR_SET_DUMPABLE=0` before the first
   stdin byte, `runner/hardening.rs`). This is how a production workload
   receives input and returns output. On the in-house runner it flows over the
   `agent.sock` the runner already stands up unconditionally
   (`workload_runner/runner.rs:92-98`). **Unchanged by this work.**

2. **Kernel/boot console — write-only capture, no host input fd.**
   `open_console_capture` (`crates/mvm-backend/src/libkrun.rs:119`) opens
   `console.log` write-only; `prod_console_attachment_has_no_input`
   (`libkrun.rs:1137`) asserts there is no guest console input path in prod.
   Guest→host only. The in-house runner already stands up write-only
   `console.log`. **Unchanged by this work.**

3. **Interactive PTY shell — dev-only (claim 15).** The live, bidirectional
   keystroke↔screen shell served by the agent's PTY-over-vsock console
   (`crates/mvm-guest/src/console.rs`, `run_console_relay`) plus `do_exec`.
   Feature-gated behind `dev-shell`; a sealed prod agent links no console
   symbol. This is the *only* channel that is dev-only, and the only one this
   work adds to the in-house backend.

Naming rule for the whole effort: the gate is on **serving an interactive
shell**, never on "the console" as a concept, and never on channels 1–2. A
production microVM keeps full non-interactive host↔guest I/O.

## Design: dev-only interactive PTY shell on the in-house runner

**Guest side:** unchanged. The agent's PTY console and `do_exec` are already
`dev-shell`-gated (claims 4, 15).

**Host side — runner gains a dev-gated `dev_console` pre-open.** When
`VmStartConfig` requests a dev console (the same signal libkrun/vz already
consume) *and* the image is not sealed, the in-house `WorkloadRunner` pre-opens
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
(`crates/mvm-cli/src/commands/vm/console.rs:31`) gets an in-house probe gated
on `is_dev_mode()` + the state-dir carrying the in-house marker, slotted where
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

**Open question for the plan, not the design:** whether the in-house runner's
host-side vsock bridge (`crates/mvm-backend/src/vmm/vsock.rs`) can pre-open
arbitrary guest ports on demand or needs the port set fixed at boot. Settle
with a short spike in Step 0; it only affects how the pre-open is wired, not
the boundary.

## Two flips, not one

`mvm-vz-supervisor` serves **both** the workload VMM and the builder VMM, so
both defaults must flip (and both be proven) before the supervisor can be
deleted.

- **Workload VMM:** `AnyBackend::auto_select` macOS-26 tier → in-house runner
  (`backend.rs:566`).
- **Builder VMM:** `builder_backend_select::auto_detect_default_for(macos_26)`
  → in-house builder (`builder_backend_select.rs:91`). Note
  `builder_backend_select.rs:180-185`: Stage 0 is implemented for libkrun/QEMU;
  the Vz builder has a Stage-0 fallback quirk today. The in-house builder must
  carry Stage 0 to parity (part of Step-0 builder reachability).
- **`mvmctl dev` interactive shell** runs on the *builder* VM, not the
  workload — so the builder flip must preserve the dev shell.

## Collapse `hvf` → `inhouse`

Today `--hypervisor hvf` resolves to `HvfBackend` (its own `start()` at
`crates/mvm-backend/src/hvf_backend.rs:174`) and `--hypervisor inhouse`
resolves to the `WorkloadRunner` path — same VMM, two entrypoints. As part of
the tail, make the runner the macOS-26 default and delete `HvfBackend`'s
separate `start()` copy so we do not ship two in-house code paths. `hvf`/
`inhouse` selectors converge on the runner.

## Sequenced plan (refined "B")

- **Step 0 — gate, no default flip.** Prove workload reachability, the
  production I/O round-trip, and builder reachability on macOS-26 (see gate
  above). Spike the vsock pre-open question.
- **Step 1 — flip + wire.** Flip both defaults (workload `auto_select` +
  builder `auto_detect`) to the in-house runner / builder. Keep Vz reachable
  via explicit `--hypervisor vz` / `MVM_BUILDER_BACKEND=vz` for this step. Wire
  the dev-only interactive PTY shell (the console design above). Collapse
  `hvf` → runner as the default. After this, no non-interactive `machine run`
  or `dev` command touches Vz; `-it` works over the in-house runner in dev.
- **Step 2 — delete Vz.** Remove `vz.rs`, `vz_control.rs`, `VzTransport`
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

- Interactive-shell-over-in-house in **production** (forbidden by claim 15 —
  channel 3 stays dev-only).
- KVM/WHP backends and the broader multi-backend seam (ADR-099) beyond what the
  `hvf`→`inhouse` collapse requires.
- Changing channels 1–2 (production I/O and boot-console capture).
