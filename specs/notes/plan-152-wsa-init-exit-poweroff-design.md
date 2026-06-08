# Design — Plan 152 WS-A: guest `/init` exit-code / poweroff parity

> **Status (2026-06-07):** Brainstormed, approved. Scoping/design artifact
> for **Plan 152 WS-A** (roadmap S2 in `specs/plans/163-...`). The numbered
> implementation plan is produced from this via writing-plans.
>
> **Naming:** the external VZ project that supplies the `/init` exit
> contract is referred to obliquely ("the reference") per repo policy;
> oblique-reference key in auto-memory `reference_objc2_vz_external_references`.

## Goal

Give a finished **one-shot sealed workload** a clean terminal-exit path:
PID-1 `/init` runs the workload, captures its exit code, reports it to the
host over a dedicated control vsock port, `sync`s, and `poweroff -f`. The
host captures the code, surfaces it as `VmExitStatus`, records a
chain-signed `plan.exited` audit entry, and `mvmctl` returns it as its own
exit status.

## Framing reconciliation (the plan's premise was partly stale)

Exploration (2026-06-07) found:

- **The exit code already flows for the persistent agent/function path.**
  `entrypoint.rs:570` captures `CallOutcome::Exited{code}` and the agent
  returns `EntrypointEvent::Exit{code}` over the agent vsock port 5252
  (`mvm-guest-agent.rs:1792`); the host reads it on the `invoke`/`exec`
  path. `mvm-core` even has an unused `VmExitStatus{code,success}`
  (`vm_backend.rs:355`).
- **PID-1 does not reboot today.** It idles (`dev` → `sleep infinity`,
  `mk-guest.nix:489`) or, on the prod/sealed path, sources `/etc/mvm/boot`
  and **panics if it returns** (`mk-guest.nix:532`). The plan's named
  Plan-120 "reboot strands the agent" root cause (the entrypoint
  collision) is **already fixed** by the boot/entrypoint split
  (`mkFunctionWorkload.nix:128`).
- **Host side has no exit capture, audit, or propagation.** libkrun's
  supervisor blocks in `krun_start_enter` (which `exit()`s on guest
  poweroff) and the parent never reads status (`libkrun.rs:325`); audit
  has `plan.launched`/`plan.failed` but no `plan.exited`; `mvmctl up`/`run`
  doesn't propagate a workload exit code (only `mvmctl exec` does).

So the genuine remaining gap is a clean **exit-code-carrying terminal
poweroff** for the one-shot path, plus host capture/audit/propagation.

## Decisions

- **D1 — Lifecycle target: the one-shot PID-1 contract (Model B).** PID-1
  *is* the workload command → capture `$?` → report → `sync` →
  `poweroff -f`. The persistent agent/function-service path (Model A)
  already carries the code and stays warm for reuse — **out of scope**.
- **D2 — Exit channel: dedicated control vsock port.** Confirmed clean:
  libkrun's `add_vsock_port2(port, path, listen=false)` (`sys.rs:247`)
  has the host bind a unix listener and proxies guest-initiated connects
  to it — exactly a guest→host control channel, no new mount. Reuses the
  established `<vm_state_dir>/vsock-<port>.sock` convention.
- **D3 — Backend scope: libkrun-first; guest contract backend-agnostic;
  Vz host-side deferred to WS-B.** The guest `/init` change + the
  `mvm-exit-report` helper + the shared host-capture unit + the control
  contract are backend-agnostic and land once. The libkrun supervisor
  wiring + E2E land now. Vz host-side capture is **deferred to WS-B**
  (the Rust-objc2 supervisor rewrite) so we never write it against the
  Swift supervisor WS-B deletes.

## Interaction with the upcoming Vz refactor (WS-B)

WS-A is **complementary and de-risking, not conflicting**:

- The backend-agnostic pieces (guest `/init` contract, `mvm-exit-report`,
  control-port constant + wire format, `workload.exit` convention,
  `VmExitStatus` surfacing, `plan.exited` audit, `mvmctl` propagation) are
  built once and **reused as-is by WS-B**.
- The **host-capture logic is factored as a shared, backend-agnostic
  unit** (accept on control socket → parse `i32` → persist
  `workload.exit`), explicitly so WS-B's new Rust Vz supervisor calls the
  same function — the control port just becomes one more port in its mux.
- The only Vz-specific work (supervisor binds the control listener) is
  deferred to WS-B by design → **zero throwaway Swift work**.

WS-A effectively *defines the contract* WS-B implements for Vz.

## Components

1. **Control-port constant + wire format** — `mvm-guest/src/vsock.rs`:
   `WORKLOAD_EXIT_PORT = 5251` (adjacent to the agent's `GUEST_AGENT_PORT
   = 5252`; clear of `PORT_FORWARD_BASE = 10000`+ and the `21470`+ builder
   ports) and a 4-byte little-endian `i32` wire format. Shared by guest,
   helper, both supervisors.
2. **`mvm-exit-report` helper** — new `[[bin]]` in `mvm-guest-helpers`:
   `mvm-exit-report <code>` connects `AF_VSOCK` (CID=host, the control
   port), writes the `i32`, exits. std-only; baked into the rootfs by
   mkGuest (mirrors `mvm-addon-dns`/`mvm-addon-vsock-bridge`).
3. **Guest `/init` terminal contract** — `nix/lib/mk-guest.nix`: on the
   prod/sealed path, replace "source boot cmd → panic-on-return" with: run
   the boot command → capture `$?` → `mvm-exit-report $?` → `sync` →
   `poweroff -f`. Dev path (idle loop) unchanged; persistent
   function-services (`exec sleep infinity`) never return, so unaffected.
4. **Shared host-capture unit** — backend-agnostic fn (in `mvm-vm-host`
   or `mvm-backend`): accept on the control socket → parse the `i32` →
   persist `<vm_state_dir>/workload.exit`. The unit WS-B reuses.
5. **libkrun supervisor wiring** — `mvm-libkrun-supervisor`: register the
   control port via `add_vsock_port2(listen=false)` and run the shared
   capture on an accept-thread before `krun_start_enter`.
6. **`VmExitStatus` surfacing** — libkrun backend reads `workload.exit`
   after stop → the existing `VmExitStatus{code,success}`.
7. **Audit `plan.exited`** — `AuditEmitter::emit_exited(plan, code,
   backend)` in `crates/mvm-cli/src/commands/vm/audit_chain.rs`,
   chain-signed alongside `plan.launched`/`plan.failed`.
8. **`mvmctl` propagation** — `up`/`run` reads the captured code and exits
   with it (mirrors `exec.rs`'s existing `process::exit(code)`).

## Data flow

`/init` runs workload → `$?` → `mvm-exit-report` → control vsock →
supervisor accept-thread → `<vm_state_dir>/workload.exit` → guest
`poweroff -f` → `krun_start_enter` returns → backend reads `workload.exit`
→ `VmExitStatus` → `plan.exited` (audit) + `mvmctl` exit status.

## Error handling (fail-closed, never hang)

- **No code reported** (crash, signal, kill, timeout before report):
  `workload.exit` absent → `VmExitStatus{code:None,success:false}`; audit
  records the terminal event with no code; `mvmctl` exits non-zero
  (conventional `1`) and logs the cause.
- **Malformed/partial control write**: supervisor treats it as "no code"
  — never trusts a partial frame.
- **`poweroff -f` applet missing**: `/init` falls back to the existing
  terminal behavior, logged (shouldn't happen — busybox is baked).

## Testing & verification

- **Unit:** shared-capture parses an `i32` from a mock `UnixStream` +
  writes `workload.exit`; `mvm-exit-report` wire-format round-trip;
  `emit_exited` shape.
- **E2E on the libkrun host** (`project_dev_host_runs_builder_via_vz`;
  isolate with `MVM_CACHE_DIR`/`MVM_DATA_DIR`): a non-zero-exit one-shot
  fixture (`examples/exit_code`) → `mvmctl` returns that code;
  `mvmctl audit verify` shows `plan.exited` with the code; the VM actually
  powered off (console.log / supervisor reaped, not idling). Never run
  `core_demo_e2e` unbounded (`feedback_never_run_core_demo_e2e_unbounded`).
- **Gates:** `rustup run nightly cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`, `cargo nextest run`
  (mvm-backend excluded locally per
  `reference_mvm_backend_test_binary_macos_codesign_sigkill` → Linux CI),
  `cargo test --doc`. `mvm-libkrun-supervisor` must be rebuilt explicitly
  with `--features libkrun-sys` (`reference_libkrun_supervisor_required_features`).

## Scope / non-goals

- **In:** components 1–8, libkrun host path + E2E, backend-agnostic guest
  contract.
- **Out (by design):** Vz host-side capture (→ WS-B, reuses the shared
  unit); the persistent agent/function-service path (Model A — already
  carries the code); Firecracker / apple_container (no per-VM supervisor
  today); reboot semantics (we `poweroff -f`, never reboot).

## References

- `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md` — WS-A
  (this) + WS-B (the Vz supervisor that reuses the shared unit).
- `specs/plans/163-vz-support-execution-roadmap.md` — S2 = this.
- `nix/lib/mk-guest.nix` (`/init`), `nix/lib/factories/mkFunctionService.nix`
  — guest contract edit sites.
- `crates/mvm-guest/src/vsock.rs`, `crates/mvm-guest/src/entrypoint.rs` —
  ports + existing exit capture (Model A).
- `crates/deps/libkrun-sys/src/sys.rs:247` — `add_vsock_port2(listen=false)`.
- `crates/mvm-backend/src/libkrun.rs`, `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs`
  — host wiring.
- `crates/mvm-cli/src/commands/vm/audit_chain.rs` — `plan.exited`.
- `crates/mvm-core/src/protocol/vm_backend.rs:355` — `VmExitStatus`.
</content>
