# Plan 221 — dev-only interactive `-it` console on the in-house VMM

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Make `mvmctl machine run --image X -it -- /bin/sh` drop into an interactive shell over the **in-house** backend (`--hypervisor inhouse` / the `WorkloadRunner`), as a DEV-ONLY affordance — the prerequisite for flipping the macOS-26 default off Vz (Plan 214 tail).

**Architecture:** The in-house runner today exposes only `agent.sock` + write-only `console.log`, and `pick_console_transport` has no in-house case, so `-it` fails at console attach. This plan gives the runner a **dev-gated `dev_console` pre-open** (mirroring libkrun/vz) that binds the guest console data-port range as host UDS, plus a backend-neutral `DevConsoleTransport` + an in-house probe in `pick_console_transport`. The one new device mechanism is a `ConsoleBridge` in `vmm/vsock.rs` — a clone of the existing `AgentBridge` — that host-dials arbitrary console ports.

**Source:** spike 2026-07-02 (in-session); design `specs/notes/2026-07-02-vz-deprecation-design.md` §"Design: dev-only interactive PTY shell".

## Global Constraints
- Claim 15: sealed prod must link/open nothing. The pre-open binds host UDS ONLY when `config.dev_console` is true (matches `libkrun.rs:316` / `vz.rs:2025`); the guest console verbs are already `dev-shell`-gated; `enforce_accessible_gate` (`console.rs:91`) refuses sealed attach.
- No backwards-compat shims. No `#[allow(clippy::too_many_arguments)]`. No plan/PR/ADR citations in code comments.
- Reuse the existing Vz socket-path convention `<vm_state_dir>/vsock/vsock-<port>.sock` (`vm_vz_vsock_port_socket`, `config.rs:451-467`) — do not invent a new layout.
- `fmt --all` / `clippy -D warnings` / `nextest` green; live-proof required (Task 7).

## Established facts (spike, with anchors)
- Dev signal: `VmStartConfig.dev_console: bool` (`crates/mvm-core/src/protocol/vm_backend.rs:136-146`), set for dev-accessible machines (`up.rs:1207`).
- Port range: `mvm_guest::vsock::dev_console_data_ports()` = 20001..=20128 (`crates/mvm-guest/src/vsock.rs:87-105`).
- Console protocol = TWO host connects over one transport: open on `GUEST_AGENT_PORT` → receive `data_port` → connect `data_port` (`console.rs:251,264-268,282-284`). Guest binds a vsock listener on `CONSOLE_PORT_BASE+session_id` (`guest/console.rs:142-143,336-391`).
- In-house host-dials is nailed to the agent port and REJECTS other ports: `inhouse.rs:311-330` (`vsock_connect` bails on `guest_port != GUEST_AGENT_PORT`); device frames host packets to `GUEST_AGENT_PORT` at `vmm/vsock.rs:474,481`; replies routed via `is_agent_stream` at `vsock.rs:342`. `AgentBridge` = single `Option<UnixListener>` (`vmm/agent_bridge.rs:40-42,64-69`).
- Standing sockets are a fixed 3-tuple (agent/exit/console_log) with no console-data entries: `workload_runner/runner.rs:86-98`; spec omits console ports by design (`spec_map.rs:71-91`). Supervisor config has fixed socket fields (`hvf_supervisor.rs:79-92`); device wired at `hvf/kernel_boot.rs:481-505`.

## Sequencing gate (READ FIRST)
`vmm/vsock.rs` + `vmm/run.rs` are being edited by a parallel session (in-house agent-reachability poll-starvation fix; see memory `project_inhouse_agent_reachability_root_cause`). **Task 5 (ConsoleBridge) must land after that fix** to avoid a three-way merge in the `poll()`/`drain_*`/`flush_rx` surface. Tasks 1–4 and 6 are collision-free and may proceed immediately. Build the bridge as a NEW `ConsoleBridge` field + a third `drain_console()` in `poll()` — do NOT modify `drain_agent`/`flush_rx` semantics (the framing is already port-agnostic; only callers pin the port).

---

## Task 1 — `dev_console` console-data sockets in the runner (collision-free)
**Files:** `crates/mvm-backend/src/workload_runner/runner.rs` (StandingSockets 86-98, standing_sockets, start/start_workload 115-198); test in same file.
Add console-data UDS paths (Vz shape `<state_dir>/vsock/vsock-<port>.sock` for each `dev_console_data_ports()`), populated into `StandingSockets` and pre-bound ONLY when `config.dev_console`. Thread the (port→path) list into the `VmmSpec`/supervisor request.
**Test:** with `dev_console=true`, the spec/standing-sockets carry all 128 console-port paths under `vsock/`; with `dev_console=false`, none. (Unit-testable via `MockDriver`/`RecordingSpawner`, per existing `spec_map` tests.)

## Task 2 — supervisor config carries the console sockets (collision-free)
**Files:** `crates/mvm-build/src/hvf_supervisor.rs:79-92` (+ its parser/tests).
Add `console_data_sockets: Vec<(u32, PathBuf)>` (default empty; `#[serde(default)]`). Serde roundtrip + `deny_unknown_fields` test.

## Task 3 — thread console sockets through the driver + allow the port range (collision-free)
**Files:** `crates/mvm-backend/src/driver/inhouse.rs` (relay_supervisor_config 92-150; vsock_connect 311-330).
Populate `console_data_sockets` in the relayed config; relax `vsock_connect` so a port in `dev_console_data_ports()` is dialable (return the console UDS) instead of bailing. Keep non-agent, non-console ports rejected.
**Test:** `vsock_connect(GUEST_AGENT_PORT)` and a console port both resolve; an out-of-range port still bails.

## Task 4 — `DevConsoleTransport` + in-house probe in the picker (collision-free)
**Files:** `crates/mvm/src/vsock_transport.rs` (new transport, mirror `VzTransport` 117-143); `crates/mvm-cli/src/commands/vm/console.rs:31-63` (pick_console_transport).
Add `DevConsoleTransport::for_vm` dialing `<vm_vz_vsock_dir>/vsock-<port>.sock` (reuse `vm_vz_vsock_port_socket`). Add an in-house arm to `pick_console_transport` gated on `is_dev_mode()` + an in-house state marker, slotted where the vz probe sits. **Extend** the two existing boundary tests (`pick_console_transport_does_not_route_workload_to_dev_socket`, `..._selects_dev_socket_for_dev_vm`) — do not weaken them.

## Task 5 — `ConsoleBridge` in the device (GATED on parallel merge)
**Files:** `crates/mvm-backend/src/vmm/vsock.rs` (new `ConsoleBridge` mirroring `agent_bridge.rs`); `crates/mvm-backend/src/vmm/run.rs:228-235` (add `drain_console()` as a third poll drain); `crates/mvm-backend/src/hvf/kernel_boot.rs:481-505` (wire console sockets next to `set_agent_socket`).
A per-console-port host→guest bridge: on a host connect to `<state_dir>/vsock/vsock-<port>.sock`, open the guest vsock listener on that port (reuse `queue_host_packet` with the real port, not the hardwired agent port; route replies by conn-id, not `is_agent_stream`). Add `drain_console()` to `poll()` as a NEW drain alongside `drain_agent`/`drain_substitution` — no changes to their bodies.
**Test:** mock-scripted vCPU: a host connect on a console port opens the guest listener and streams bytes both ways; agent + substitution paths unchanged.
**Do not start until the parallel poll-starvation fix has merged to main; rebase first.**

## Task 6 — end-to-end wiring + fmt/clippy/nextest (partial: needs Task 5)
**Files:** touch points from Tasks 1–5.
Confirm `machine run -it --hypervisor inhouse` resolves `dev_console=true` and the picker selects `DevConsoleTransport`. Full gate green on `mvm-backend`, `mvm`, `mvm-cli`.

## Task 7 — LIVE proof (manual, dev host)
`cargo build -p mvmctl -p mvm-vm-host --bin mvmctl --bin mvm-hvf-supervisor`, then from a real TTY:
`./target/debug/mvmctl machine run --image alpine -it --hypervisor inhouse -- /bin/sh` → an interactive shell prompt; `uname -a` etc. returns; exit cleanly. Record the result and flip the design note's "-it in-house" line to PROVEN. Also verify claim 15: the same against a sealed image is REFUSED by `enforce_accessible_gate`.

---

## After Plan 221 → Plan 222 (flip + delete)
Once `-it` in-house is live-proven, flip `auto_select` (`backend.rs:566`) + builder `auto_detect_default_for` (`builder_backend_select.rs:91`) to in-house, collapse `hvf`→runner, then delete Vz (`vz.rs`, `vz_control.rs`, `mvm-vz-supervisor`, `is_vz_default_tier`, `vz_builder.rs`, Vz cases) — coordinating the `mvmctl::runtime::*` deletion with mvmd's build.
