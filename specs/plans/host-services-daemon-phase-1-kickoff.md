# Kickoff prompt — Plan 202 Phase 1 (host-services broker daemon + control plane)

> Paste this into a fresh session to implement Phase 1. It is self-contained; do not assume prior context.
> Filename is deliberately non-numeric so it does not trip `xtask check-spec-numbers` (which fails on duplicate `NNN-` plan prefixes).

## Mission

Implement **Phase 1 of [Plan 202](202-host-services-daemon.md)** under **[ADR-084](../adrs/084-host-services-daemon-not-per-vm-spawn.md)**: replace the per-VM *fork* of `mvm-broker` with a **long-lived, per-tenant broker daemon** that VMs **register/deregister** with. Phase 1 is the broker only — the audit-signer daemon is Phase 2, do not touch it yet beyond what register/forward requires.

## Read these first (in order)

1. `specs/adrs/084-host-services-daemon-not-per-vm-spawn.md` — the decision, the moat, why per-tenant, the control-plane shape, crash semantics.
2. `specs/plans/202-host-services-daemon.md` — Phase 1 tasks 1a–1d + the invariants list. **Your work is bounded by Phase 1; do not start Phases 2–6.**
3. `crates/mvm-backend/src/broker_services_spawn.rs` — the current per-VM fork you are replacing (`spawn_broker_services_if_admitted`, `spawn_broker`, the reaper, the `BrokerServicesGuard`). Note the call sites in `libkrun.rs` and `vz.rs` `start()`.
4. `crates/mvm-hostd/src/broker/` — the broker server, dispatch, registry, `host_audit_v1` handler, `ServiceCall`/`ServiceResponse` wire. `src/bin/mvm-broker.rs` is the current per-VM binary entry.
5. `crates/mvm-hostd/src/broker/handlers/host_audit_v1.rs` — claim-12 binding gate, the 20/s token bucket, the 4 KiB cap, the `workload_audit` stamp. These behaviors must survive unchanged, now keyed by `vm_id`.

## Phase 1 scope (tasks 1a–1d from the plan)

- **1a — control protocol.** `RegisterVm { vm_id, tenant, broker_listen_socket, services_bindings, workload_chain_path }` / `DeregisterVm { vm_id }`, **host-signed**, framed on a per-tenant control UDS `<run>/broker-control-<tenant>.sock` (mode 0700, host-owned). Use the host signer identity that already signs plans. Tests: serde roundtrip, tampered-signature rejection.
- **1b — daemon skeleton.** `mvm-broker` becomes a resident per-tenant process: accept on the control socket, hold a `vm_id → { listen_socket, bindings, rate-bucket }` map, **bind/unbind each VM's `BROKER_PORT` socket dynamically** on register/deregister, demux accepted guest connections to a `vm_id` **by which socket accepted them**. Reuse the existing `ServiceCall` dispatch + claim-12 gate verbatim.
- **1c — `ensure_daemon` + `register_vm`.** New `mvm_backend` seam replacing the `spawn_broker` call in `start()`: lazily start the per-tenant broker (idempotent — pid/lock under the run dir so concurrent `mvmctl up`s converge on one daemon, never racing two) and send `RegisterVm`. `stop()` sends `DeregisterVm`; it does **not** tear the daemon down (stays warm).
- **1d — server-derived identity.** Assert in tests that the dispatched `vm_id` comes from the accepting socket, never from the guest frame — a frame claiming another `vm_id` cannot reach that VM's bindings. (Same discipline as the server-authoritative `correlation_id` the broker already mints.)

## Invariants you must hold (from the ADR/plan)

- **The moat stays:** the broker holds **no keys**. It only forwards "sign this" to the (still per-VM, for now) audit-signer. Do not move the signing key into the broker.
- **`vm_id` and `correlation_id` are server-derived**, never guest-supplied.
- **Control plane is host-only** (mode 0700, host-signed) — never guest-reachable. No new guest-facing port, verb, or frame.
- **Guest-facing wire is byte-identical** — the SDK veneer and the in-guest `audit-probe` must keep working unchanged. The supervisor still splices `connect_host_vsock(BROKER_PORT)` to the backend-specific `broker_listen_socket` (libkrun `vm_vsock_port_socket`, vz `vm_vz_vsock_port_socket` — see `mvm_core::config`).
- Claim 12 (binding-gated dispatch), the 20/s rate limit, the 4 KiB cap — preserved, keyed by `vm_id`.

## Explicitly NOT in this phase

- The audit-signer daemon (Phase 2) — leave the per-VM signer as-is; the broker still forwards to it. Only thread the server-derived `vm_id` through the forward so Phase 2 can route.
- Decoupling availability from `MVM_GATEWAY_BRIDGE` (Phase 3).
- Crash/restart journal + supervision (Phase 4).
- mvmd adoption (Phase 5).
- Removing `spawn_broker_services_if_admitted` (Phase 6) — keep the audit-signer half of it; only the broker half moves to the daemon.

## Repo conventions (do not skip — these are CI-gated)

- **Work in a git worktree off `origin/main`**, not the main checkout. `git fetch origin` first.
- **Check `gh pr list` + recent `git log origin/main` before starting** — a parallel session may already own `broker_services_spawn.rs` / the broker. Coordinate; do not duplicate (this exact dup happened on the vz-socket fix, #970 vs #971).
- Gates before every push: `rustup run nightly cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo check --workspace --all-targets`; full `cargo test -p <crate>` for crates you touch (`mvm-hostd`, `mvm-backend`); `cargo run -p xtask -- check-no-spec-refs-in-comments`; `cargo run -p xtask -- check-core-runtime-free`.
- **Homebrew `rustc` shadows rustup** on this Mac — pin to the rustup toolchain (`PATH="$(dirname "$(rustup which rustc)"):$PATH"`) or gates see the wrong compiler and target dirs cross-contaminate (E0514).
- **No spec/PR/ADR citations in code comments** — keep the reasoning, drop the citation (the `check-no-spec-refs-in-comments` lint enforces this). ADRs/plans cite each other freely; code does not.
- **No `Co-Authored-By: Claude` trailer**; attribute to the user.
- Keep `specs/plans/202-host-services-daemon.md` checkboxes + `specs/REFACTOR-STATUS.md` current in the same change as the code.
- Prefer small testable functions, builder/struct params over long arg lists (`#[allow(clippy::too_many_arguments)]` is banned), and a trait over scattered backend `match`es.

## How to verify (live)

Phase 1 is host-side, so unit/integration tests cover most of it (register → bind → dispatch → deregister → unbind; concurrent-`up`-converges-on-one-daemon; server-derived `vm_id`). For the end-to-end smoke, reuse the E5.3b-4 libkrun round-trip:

- Build: `cargo build --bin mvmctl`; `cargo build -p mvm-hostd --bin mvm-broker --bin mvm-audit-signer`; `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys`.
- Boot the `examples/audit-probe` fixture (baked by the `withAuditProbe` mkGuest flag) on **libkrun**, real `~/.mvm` (the bridge supervisor pins the host-signer key under `~/.mvm/keys`), warm shared `~/.cache/mvm`, `MVM_BUILDER_BACKEND=libkrun`. Until Phase 3, `host.audit.v1` availability still needs `MVM_GATEWAY_BRIDGE=1`.
- The probe emits in-guest; entries land in `~/.mvm/audit/local.<vm>.workload.jsonl`. Verify the **workload chain** clean in isolation: copy it + the real `~/.mvm/keys/host-signer.ed25519` into a temp `MVM_DATA_DIR/{audit,keys}` (no `local.jsonl`) and run `mvmctl trust audit verify --tenant local` — it must report the workload chain clean. (Verifying against real `~/.mvm` directly trips on a pre-existing corrupt shared `local.jsonl`; that's not your bug.)
- Run live tests **backgrounded + `gtimeout`**, log to files; never unbounded. Clean up `~/.mvm/vms/<vm>` + the workload chain after.

## Definition of done for Phase 1

- `mvm-broker` runs as a resident per-tenant daemon; `start()` registers, `stop()` deregisters, the daemon stays warm across VM churn; concurrent `up`s converge on one daemon.
- Guest-facing wire unchanged; the live libkrun round-trip + isolated `verify_workload_chain` still green (with `MVM_GATEWAY_BRIDGE=1`, since Phase 3 hasn't landed).
- Server-derived `vm_id` proven by test; claim-12 / rate-limit / cap tests still green.
- All gates clean; Plan 202 Phase 1 checkboxes ticked; PR scoped to Phase 1 only.
