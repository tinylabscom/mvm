# Plan 125 E5 — host-services SDK (workload → broker): scoping note

**Status:** scoped, not yet built. E5 is the sole remaining Plan 125 task
(Phases A–D + E1–E4 are done). This note grounds the build so it can run as its
own focused PR (it is security-critical — claims 8/12/13 — and the headline
acceptance test needs a live VM, so it is deliberately *not* rushed at the tail
of the E1–E4 batch).

## What exists today (verified on `main`)

- **Host broker is built** (Plan 104): `mvm-hostd/src/supervisor/services/broker_proxy.rs`
  proxies `host.time.v1` / `host.cost.v1` / `broker.v1`; the three broker
  subprocesses live under `mvm-hostd/src/broker/`.
- **Protocol types exist** in `mvm_core::protocol::broker`:
  - `ServiceCall { service: ServiceId, verb: String, correlation_id: CorrelationId, payload: serde_json::Value }`
  - `ServiceResponse::{ Ok { correlation_id, payload }, Err { correlation_id, code: ServiceErrorCode, message } }`
  - `ServiceId` (validated), `CorrelationId`, `ServiceErrorCode`, `Idempotency`, `AuditDurability`.
- **Wire format** (from `broker_proxy.rs` + its mocks): a `u32` big-endian
  length prefix followed by the `serde_json` body of `ServiceCall` /
  `ServiceResponse`. Host side frames via `supervisor/services/frame.rs`
  (`read_frame`/`write_frame`/`connect`, `DEFAULT_MAX_FRAME_BYTES`).
- **The guest already has the transport primitives** in
  `mvm_guest::vsock`: `connect_to_port(uds_path, port, timeout)`,
  `read_frame`/`write_frame` (same length-prefixed shape). The E5 transport
  builds on these — it does NOT need a new socket/framing stack.
- **No guest-side broker caller exists** (`rg` across `mvm-guest` / `mvm-sdk`
  finds none). Confirmed — this is the gap E5 fills.

## The three layers (per the plan)

1. **Guest-side broker client / transport** — opens the broker's guest-facing
   vsock port, writes a framed `ServiceCall`, reads a framed `ServiceResponse`,
   carries the plan-bound session (claim 12). Lives in `mvm-sdk`'s runtime.
   This is the foundational piece all broker services ride on.
2. **Typed service methods** — `host.audit.v1` / `host.time.v1` /
   `host.cost.v1` wrappers on the transport. The `host.audit.v1` handler forces
   `category: workload_audit`, stamps host-authoritative IDs, rate/size-caps,
   and chain-signs via `mvm-audit-signer` (claim 8 preserved).
3. **SDK veneer** — `mvm.audit.emit/emit_batch`, `mvm.host.time()`,
   `mvm.host.cost()`, exposed to in-guest Python/TS via PyO3/napi. NB: this is
   the *in-guest runtime* SDK (baked into the image), distinct from the
   host-side `sdks/` that shell to `mvmctl` (ADR-0010).

## Open questions to resolve FIRST (don't guess — claim-12 surface)

1. **Guest-facing broker vsock port.** `broker_proxy.rs` connects host-side over
   a UDS; the guest→host path goes over vsock through the supervisor. Find the
   exact port the supervisor exposes for broker calls (grep the supervisor
   vsock port all-list / the proxy-port wiring; W1.3 "proxy port allowlist").
2. **Session binding (claim 12).** How does a `ServiceCall` prove it belongs to
   the admitted `ExecutionPlan.services` binding? Is the binding carried in the
   frame (an `AuthenticatedFrame` wrapper — `mvm_core::policy::security`), or
   enforced purely host-side by the connection's identity? `broker_proxy.rs`
   returns `"service <x> not bound"` — read where that bound-set comes from and
   what the guest must present. **This is the security crux; build nothing
   until it's pinned.**

## Test matrix

- **Unit (no VM):** transport framing roundtrip; oversize-frame rejection;
  `ServiceResponse::Err` propagation as a typed error; tampered/short frame
  rejection; `host.audit.v1` request shape (forces `workload_audit`); a >4 KiB
  record refused (`BadRequest`); rate-limit (20/s) trip surfaced as the typed
  error. These mirror the existing `broker_proxy.rs` mock-I/O tests and are the
  bulk of the coverage.
- **Live-VM E2E (gated, box):** `mvm.audit.emit({...})` from inside a `Sandbox`
  lands a `workload_audit` entry visible in `mvmctl audit verify`, host-stamped
  + workload-originated; a workload can never write a host-category entry.

## Recommended slicing

- **E5.1** — transport (Layer 1) in `mvm-sdk` runtime over `mvm_guest::vsock`,
  with mock-I/O unit tests (roundtrip, oversize, err-propagation, tamper).
  Resolve the two open questions before this lands.
- **E5.2** — typed `host.audit.v1` method + the request-shape / cap / rate-limit
  unit tests (claim 8 preserved: handler forces `workload_audit`).
- **E5.3** — PyO3/napi veneer (`mvm.audit.emit`) + the live-VM E2E (box).
- **E5.4** — `host.time.v1` / `host.cost.v1` typed methods + veneer (ride the
  same transport).

Binding-gated dispatch + no-payload-in-errors are gated in Plan 128
(claims 12/13).
