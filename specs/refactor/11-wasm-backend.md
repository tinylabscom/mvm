# WS11 — the `WasmBackend` seam (DESIGN)

Design of record for the wasm-container core goal: a `WasmBackend` that runs a
workload as a WASI module under the same `VmBackend` + Workload-IR + host
egress/audit contract every microVM backend uses — reaching hosts with no
KVM/HVF (CI runners, edge, the browser), and proving the design supports *more
backends from one model*. Builds on the boundary set in
[ADR-024](../adrs/024-wasm-sandbox-backend.md) and the intent in
[02-architecture.md](02-architecture.md) §"Wasm-container backend & `no_std` core".

## Scope (decided)

`WasmBackend` is the **claim-free portability / demo / browser tier**:
host-side `wasmtime`, opt-in, honest capability matrix, **zero numbered
security claims** (ADR-024's three constraints, verbatim). It runs a
**user-supplied WASI module** as-is — not an mvm-compiled workload.

Explicitly **out of scope** (deferred, separable): executing *attacker-controlled
production* workloads under a host wasm engine. ADR-024 requires that path to run
the engine as a guest binary *inside a real microVM* (engine-in-guest), never as
a host dependency — so it is a future concern, not part of `WasmBackend`.

This resolves the apparent tension between ADR-024 (cautious: "claims no
isolation") and 02-architecture (ambitious: "same security model, WASI
transport"): both hold once the tier is scoped. `WasmBackend` does **not** claim
*isolation* — but it still enforces the *governance* half of the model
(default-deny egress, secret substitution, PII masking, the chain-signed audit
log), so even the demo tier is honest and audited. It just never pretends to be
a hardware isolation boundary.

## Foundation — already done (Increment 3)

The enabling discipline landed with the `mvm-protocol` extraction:
`mvm-protocol` is `#![no_std] + alloc + forbid(unsafe_code)`, holds the Workload
IR + wire protocol + policy/audit DTOs + the audit-log verifier, and builds on
`wasm32-unknown-unknown` in CI. mvm's core contract already compiles into the
wasm sandbox and the browser.

**One foundation gap remains** (WS11 bullet 1's "…and its tests running under
wasm"): the CI `wasm32` build is a *library* build. A `wasm32` **test** pass is
not wired, and there is no explicit `no_std`-boundary lint beyond "the lib
builds on wasm32". P1 closes both.

## The three open questions — resolved

1. **What is a wasm workload?** A **user-supplied WASI module** (Preview 2 /
   component model), run as-is. The honest portability story ("bring a wasm
   module, run it with no KVM"). mvm-compiled-workload→wasm is a larger,
   separable effort, not this.
2. **Overlay/agent mapping with no Linux init?** **There is no in-guest agent.**
   A wasm instance has no PID 1, no vsock, no `mvm-agentd`. The agent's
   *responsibilities* — egress mediation, secret substitution, audit — move
   entirely host-side and are reached through **WASI host-imports**: the module's
   WASI socket/HTTP calls are serviced by the host and run through the same
   default-deny / substitute / audit seam. "runtime-overlay + agent" collapses to
   "host-provided WASI imports." (`rootfs`/overlay mount ordering is moot — a
   wasm module has no block device; its "filesystem" is WASI preopens the host
   grants, governed by the same fs-policy projection.)
3. **Browser `mvm-fs` slice?** The **`no_std` OCI layer decoders only** (manifest
   + layer parse, the pure-Rust reader path) — enough to *inspect/verify* an
   image in the browser. Not ext4 materialization (no block device in a browser).
   Anything needing `std`/fs stays out of the browser slice.

## The seam

- **`BackendKind::Wasm`** joins the `backend_catalog!` registry (Increment 3's
  typed dispatch — never string-matched). Capability descriptor: `is_workload =
  true`, `bundled_kernel = false`, no HW-virt, no TAP/virtio/vsock, no snapshot.
- **`WasmBackend: VmBackend`** — a host `wasmtime` instance instead of a booted
  Linux microVM. Opt-in behind a `wasm-backend` Cargo feature so the default
  workspace build carries no `wasmtime`; never auto-selected (ADR-024 §1 — the
  `builder_attempt_order`/auto-detect ladder never resolves to it).
- **Honest capability matrix, fail-closed** (ADR-024 §2): every request the tier
  cannot satisfy — `--kernel`, a snapshot, a real networking mode, verified boot,
  anything hardware — returns a **typed error naming the supported alternative**,
  never a silent drop-and-proceed. The capability matrix says plainly what it
  lacks.
- **Egress via `VmDuplexTransport::Wasi`** — a wasm container has no vsock, so its
  outbound calls ride WASI host-imports through the *same* default-deny, audited,
  secret-substituting host seam that Firecracker-UDS / libkrun-unixgram /
  HVF-vsock use (see [03-networking.md](03-networking.md)). Secrets stay
  host-side, substituted only on a bound destination, `${NAME}` placeholders and
  all. Any backend that cannot mediate egress through the host fails closed on
  `--network-allow`; `WasmBackend` mediates, so it complies.
- **Claim-free**: `BackendSecurityProfile` reports every numbered claim as N/A
  for this tier. `mvmctl doctor` and the per-backend tier matrix show it as a
  portability tier, never an isolation tier. No claim-catalog witness is added.

## POC acceptance gate

`WasmBackend` runs a trivial WASI module that makes one outbound request; the
request is **default-denied, then allowed by an explicit policy**, through the
host seam, producing a **chain-signed audit entry** — and the **data-governance
witness passes** (the module sees no secret value and emits no PII), *the same
witness the microVM backends pass*. That is the whole point: one governance
model, many transports.

## Phased plan

- **P1 — close the foundation bullet.** Wire a `wasm32` **test** pass for
  `mvm-protocol` (a `wasm-bindgen-test` / `wasmtime`-runner CI lane so the IR +
  verifier tests run *under* wasm, not just build), and add the explicit
  `no_std`-boundary lint (a gate asserting nothing workload-execution-relevant in
  `mvm-protocol` reaches `std`/OS beyond the sanctioned `schema` feature). Bounded,
  no new backend — the right first step. Gate: wasm test lane green.
- **P2 — the skeleton.** `BackendKind::Wasm` + `WasmBackend` impl with the honest
  capability matrix + fail-closed typed errors, `wasmtime` behind the opt-in
  `wasm-backend` feature. It instantiates a WASI module and runs it to completion
  with no networking yet. Gate: `mvmctl run --backend wasm <module.wasm>` runs a
  no-egress module; every unsupported flag fails closed with the right typed error;
  default build carries no `wasmtime`.
- **P3 — the governed seam + POC.** `VmDuplexTransport::Wasi` egress through the
  default-deny/substitute/audit host seam; meet the POC acceptance gate above.
- **P4 — the browser slice.** `mvm-protocol` + the `no_std` OCI decoders running
  in the browser (image inspect/verify), per the holospaces path.

## Risks / notes

- **Dep budget**: `wasmtime` is a large dependency tree. It stays strictly behind
  the `wasm-backend` feature (off by default), like `object_store` behind `s3`.
  `deny.toml` review at P2.
- **WASI version churn**: target the component model / WASI Preview 2; pin it.
- **"Honest" is load-bearing**: the single biggest failure mode is a capability
  matrix that overstates — every gap must fail closed with a typed error, enforced
  by a test, so the tier can never be mistaken for an isolation boundary.
- Not a claim tier, by construction — do not add a claim-catalog witness; the
  data-governance witness it *does* pass is a governance witness, not an isolation
  claim.
