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

## POC acceptance gate — MET (`e669bcc5d`/`4d709d196`/`8c270214d`)

`WasmBackend` runs a trivial WASI module that makes one outbound request; the
request is **default-denied, then allowed by an explicit policy**, through the
host seam, producing a **chain-signed audit entry** — and the **data-governance
witness passes** (the module sees no secret value and emits no PII), *the same
witness the microVM backends pass*. That is the whole point: one governance
model, many transports.

**Gate met.** `crates/mvm-hostd/tests/wasm_egress_witness.rs` (two tests, allow +
deny) drives a `.wat` module's `mvm:egress` host-import through the REAL
`SubstitutionService` (real registry/resolver/encrypted secret store/claim-10
gate/chain-signed recorder), swapping only the outbound TCP dial for a `Forwarder`
test double — the production forward leg refuses loopback by construction (SSRF),
so this is the one hermetic concession, and it is the crate's own test seam. The
allow path witnesses `WireResponse::Ok{200}` through the claim-10 gate + host-side
substitution (destination gets the real secret, module holds only the placeholder)
+ a verifying `secret.substituted` chain entry with no secret in it; the deny path
witnesses a claim-12 bind-check drop (refused, destination never contacted,
verifying `secret.placeholder_dropped` entry). The witness homes in mvm-hostd (not
mvm-runtime) because mvm-hostd deps both `WasmBackend` and `SubstitutionService`, so
it drives the real governance in-process with no dependency inversion. See
`specs/plans/13-ws11-wasm-egress-poc.md`.

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
  **Feasibility (recon'd): GO, and decoupled from the in-flux WS-NET.** The real
  transport abstraction the design's "`VmDuplexTransport`" refers to is
  `EndpointTransport` (`mvm-runtime/src/substitution_spawn.rs` — today `Vsock {
  port }` / `Uds { path }`), the per-backend way a workload reaches the per-VM
  **substitution endpoint** (`mvm-substitution-endpoint`, an `mvm-hostd` bin):
  the backend-agnostic governance seam that does secret substitution + egress
  policy + audit (libkrun/FC/qemu all spawn it). That layer is **separate from
  the actively-churning smoltcp-vsock *tunnel/forwarder* layer** (`smoltcp_egress`
  / `network_tunnel`, Plan 236 `#1681`). A wasm container has no vsock/TUN, so it
  **bypasses the tunnel entirely** — P3 adds an `EndpointTransport::Wasi` variant
  and routes the WASI module's outbound host-calls (intercepted by the host
  `wasmtime` embedding) straight into the substitution endpoint. So P3 touches
  the *stable* governance layer, not the WS-NET flux — it need not wait for
  WS-NET. Real work: (a) the `EndpointTransport::Wasi` variant (enum-variant
  churn like `BackendKind::Wasm`); (b) the WASI host-call → substitution-endpoint
  routing in the `wasmtime` embedding; (c) the POC's **data-governance witness**
  — referenced across the specs (04/06) as a planned CI witness but not yet a
  concrete test, so P3 must identify/build it. Scope note: the endpoint's full
  TLS-terminating secret-substitution (per-VM egress-CA intermediate the guest
  trusts) is heavier than a byte relay; a first P3 cut can prove
  default-deny/allow + audit + `${NAME}` substitution through the seam and defer
  full TLS termination to P3b if it complicates.
- **P4 — the browser slice.** `mvm-protocol` + the `no_std` OCI decoders running
  in the browser (image inspect/verify), per the holospaces path.

## P3 implementation design (recon'd — do this before building)

The feasibility recon settled the two sub-forks that would otherwise sink a
build:

**Fork 1 — how the module's egress is expressed → explicit host-import ABI (for
the POC).** The wasm module reaches egress through an `mvm:egress` host-import
the `wasmtime` embedding provides (the module calls `egress(dest, payload) ->
outcome`), not transparent WASI-socket interception. Transparent interception is
the eventual goal (truest to "run a user module as-is") but is more `wasmtime`
plumbing; the host-import proves the governance seam with the least uncertainty
and is cleanly testable. Adding it does not change the "user-supplied module"
story for the POC — the demo module is written against the import.

**Fork 2 — in-process vs. subprocess governance → SUBPROCESS (Approach X),
decided by a reachability fact.** `mvm-runtime` (where `WasmBackend` lives) does
**not** depend on `mvm-hostd`, and the real chain-signed audit emitter
(`mvm-hostd/src/audit/emitter.rs`) + the full substitution machinery live in
`mvm-hostd`. Reachable in-process from `mvm-runtime`: the egress **policy** check
(`network_policy`), plan-**secret decode** (`egress_shared`), and only the
*local* audit (`mvm-core::policy::audit`, not the claim-8 chain). So an
in-process POC would emit a *parallel* audit, not the chain the microVM backends
use — which defeats the entire point ("the same witness"). Therefore P3 routes
the module's egress through the **existing `mvm-substitution-endpoint`
subprocess** (the `mvm-hostd` bin that already does policy + `${NAME}`
substitution + chain-signed audit for libkrun/FC/qemu), via a new
`EndpointTransport::Wasi`.

**The wiring (simplified after reading the endpoint — no new transport needed).**
The endpoint already speaks a clean, transport-agnostic framed-JSON contract:
`mvm_core::substitution_wire::{WireRequest, WireResponse}` (length-prefixed JSON;
`WireRequest { method, url, headers, body_b64 }` where a header value carries the
`${NAME}` placeholder; `WireResponse::{Ok{status,headers,body_b64} | Refused{message}}`).
`SubstitutionService::serve(UnixListener)` reads a `WireRequest`, runs
`process()` — bound-destination policy + `${NAME}` substitution + chain-signed
audit + forward — and replies `WireResponse`. **The wasm host-import is therefore
just another `WireRequest` client over the existing `Uds` transport** — faithful
by construction, because it hits the *same* endpoint + the *same* `process()` the
microVM SDK path uses. No `EndpointTransport::Wasi` variant, no new relay protocol,
no touching the 2972-line proxy.
1. `WasmBackend::start()` (when the plan carries secrets / the policy allows
   egress) spawns the substitution endpoint via the *same* `spawn_substitution_endpoint`
   path (`substitution_spawn.rs`) with `EndpointTransport::Uds { path }`.
2. The `mvm:egress` host-import, on each module call, builds a `WireRequest`
   (`mvm_core::substitution_wire`, reachable from `mvm-runtime`), connects to that
   Uds, writes the length-prefixed JSON frame, reads the `WireResponse`, returns
   it to the module. Reuse the existing frame writer/reader (the in-guest client
   in `mvm-agentd` already speaks this) rather than a second copy. The module only
   ever holds the placeholder — the real secret lives host-side in the endpoint.
4. **Data-governance witness — BUILT (wasm leg).** `crates/mvm-hostd/tests/wasm_egress_witness.rs`:
   a WASI module requests egress with a placeholder to (a) a policy-allowed but
   secret-bound destination and (b) a network-admitted-but-not-secret-bound
   destination; it asserts allow-by-policy through the claim-10 gate, host-side
   substitution (destination gets the real secret, module holds only the
   placeholder), a chain-verifying `secret.substituted` entry, deny-by-drop
   (claim-12 bind-check → refused, destination never contacted), and a
   chain-verifying `secret.placeholder_dropped` entry — with no secret in either
   chain. **Cross-backend follow-up:** the microVM backends do not yet run this
   *same* chain-verifying witness as a shared CI lane; wiring it across all
   workload backends (so wasm and the microVMs pass one witness) is tracked in
   [07-progress-and-decisions.md](07-progress-and-decisions.md) §"Not started".

**Deferred to P3b:** the endpoint's full TLS-terminating substitution (per-VM
egress-CA intermediate the guest trusts) is heavier than the UDS-framed
request/response the POC needs; a first cut proves policy + audit + `${NAME}`
over the UDS and defers TLS termination. **Sequencing:** the subprocess is the
*stable* substitution/audit layer, so P3 does not block on the in-flux
smoltcp-tunnel WS-NET work — but it does touch the endpoint's input protocol
(adding the Wasi transport), so it wants a careful, focused build, not a
tail-of-session cram.

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
