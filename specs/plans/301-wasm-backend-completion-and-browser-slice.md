# Plan 301: Finish WS11 — `WasmBackend` completion + the P4 browser slice

## Status

Not started. Design of record for the two open halves of WS11.

WS11's P1–P3b.2 have landed: `mvm-contract` builds and tests under wasm,
`BackendKind::Wasm` + `WasmBackend` run a WASI module under host `wasmtime`
behind the opt-in `wasm-backend` feature, and the data-governance witness
(`crates/mvm-hostd/tests/wasm_egress_witness.rs`) proves substitution + audit
through the real claim-10/claim-12 governance. What remains splits cleanly in
two, and this plan covers both:

- **Part A — the host tier.** Close the gaps P3 knowingly deferred so
  `WasmBackend` is honest end-to-end rather than honest-at-the-seam.
- **Part B — the browser slice (P4).** The half with no design at all:
  `specs/refactor/11-wasm-backend.md` scopes P4 in one sentence
  ("`mvm-contract` + the `no_std` OCI decoders running in the browser") with no
  execution model, no storage model, and no size discipline.

The two parts are independent. Part B does not block on Part A.

Binding constraints (unchanged, not relitigated here): ADR-024's three —
opt-in only and never auto-selected; honest capabilities, fail closed;
**zero numbered security claims**. Nothing in this plan adds a claim witness.
Executing attacker-controlled production wasm stays deferred under ADR-024's
engine-in-guest rule.

## Part A — `WasmBackend` completion

### A1 — End-to-end spawn-path coverage

P3b.2's witness drives `WasmBackend::with_egress_endpoint` with an in-process
`SubstitutionService`. It proves the governance seam but never exercises
`start()` → `spawn_wasm_egress_endpoint_if_needed` → real endpoint subprocess:
both witness tests use `VmStartConfig::default()` (`deny_all`), so the gate
P3b.2 relaxed never actually fires in them. The decision layer is unit-tested;
the wiring is not.

The blocker is known and shared with the microVM backends: the production
forward leg refuses loopback by construction (SSRF hardening), so a hermetic
test cannot dial a local destination through the real path.

- [ ] Decide the seam: either a test-only bind-address injection on the
      forwarder (narrow, explicit, `#[cfg(test)]`-gated) or a non-loopback
      hermetic destination in CI. Pick one and record why in this plan.
- [ ] Test: an allow-egress `VmStartConfig` through the real `start()` path
      spawns the endpoint, the module's `mvm:egress` call reaches it over the
      spawned UDS, and the endpoint is reaped on exit.
- [ ] Test: endpoint spawn failure fails the run closed with a typed error —
      never a silent no-egress run.
- Gate: the spawn path is covered by a test that fails if the wiring regresses.

### A2 — P3c: TLS-terminating substitution

P3b.1 shipped http-only: `tls_intermediate: None`, `terminator_listen: None`.
A real destination is https, so the tier today substitutes secrets only for
plaintext destinations — an honest POC, but a sharp edge if left undocumented.

- [ ] Wire the per-VM egress-CA intermediate + terminator listen for the wasm
      endpoint, reusing `spawn_substitution_endpoint`'s existing parameters —
      no wasm-specific TLS path.
- [ ] Extend the witness to an https destination: the module holds only the
      placeholder, the terminator injects the real secret, and the chain-signed
      `secret.substituted` entry still carries no secret.
- [ ] Until this lands, `WasmBackend` fails closed with a typed error on an
      https destination rather than forwarding a placeholder.
- Gate: https witness green, or the fail-closed error is tested.

### A3 — Transparent WASI socket interception

Fork 1 chose an explicit `mvm:egress` host-import for the POC and named
transparent interception the eventual goal — it is what makes "bring a wasm
module, run it as-is" true rather than "bring a module written against our
import".

- [ ] Intercept WASI socket egress in the `wasmtime` embedding and route it to
      the same `WireRequest` client, so an unmodified module gets governed
      egress.
- [ ] Keep the explicit host-import as the supported path; interception is
      additive, not a replacement.
- [ ] Both paths pass the same witness assertions.
- Gate: an unmodified WASI module that opens a socket is governed identically.

### A4 — WASI Preview 2 / component model

`specs/refactor/11-wasm-backend.md` §Risks says "target the component model /
WASI Preview 2; pin it". P2 shipped Preview 1 (`wasmtime-wasi` 46). That is a
reasonable POC choice, but it is an undeclared divergence from the design.

- [ ] Either move to Preview 2 / the component model, or amend doc 11 to record
      Preview 1 as the deliberate choice with the reason. Do not leave the
      design and the code disagreeing.

### A5 — Doc + dependency hygiene

- [ ] **ADR-024's Status paragraph is stale.** It reads "No implementation has
      landed yet: `BackendKind` still enumerates the microVM backends only; no
      `wasmtime` dependency is in the workspace." Both clauses are false since
      P2. Rewrite the status; leave the three constraints untouched.
- [ ] Confirm the `deny.toml` review doc 11 §Risks assigned to P2 actually
      happened for the `wasmtime` tree; run it now if not.
- [ ] Re-assert the dep budget as a gate: the default workspace build carries
      zero `wasmtime`. This is already checked — keep it checked.

### A6 — One witness across all workload backends

Doc 11 flags it: the microVM backends do not run the *same* chain-verifying
governance witness the wasm tier does. "The same witness" was the entire
argument for routing wasm egress through the existing endpoint subprocess, and
it is currently true only on the wasm side.

- [ ] Parameterize `wasm_egress_witness.rs`'s assertions over the workload
      backends so wasm, Firecracker, libkrun, and HVF pass one shared witness.
- [ ] Where a backend cannot run it hermetically, say so in the lane rather
      than silently covering fewer backends.
- Gate: one witness, N backends, and the count is visible in CI output.

## Part B — the browser slice (P4)

### Prior art

[ferrovec](https://github.com/singhpratech/ferrovec) is an in-browser vector
store: Rust core compiled to wasm, dedicated Web Worker owning the engine, thin
async proxy on the main thread, OPFS for durable storage, ~33 KB gzipped on a
two-crate dependency budget. It is not a dependency and shares no domain with
mvm — but it is a working instance of exactly the shape P4 needs, and B2/B3/B4
below take their execution model, storage model, and size discipline from it.

### B1 — Extract the `no_std` OCI decoders (the long pole)

P4 assumes "the `no_std` OCI decoders" exist. They do not. `mvm-fs` is a
thoroughly `std` crate — `tokio`, `reqwest`, `rustls`, `rayon`, `libc`,
`rustix`, `xattr`, `tar`, `flate2` — so nothing under `crates/mvm-fs/src/oci/`
compiles for the browser today. This is the bulk of P4's work and it must land
before any page can inspect an image.

The method is not novel: this is the same DTO inversion Increment 3 executed
twelve times (Batches A–L) against `mvm-core` → `mvm-contract`. Reuse it,
including the discipline that made it safe.

- [ ] Inventory `oci/{manifest_types,manifest,reference,layer,archive}.rs` and
      cut each into *decode/verify* (pure, moves down) vs *fetch/materialize*
      (`std`, stays in `mvm-fs`).
- [ ] Relocate the pure half to `mvm-contract` **verbatim** — no serde-shape
      change. Manifest bytes are content-addressed; a shape change is a
      correctness bug, not a refactor.
- [ ] Leaf-first tier order, green + wasm-clean after every step, exactly as
      `specs/refactor/10-increment3-protocol-core-split.md` prescribes.
- [ ] Digest verification (sha256 over layer bytes) must work under `no_std` —
      `sha2` is already a `mvm-contract` dependency.
- [ ] Gzip/tar decode is the open question: `flate2` defaults to a C backend.
      Either a pure-Rust `no_std` inflate or scope B1 to manifest-level
      inspection only and say so plainly.
- Gate: the OCI decoders build on `wasm32-unknown-unknown` and their tests pass
      under `wasm32-wasip1` in the existing lane.

### B2 — Execution model: Worker + thin proxy

- [ ] Dedicated Web Worker owns the wasm module; the main thread gets an async
      proxy only (`open` / `verifyChain` / `inspectImage`).
- [ ] No verification work on the main thread. Verifying a long audit chain is
      Ed25519 + SHA-256 in a loop and OCI layer digests are worse; on the main
      thread that jank-locks the tab. The current `web/audit-verify/index.html`
      does exactly this, which is one of the reasons it is being replaced.
- [ ] Progress reporting for long chains, so a large log does not look hung.
- Gate: a chain long enough to take seconds verifies with the page responsive.

### B3 — OPFS as a content-addressed cache

The reason P4 is scoped to inspect/verify-only is that a browser has no
filesystem. OPFS is one, and it is durable across reloads. Our host-side pack
cache is already digest-keyed, so the semantics port directly: fetch a manifest
once, store layers under their digest, re-verify offline afterwards.

- [ ] OPFS store keyed by content digest, mirroring the host pack-cache
      semantics.
- [ ] Verify-on-read, not verify-on-write: a cache entry is re-verified against
      its digest every time it is read, and a mismatch evicts the entry. This is
      the same posture the host-side dev cache adopted; do not weaken it here
      because the store is local.
- [ ] Explicit eviction and a "clear cache" affordance — this is a user's disk.
- [ ] `postcard` for the OPFS *record* envelope only. It is local, never signed,
      never crosses a trust boundary. **It does not touch the control plane** —
      JCS canonical JSON *is* the signing input for `ExecutionPlan`, audit
      entries, and `ControlRequest`, and that byte-identity contract with mvmd
      is untouchable (ADR-031).
- Gate: reload the page, verify offline from cache, and a corrupted entry is
      detected and evicted rather than trusted.

### B4 — Ship it, and gate its size

ferrovec is ~33 KB gzipped. Nobody is measuring ours, and Increment 3 just moved
the entire signed plan plus all wire/policy DTOs into `mvm-contract` — the crate
the browser bundle is built from. Bundle growth will otherwise be discovered by
a user on a slow connection.

- [ ] Add `wasm-opt -Oz` to the browser build.
- [ ] Add a gzipped-size budget to the existing wasm lane in
      `scripts/ci-linux-coverage.sh` (which already installs `wasmtime` and
      builds `mvm-contract` for `wasm32-unknown-unknown`). Fail the lane on
      regression past the budget; raising the budget is a deliberate commit.
- [ ] Build it in the builder VM, never a host toolchain — same invariant as
      every other build in this repo (ADR-004 / ADR-007).
- [ ] Publish a static page: audit-chain verification + Merkle inclusion proof
      (`verify_membership`) + image inspect.
- Gate: the page is reachable, works offline after load, and the size budget is
      enforced in CI.

### B5 — Retire `web/audit-verify/`

`specs/SPRINT.md` already lists it for deletion, superseded by wasm
`mvm-contract`. Its capability comes back through B4.

- [ ] Delete `web/audit-verify/` once B4's page covers audit-chain verification
      and Merkle inclusion, after confirming no CI gate depends on it.
- [ ] Fix the stale `mvm-verify` crate references in `specs/adrs/031` (the crate
      does not exist; the logic is `mvm_contract::verify`). Do this now — the
      ADR outlives the directory.
- [ ] Add `mvmctl audit pubkey` to print the host signer's public half. Without
      it, a user must derive the public key from the keypair by hand before the
      page is usable, which makes B4 a demo nobody can run against their own
      logs.

## Sequencing

Part A and Part B are independent; B1 is the long pole in the whole plan and
should start first if both are worked in parallel. Within A: A1 and A5 are
small and unblock honesty about what the tier does today; A2 and A3 are real
builds; A6 is worth doing last, once the wasm-side witness is stable enough to
generalize. Within B: B1 → B2 → B3 → B4 → B5, strictly.

## Non-goals

- Any numbered security claim for the wasm tier. ADR-024 §3.
- Executing attacker-controlled production workloads under a host engine.
  ADR-024's engine-in-guest rule.
- ext4 materialization in the browser. No block device.
- Replacing JCS canonical JSON anywhere on the signed control plane.
