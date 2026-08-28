# WS11 P3b.2 — Governed WASI Egress POC + Data-Governance Witness — Implementation Plan

> **STATUS: COMPLETE** (`e669bcc5d` Task 1 gate-relax · `4d709d196` allow-path witness · `8c270214d` deny-path witness · this doc-closeout). All five tasks landed; the POC acceptance gate is met and every closeout gate is green (workspace clippy, runtime+hostd wasm-backend clippy, 27 `wasm_backend` units + 2 witnesses, 0 wasmtime in the non-dev graph, 4 xtask gates, wasm32 `mvm-contract` build, fmt).
>
> **One deviation from this plan, for the better:** the witness homes in **mvm-hostd** (`crates/mvm-hostd/tests/wasm_egress_witness.rs`), not mvm-runtime. mvm-hostd already deps mvm-runtime (`WasmBackend`) *and* owns `SubstitutionService`/`Recorder`/`verify_audit_chain`, so it drives the REAL governance types **in-process** with no dependency inversion and no subprocess — cleaner than this plan's subprocess design, which the SSRF-guarded forward leg would have blocked on the allow path anyway (it refuses loopback, so a hermetic real-destination allow-path test is impossible through the real forwarder; the witness swaps only the outbound dial for a `Forwarder` test double, the crate's own test seam). A mvm-hostd `wasm-backend` feature forwards to mvm-runtime's. See SPRINT.md §WS11 P3b.2 and `specs/refactor/11-wasm-backend.md` §"POC acceptance gate — MET".

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Run every command SYNCHRONOUSLY in the foreground — never background a cargo command and wait for a notification (it wedges).

**Goal:** Prove, end to end, that a WASI module's egress is mediated by the *same* host substitution/policy/audit seam every microVM backend uses — default-deny, `${NAME}` secret-substitution on a bound destination, and a chain-signed audit entry — with the module never holding the real secret; then relax the `WasmBackend` fail-closed networking gate so governed egress is reachable in production `start()`.

**Architecture:** `WasmBackend` (host `wasmtime`, `crates/mvm-runtime`) already has (P3a) an `mvm:egress` host-import that relays a `mvm_core::substitution_wire::WireRequest` over a UDS via `mvm_agentd::substitution_client`, and (P3b.1) `start()` that spawns the real `mvm-substitution-endpoint` subprocess and wires its UDS in. This plan adds the missing proof — a **data-governance witness** — and flips the last gate. The witness is a `mvm-runtime` integration test (`tests/`) because that crate can already *spawn* the endpoint subprocess (via `substitution_spawn::spawn_substitution_endpoint`) without depending on `mvm-hostd`. HTTP-only (the P3b.1 endpoint is `tls_intermediate: None`); HTTPS termination is the separate P3c plan.

**Tech Stack:** Rust, `wasmtime` + `wasmtime-wasi` (behind the `wasm-backend` feature), `mvm_core::substitution_wire::{WireRequest,WireResponse}`, `mvm_agentd::substitution_client`, `mvm-substitution-endpoint` (an `mvm-hostd` bin), a `.wat` fixture module, a std `TcpListener` mock destination, the chain-signed audit log (`mvm_supervisor::verify_audit_chain` / `mvmctl trust audit verify`).

## Global Constraints

- Everything runs in the worktree `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-simplification-plan`, branch `plan/mvm-simplification`. Never touch the main checkout.
- Run the ordinary cargo gates; prefix wasm builds with `PATH="$HOME/.cargo/bin:$PATH"`.
- REUSE, never re-implement: `mvm_agentd::substitution_client`, `mvm_core::substitution_wire`, `substitution_spawn::{spawn_substitution_endpoint, SubstitutionSpawnParams, EndpointTransport}`, `egress_shared::decode_plan_secrets_from_state`, the P3a host-import, the P3b.1 spawn wiring.
- `wasmtime` stays behind the `wasm-backend` feature; the default workspace build carries no `wasmtime` (`cargo tree -p mvm-runtime -e no-dev | rg -c wasmtime` == 0).
- `WasmBackend` stays the **claim-free** portability tier: `security_profile()` keeps every numbered claim `DoesNotHold`; the egress seam adds NO claim-catalog witness (the data-governance witness is a *governance* witness, not an isolation claim).
- Fail closed with typed errors — no `unwrap`/`panic`/`todo!`/`unimplemented!` on any guest-controlled or start path.
- **NO `ADR-\d+` / `Plan N` / `#NNNN` / `W\d.` in code comments** — `xtask check-no-spec-refs-in-comments` is enforced; reword to the concept.
- No new `#[allow]`; `///` on public items; exhaustive matches (no wildcard on owned enums); `mvm-contract` stays `#![no_std]` + wasm-clean (do not touch it).
- Because `mvm-runtime` is excluded from the macOS workspace `nextest` (codesign SIGKILL), run new `mvm-runtime` tests with `cargo test -p mvm-runtime --features wasm-backend <name>` locally; they run under Linux CI.

## File Structure

- `crates/mvm-runtime/src/wasm_backend.rs` — MODIFY: relax `reject_unsupported_start_config` so a policy that `allows_egress()` is permitted **when** the run will spawn a governed endpoint (i.e. don't reject egress outright anymore; reject only the still-unsupported cases). Add a small helper the test can drive.
- `crates/mvm-runtime/tests/wasm_egress_witness.rs` — CREATE: the data-governance witness integration test (`#![cfg(feature = "wasm-backend")]`), plus a `.wat` fixture (inline string) + a mock-destination `TcpListener` helper.
- `crates/mvm-runtime/tests/fixtures/egress_module.wat` — CREATE (optional): the fixture module, if cleaner as a file than an inline string.

## Prerequisite recon the implementer MUST do first (one focused pass, then build)

The witness spawns the real endpoint + drives the P3a import, so confirm the exact reachable APIs before writing test code (they were verified to exist but read the current signatures):
1. `crates/mvm-runtime/src/substitution_spawn.rs`: `spawn_substitution_endpoint(SubstitutionSpawnParams)` — how it locates/execs the `mvm-substitution-endpoint` bin, whether it needs the bin pre-built (it does — the test must ensure the bin is built; a `#[ignore]`-by-default + a CI-run marker is acceptable if the bin isn't present in the unit-test env), and the ready handshake.
2. `crates/mvm-runtime/src/wasm_backend.rs`: the P3a `mvm:egress` import ABI (the exact `(req_ptr,req_len,resp_ptr,resp_cap)->i32` contract) and the P3b.1 `wasm_substitution_spawn_params` — the `.wat` fixture and the test must match them.
3. `crates/mvm-hostd/src/supervisor/substitution_endpoint.rs` (`EndpointConfig`) + `substitution_proxy.rs` (`process()`): confirm the http (non-TLS) forward path and the `secret.substituted` chain-audit emit, so the witness asserts the right audit `LocalAuditKind`/entry and knows the endpoint forwards plain HTTP to the `WireRequest.url` when `tls_intermediate: None`.
4. `crates/mvm-core/src/plan/` + `test_support::PlanFixture`: how to build an admitted plan carrying one `SecretBinding` (env var → placeholder, bound to a host) + a `network_policy` that allows the mock destination and denies another host, and how the endpoint reads secrets from the per-VM state dir (`decode_plan_secrets_from_state`) — the witness writes that state.

If any of these differ materially from the P3b.1 assumptions, STOP and report before writing the test (a wrong assumption here produces a plausible-but-false witness).

---

### Task 1: Relax the fail-closed networking gate to permit *governed* egress

`reject_unsupported_start_config` currently returns `NetworkingNotSupported` for any `config.network_policy.allows_egress()`. That was correct when there was no egress seam; now `start()` spawns one. The gate must stop rejecting egress outright — egress is now *mediated*, not unsupported — while still rejecting the genuinely-unsupported cases (kernel/verity/console).

**Files:**
- Modify: `crates/mvm-runtime/src/wasm_backend.rs` (`reject_unsupported_start_config`, ~line 103–122; and the module-doc "No networking" paragraph, ~line 23–27, which is now stale).
- Test: same file, `#[cfg(test)]`.

**Interfaces:**
- Consumes: `VmStartConfig` (`mvm_core::vm_backend`), `WasmBackendError` (existing).
- Produces: `reject_unsupported_start_config(&VmStartConfig) -> Result<(), WasmBackendError>` — same signature, egress no longer rejected.

- [ ] **Step 1: Write the failing test** (in `wasm_backend.rs` tests)

```rust
#[test]
fn start_config_with_egress_policy_is_now_allowed() {
    // A policy that allows egress must NOT be rejected: egress is governed
    // (the endpoint mediates it), not unsupported.
    let mut cfg = minimal_wasm_start_config(); // existing test helper that sets rootfs_path
    cfg.network_policy = mvm_core::policy::network_policy::NetworkPolicy::unrestricted();
    assert!(reject_unsupported_start_config(&cfg).is_ok());
}

#[test]
fn start_config_still_rejects_kernel_and_console() {
    let mut cfg = minimal_wasm_start_config();
    cfg.kernel_path = Some("/x".into());
    assert_eq!(reject_unsupported_start_config(&cfg), Err(WasmBackendError::KernelBootNotSupported));
}
```

(If no `minimal_wasm_start_config` helper exists, add one that returns a `VmStartConfig::default()`-ish value with `rootfs_path` set — mirror how the P3b.1 tests build a config.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-runtime --features wasm-backend start_config_with_egress -- --nocapture`
Expected: FAIL — the egress-allowed config currently returns `Err(NetworkingNotSupported)`.

- [ ] **Step 3: Remove the egress rejection**

Delete the `if config.network_policy.allows_egress() { return Err(WasmBackendError::NetworkingNotSupported); }` block. Keep the kernel/verity/console/module-path checks. (Leave `NetworkingNotSupported` the enum variant in place — it's still the fail-closed error the P3a host-import returns when NO endpoint is configured for a run that needs one; it just stops being an up-front `start()` rejection.) Update the module-doc "No networking" paragraph to describe the governed egress seam instead of claiming no networking.

- [ ] **Step 4: Run to verify both tests pass**

Run: `cargo test -p mvm-runtime --features wasm-backend start_config -- --nocapture`
Expected: PASS (both).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/wasm_backend.rs
git commit -m "feat(wasm): permit governed egress in WasmBackend start config"
```

---

### Task 2: The `.wat` egress fixture module

A minimal WASI module that, on `_start`, writes a `WireRequest` JSON (with a `${NAME}`-style placeholder in an `authorization` header) into linear memory, calls the `mvm:egress` import, and stores the returned status where the test can read it.

**Files:**
- Create: `crates/mvm-runtime/tests/fixtures/egress_module.wat` (or inline in Task 3's test as a `const WAT: &str`).

**Interfaces:**
- Consumes: the P3a import `(import "mvm" "egress" (func (param i32 i32 i32 i32) (result i32)))`; exports `memory`.
- Produces: after `_start`, the module's memory at a known offset holds the `WireResponse` JSON the host wrote; the test reads it.

- [ ] **Step 1: Write the fixture.** It must: (a) place a `WireRequest` JSON literal (as a `data` segment) — e.g. `{"method":"GET","url":"http://<MOCK_HOST>/ping","headers":[["authorization","Bearer ${API_KEY}"]],"body_b64":""}` — at a fixed `req_ptr`; the test will template `<MOCK_HOST>` (see Task 3 note); (b) reserve a `resp` region (`resp_ptr`, `resp_cap`); (c) `_start` calls `mvm_egress(req_ptr, req_len, resp_ptr, resp_cap)` and, since P3a returns the response length in the result, leave that length for the test to read via the import's own contract; (d) export `memory`. Keep it hand-written and tiny; `wasmtime` parses `.wat`.
- [ ] **Step 2: Sanity — the fixture loads.** In Task 3's harness, `wasmtime::Module::new(&engine, WAT)` must succeed (asserted implicitly when the round-trip test runs). No standalone step/commit — this fixture is exercised by Task 3.

*(Note: the URL host is templated because the mock destination binds an ephemeral port; if `.wat` string-templating is awkward, have the module read the URL from a second data segment the test patches, or bind the mock listener on a fixed loopback port the fixture hard-codes and the test reuses. Pick the simplest that the P3a ABI supports; document the choice in a `//!` comment.)*

---

### Task 3: The data-governance witness — allow path (bound destination, substituted, audited)

Spawn the real endpoint, run the fixture module against a mock destination bound in policy, and assert the full governance chain.

**Files:**
- Create: `crates/mvm-runtime/tests/wasm_egress_witness.rs` (`#![cfg(feature = "wasm-backend")]`).

**Interfaces:**
- Consumes: `mvm_runtime::wasm_backend::WasmBackend`, `substitution_spawn::spawn_substitution_endpoint`, `mvm_core::substitution_wire::{WireRequest,WireResponse}`, the chain-audit verify API (`mvm_supervisor::verify_audit_chain` or the `mvmctl trust audit verify` path — use whichever is a library call).
- Produces: the witness test `governed_egress_substitutes_secret_and_audits_on_bound_destination`.

- [ ] **Step 1: Write the mock-destination helper.** A `TcpListener` on `127.0.0.1:0` in a thread that accepts one connection, reads the HTTP request, records the `authorization` header value it received, and replies `HTTP/1.1 200 OK\r\ncontent-length:4\r\n\r\npong`. Return `(SocketAddr, Receiver<String>)` so the test can assert the header the destination actually saw.

- [ ] **Step 2: Write the failing witness test.**

```rust
#[test]
fn governed_egress_substitutes_secret_and_audits_on_bound_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path();
    let (dest_addr, dest_headers) = spawn_mock_destination();
    let mock_host = format!("127.0.0.1:{}", dest_addr.port());

    // 1. Write an admitted plan into state_dir: one SecretBinding
    //    (env API_KEY -> placeholder, bound to `mock_host`), a network_policy
    //    that ALLOWS `mock_host`. (Reuse decode_plan_secrets_from_state's
    //    on-disk format — see the recon; mirror how libkrun's tests seed it.)
    write_admitted_plan_with_bound_secret(state_dir, &mock_host, "API_KEY", "s3cr3t-real");
    std::env::set_var("API_KEY", "s3cr3t-real"); // the endpoint resolves the placeholder from env/secret store

    // 2. Spawn the real substitution endpoint over a Uds under state_dir
    //    (WasmBackend::start would do this; here drive the same helper directly
    //    so the test controls timing).
    let uds = mvm_core::config::vm_substitution_endpoint_socket(state_dir, "witness-vm");
    spawn_endpoint_for_test(state_dir, "witness-vm", &uds); // wraps spawn_substitution_endpoint w/ the P3b.1 params

    // 3. Run the fixture module through WasmBackend pointed at that endpoint,
    //    with a WireRequest whose url is http://<mock_host>/ping and an
    //    `authorization: Bearer ${API_KEY}`-style placeholder header.
    let backend = WasmBackend::new().with_egress_endpoint(uds.clone());
    let observed = run_egress_fixture(&backend, &mock_host); // returns the WireResponse the module saw

    // ASSERTIONS — the witness:
    // (a) allow-by-policy: the module saw Ok(200, "pong")
    assert!(matches!(observed, WireResponse::Ok { status: 200, .. }));
    // (b) substitution happened host-side: the DESTINATION saw the real secret,
    //     never the placeholder
    let seen = dest_headers.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(seen.contains("s3cr3t-real"), "destination must receive the substituted secret");
    assert!(!seen.contains("${API_KEY}") && !seen.contains("mvm-"), "no placeholder leaks to the destination");
    // (c) the module never held the real secret — only the placeholder was ever
    //     in guest memory (assert the fixture's request bytes contain the
    //     placeholder, not the secret)
    // (d) a chain-signed substitution audit entry exists and the chain verifies
    assert!(audit_chain_has_substitution_entry(state_dir), "chain-signed secret.substituted entry present");
    assert!(verify_audit_chain_ok(state_dir), "audit chain verifies");
}
```

- [ ] **Step 3: Run to verify it fails** (endpoint/audit not yet wired in the harness helpers, or the fixture/plan seeding incomplete).

Run: `cargo test -p mvm-runtime --features wasm-backend governed_egress -- --nocapture`
Expected: FAIL (a specific unwired step, not a panic-in-host).

- [ ] **Step 4: Implement the harness helpers** (`write_admitted_plan_with_bound_secret`, `spawn_endpoint_for_test` reusing `spawn_substitution_endpoint` with the P3b.1 params, `run_egress_fixture` instantiating the `.wat` via `WasmBackend` and returning the decoded `WireResponse`, `audit_chain_has_substitution_entry`, `verify_audit_chain_ok`). Reuse the real libraries — do not re-implement substitution/audit. If the endpoint bin must be present, gate the test to build/locate it, or mark it `#[ignore]` with a clear message + a CI job that runs `--ignored` (report which you chose).

- [ ] **Step 5: Run to verify the witness passes.**

Run: `cargo test -p mvm-runtime --features wasm-backend governed_egress -- --nocapture`
Expected: PASS — all four governance assertions hold.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-runtime/tests/wasm_egress_witness.rs crates/mvm-runtime/tests/fixtures/
git commit -m "test(wasm): data-governance witness — governed egress substitutes + audits (allow path)"
```

---

### Task 4: The witness — deny path (unbound destination fails closed)

- [ ] **Step 1: Write the failing test** in `wasm_egress_witness.rs`:

```rust
#[test]
fn governed_egress_denies_unbound_destination() {
    // Same setup, but the module targets a host NOT in the policy's allow list.
    // The endpoint must refuse; the module sees WireResponse::Refused; the
    // destination is never contacted; a fail-closed audit entry is written.
    // ...reuse Task 3's harness with an unbound url...
    assert!(matches!(observed, WireResponse::Refused { .. }));
    assert!(audit_chain_has_fail_closed_entry(state_dir));
}
```

- [ ] **Step 2: Run — fails** (helper `audit_chain_has_fail_closed_entry` unwritten).
Run: `cargo test -p mvm-runtime --features wasm-backend governed_egress_denies -- --nocapture` → FAIL.
- [ ] **Step 3: Implement `audit_chain_has_fail_closed_entry`** (reads the per-tenant audit log for the endpoint's fail-closed kind — see recon step 3).
- [ ] **Step 4: Run — passes.** Same command → PASS.
- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/tests/wasm_egress_witness.rs
git commit -m "test(wasm): data-governance witness — default-deny on unbound destination"
```

---

### Task 5: Full gate + doc/ledger closeout

- [ ] **Step 1: Run the full gate.**

```
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p mvm-runtime --features wasm-backend -- -D warnings
cargo test -p mvm-runtime --features wasm-backend wasm_backend
cargo test -p mvm-runtime --features wasm-backend --test wasm_egress_witness
cargo tree -p mvm-runtime -e no-dev | rg -c wasmtime   # expect 0
cargo run -q -p xtask -- check-no-spec-refs-in-comments
cargo run -q -p xtask -- check-no-string-backend-dispatch
cargo run -q -p xtask -- check-claim-catalog
cargo run -q -p xtask -- check-core-runtime-free
PATH="$HOME/.cargo/bin:$PATH" cargo build -p mvm-contract --target wasm32-unknown-unknown
cargo fmt -p mvm-runtime && rustup run nightly cargo fmt --all
```

Expected: all clean. `check-claim-catalog` must still be green — the witness adds NO numbered claim.

- [ ] **Step 2: Update the ledger.** In `specs/SPRINT.md`, tick the WS11 `P3b.2` box with the commit shas + "witness passes (allow+deny+substitution+audit); NetworkingNotSupported gate relaxed to governed egress"; in `specs/refactor/11-wasm-backend.md`, mark the P3 POC acceptance gate met. Commit `docs(sprint): WS11 P3b.2 done — governed-egress data-governance witness passes`.

- [ ] **Step 3: Consider the "same witness across all workload backends" promise.** The specs (04/06) say the data-governance witness is a CI witness across *all* workload backends. This plan lands the *wasm* leg. If the microVM backends don't yet have an equivalent chain-verifying witness, note it in `07-progress-and-decisions.md` as a follow-up (do not scope-creep it here).

---

## Self-Review

- **Spec coverage:** P3b.2's design (`11-wasm-backend.md` §"P3 implementation design", steps 1–2 + the witness bullet) is covered: endpoint reuse (Task 3 uses the real `spawn_substitution_endpoint`), the `WireRequest` client (P3a, exercised by the fixture), substitution + audit (asserted in Tasks 3–4), the gate relaxation (Task 1). The "full TLS termination deferred to P3c" note is honored (HTTP-only mock destination).
- **Placeholder scan:** the harness-helper *bodies* in Tasks 3–4 are described, not fully coded, because they depend on the on-disk plan/secret format the implementer must read in the prerequisite recon (writing literal bytes now would be a plausible-but-wrong guess — worse than an explicit "reuse `decode_plan_secrets_from_state`'s format, seed it as libkrun's tests do"). This is a deliberate, flagged boundary, not a lazy TODO: the recon step + the "STOP if it differs" instruction make it safe.
- **Type consistency:** `WireRequest`/`WireResponse` (from `mvm_core::substitution_wire`), `WasmBackend::{new,with_egress_endpoint}` (P3a), `spawn_substitution_endpoint`/`SubstitutionSpawnParams`/`EndpointTransport::Uds` (P3b.1), `vm_substitution_endpoint_socket` (P3b.1) — all match the built code.

## Subsequent plans (out of scope here — each its own design→plan)

- **P3c — HTTPS termination for wasm egress:** give the wasm run a per-VM egress-CA intermediate (`build_egress_tls_delivery`) so the endpoint terminates TLS for `https://` `WireRequest.url`s. Needs a design pass (how the wasm module trusts the intermediate — it has no rootfs trust bundle; likely the module is handed the cert via a WASI preopen / the `WireRequest` stays plaintext-to-endpoint and the endpoint originates TLS). Blocks nothing; the POC is HTTP-only.
- **P4 — browser POC:** `mvm-contract` + the `no_std` OCI decoders + the workload-address (`mvm-core`, doc 12) running in the browser (image inspect/verify + workload fingerprint). Needs its own design (wasm-bindgen/component-model packaging; the `uor-addr`-crate-vs-native decision from doc 12). Independent of P3b.2/P3c.
