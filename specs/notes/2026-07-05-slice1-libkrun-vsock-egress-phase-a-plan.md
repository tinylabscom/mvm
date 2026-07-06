# Slice 1 Phase A — libkrun transparent-TCP vsock egress (flag-gated, NIC retained) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a **no-bound-secret** libkrun workload reach the network through the host vsock `EgressGate` (claim-10) instead of the NIC, opt-in behind the `MVM_VSOCK_EGRESS` host flag, with the gvproxy/passt NIC **retained** so the change is reversible and non-regressing.

**Architecture:** The guest side is already built and inert — `mvm-egress-client` (SOCKS5→vsock, writes `"host:port\n"`), its nix package, and mkGuest Stage 2.6 (gated on the guest env var `MVM_VSOCK_EGRESS`) all exist. This phase lights it up on libkrun: (1) the libkrun backend injects `MVM_VSOCK_EGRESS=1` into the guest entrypoint env via `KrunContext::with_guest_envp` when the host opts in and the workload has no bound secrets; (2) the `mvm-libkrun-supervisor` binds the `EGRESS_PORT` UDS and runs the already-built `mvm_vm_host::egress_server::run(listener, gate)`, mirroring its existing `WORKLOAD_EXIT_PORT` exit-capture pattern. No collision with credential substitution: the substitution endpoint only binds `EGRESS_PORT` when secrets are present, and this phase is scoped to the no-secrets case, so the two are mutually exclusive.

**Tech Stack:** Rust, tokio (supervisor runtime), libkrun-sys `KrunContext`, `mvm_backend::vsock_egress_bridge::egress_gate::EgressGate`, nextest.

## Global Constraints

- No `#[allow(clippy::too_many_arguments)]` in hand-written code — use a params struct + builder (CLAUDE.md).
- All `~/.mvm` / `~/.cache/mvm` paths go through `mvm-core::config` helpers — never inline `$HOME`.
- Reuse first: call `mvm_hostd::supervisor::substitution_endpoint::build_egress_gate` and `mvm_backend::egress_shared::decode_plan_secrets_from_state` — do not reimplement gate/secret decode.
- Every change gated: unset `MVM_VSOCK_EGRESS` (or any workload carrying bound secrets) ⇒ **byte-identical legacy NIC path**. The NIC (`with_gvproxy`/`with_passt`) is **not** removed in this phase.
- Test gate before "done": `cargo fmt --all -- --check` && `cargo nextest run --workspace` && `cargo test --workspace --doc` && `cargo clippy --workspace -- -D warnings`.
- Per-VM aux bins (`mvm-libkrun-supervisor`) are **not** rebuilt by `cargo run`/test — rebuild explicitly with `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor` before any live boot (stale bin ⇒ `deny_unknown_fields` boot failure).

## Scope note (read before starting)

This plan is **Phase A only**. It deliberately does NOT: fold claims-12/13 credential substitution onto the transparent-TCP path, delete the NIC, or widen `check-vsock-only-egress`. Those are **Phase B**, a separate review-gated plan (substitution is a `WireRequest` RPC today; unifying it with the transparent-TCP stream is the security-critical change the ADR-100 Step 2.3 note reserves for maintainer review + a live boot). Phase A stands up and live-proves the transparent-TCP path with the NIC still present as a fallback; Phase B is authored only after Phase A's live boot passes.

---

### Task 1: Expose the secrets-presence check (reuse, make `pub`)

The supervisor and backend must both answer "does this workload carry bound secrets?" to stay mutually exclusive with the substitution endpoint. `decode_plan_secrets_from_state` already answers it but is `pub(crate)` in `mvm-backend`. Promote it and add a thin boolean wrapper.

**Files:**
- Modify: `crates/mvm-backend/src/egress_shared.rs` (the `decode_plan_secrets_from_state` fn, currently `pub(crate)` around lines 16–24)
- Test: `crates/mvm-backend/src/egress_shared.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces: `pub fn decode_plan_secrets_from_state(state_dir: &Path) -> Result<Option<(Vec<mvm_core::plan::SecretBinding>, mvm_core::policy::RedactionPolicy, String)>>` and `pub fn state_has_bound_secrets(state_dir: &Path) -> Result<bool>`

- [ ] **Step 1: Write the failing test** (append to `egress_shared.rs`)

```rust
#[cfg(test)]
mod phase_a_tests {
    use super::*;

    #[test]
    fn state_has_bound_secrets_is_false_for_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        // No plan file written → no secrets.
        assert!(!state_has_bound_secrets(dir.path()).unwrap());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-backend state_has_bound_secrets_is_false_for_empty_state`
Expected: FAIL — `state_has_bound_secrets` not found.

- [ ] **Step 3: Change visibility + add the wrapper**

Change the existing signature from `pub(crate) fn decode_plan_secrets_from_state` to `pub fn decode_plan_secrets_from_state` (keep the body untouched). Then add directly below it:

```rust
/// True when the workload's persisted plan carries at least one bound secret
/// (i.e. the credential-substitution endpoint will own `EGRESS_PORT`). The
/// transparent-TCP vsock egress path (Phase A) is scoped to the `false` case so
/// the two never contend for the port.
pub fn state_has_bound_secrets(state_dir: &Path) -> Result<bool> {
    Ok(decode_plan_secrets_from_state(state_dir)?
        .map(|(secrets, _, _)| !secrets.is_empty())
        .unwrap_or(false))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-backend state_has_bound_secrets_is_false_for_empty_state`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/egress_shared.rs
git commit -m "feat(egress): pub state_has_bound_secrets for Phase A gating"
```

---

### Task 2: Host opt-in flag reader

One host env var, `MVM_VSOCK_EGRESS`, gates the whole phase. Read it in one place.

**Files:**
- Modify: `crates/mvm-build/src/libkrun_network_provider.rs` (next to `resolve_networking_mode`, the existing per-OS networking selector)
- Test: same file, inline

**Interfaces:**
- Produces: `pub fn vsock_egress_opt_in() -> bool`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn vsock_egress_opt_in_reads_env() {
    // Guard: this test mutates process env; keep it serial-safe by scoping.
    unsafe { std::env::set_var("MVM_VSOCK_EGRESS", "1") };
    assert!(vsock_egress_opt_in());
    unsafe { std::env::remove_var("MVM_VSOCK_EGRESS") };
    assert!(!vsock_egress_opt_in());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-build vsock_egress_opt_in_reads_env`
Expected: FAIL — `vsock_egress_opt_in` not found.

- [ ] **Step 3: Implement**

```rust
/// Host opt-in for the transparent-TCP vsock egress path on libkrun (Phase A).
/// Unset ⇒ the legacy gvproxy/passt NIC path is used unchanged. Mirrors the
/// `MVM_NETWORKING` selector convention (present-and-non-empty ⇒ on).
pub fn vsock_egress_opt_in() -> bool {
    std::env::var("MVM_VSOCK_EGRESS")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-build vsock_egress_opt_in_reads_env`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-build/src/libkrun_network_provider.rs
git commit -m "feat(egress): MVM_VSOCK_EGRESS host opt-in reader"
```

---

### Task 3: Supervisor decision predicate (testable, extracted from the bin)

The bin can't be unit-tested directly, so extract the "should I serve vsock egress?" decision into a pure function in the `mvm-vm-host` lib.

**Files:**
- Modify: `crates/mvm-vm-host/src/egress_server.rs` (add a pure predicate + its test)

**Interfaces:**
- Consumes: `SupervisorConfig.krun.host_listen_ports: Vec<u32>`, `mvm_guest::vsock::EGRESS_PORT`
- Produces: `pub fn should_serve_vsock_egress(host_listen_ports: &[u32], opt_in: bool, has_bound_secrets: bool) -> bool`

- [ ] **Step 1: Write the failing test** (append to `egress_server.rs` test module)

```rust
#[test]
fn serves_only_when_opted_in_no_secrets_and_port_present() {
    let egress = mvm_guest::vsock::EGRESS_PORT;
    // Happy path: opted in, no secrets, port listed.
    assert!(should_serve_vsock_egress(&[egress], true, false));
    // Any single disqualifier fails closed.
    assert!(!should_serve_vsock_egress(&[egress], false, false)); // not opted in
    assert!(!should_serve_vsock_egress(&[egress], true, true)); // has secrets
    assert!(!should_serve_vsock_egress(&[], true, false)); // port absent
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-vm-host serves_only_when_opted_in_no_secrets_and_port_present`
Expected: FAIL — `should_serve_vsock_egress` not found.

- [ ] **Step 3: Implement** (add near the top of `egress_server.rs`, outside the test module)

```rust
/// Phase A guard: serve transparent-TCP vsock egress only when the host opted in,
/// the workload carries NO bound secrets (else the substitution endpoint owns
/// `EGRESS_PORT`), and `EGRESS_PORT` is actually forwarded. All three required —
/// fail closed on any missing.
pub fn should_serve_vsock_egress(
    host_listen_ports: &[u32],
    opt_in: bool,
    has_bound_secrets: bool,
) -> bool {
    opt_in
        && !has_bound_secrets
        && host_listen_ports.contains(&mvm_guest::vsock::EGRESS_PORT)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-vm-host serves_only_when_opted_in_no_secrets_and_port_present`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-vm-host/src/egress_server.rs
git commit -m "feat(egress): should_serve_vsock_egress Phase A predicate"
```

---

### Task 4: Bind EGRESS_PORT + run the egress server in the supervisor bin

Wire the already-built `egress_server::run` into `mvm-libkrun-supervisor`, mirroring the existing `WORKLOAD_EXIT_PORT` exit-capture block (`dispatch_config`, lines 168–188).

**Files:**
- Modify: `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` (`dispatch_config`, immediately after the exit-capture block, before the bridge/legacy route at line ~194)

**Interfaces:**
- Consumes: `should_serve_vsock_egress`, `mvm_build::libkrun_network_provider::vsock_egress_opt_in`, `mvm_backend::egress_shared::state_has_bound_secrets`, `mvm_hostd::supervisor::substitution_endpoint::build_egress_gate`, `mvm_vm_host::egress_server::run`, `cfg.krun.vsock_socket_path(port)`, `cfg.network_policy: Option<serde_json::Value>`, `cfg.vm_state_dir: String`

- [ ] **Step 1: Read the orientation context**

Read `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` lines 160–210 to confirm the exit-capture block shape and where `dispatch_config` branches to `run_with_bridge`/`run_legacy`. Confirm `use tokio::net::UnixListener;` is already imported (the exit-capture block uses `UnixListener::bind`).

- [ ] **Step 2: Add the egress-server block** (insert after the exit-capture `if` block, before the `let outcome = if cfg.tenant_id.is_some()` line)

```rust
// Phase A: transparent-TCP vsock egress. When the host opted in and the
// workload carries no bound secrets (so the substitution endpoint is NOT
// binding EGRESS_PORT), bind the EGRESS_PORT UDS and run the claim-10 egress
// server. The NIC is still attached (Phase A retains it); this is the opt-in
// vsock path used to live-prove egress before the NIC is removed in Phase B.
{
    let opt_in = mvm_build::libkrun_network_provider::vsock_egress_opt_in();
    let has_secrets = mvm_backend::egress_shared::state_has_bound_secrets(
        std::path::Path::new(&cfg.vm_state_dir),
    )
    .unwrap_or(false);
    if mvm_vm_host::egress_server::should_serve_vsock_egress(
        &cfg.krun.host_listen_ports,
        opt_in,
        has_secrets,
    ) {
        let policy: mvm_core::network_policy::NetworkPolicy = cfg
            .network_policy
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_else(mvm_core::network_policy::NetworkPolicy::deny_all);
        let gate =
            mvm_hostd::supervisor::substitution_endpoint::build_egress_gate(&policy);
        let egress_sock = cfg.krun.vsock_socket_path(mvm_guest::vsock::EGRESS_PORT);
        let _ = std::fs::remove_file(&egress_sock);
        match UnixListener::bind(&egress_sock) {
            Ok(listener) => {
                std::thread::spawn(move || {
                    let rt = match tokio::runtime::Runtime::new() {
                        Ok(rt) => rt,
                        Err(e) => {
                            eprintln!("mvm-libkrun-supervisor: egress runtime: {e}");
                            return;
                        }
                    };
                    if let Err(e) =
                        rt.block_on(mvm_vm_host::egress_server::run(listener, gate))
                    {
                        eprintln!("mvm-libkrun-supervisor: egress server: {e}");
                    }
                });
            }
            Err(e) => eprintln!("mvm-libkrun-supervisor: bind egress socket: {e}"),
        }
    }
}
```

- [ ] **Step 3: Build the bin (it is not built by test runs)**

Run: `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor`
Expected: builds clean (confirms `vsock_socket_path`, `build_egress_gate`, `NetworkPolicy::deny_all` all resolve; fix imports if not).

- [ ] **Step 4: Workspace test + clippy**

Run: `cargo nextest run -p mvm-vm-host && cargo clippy -p mvm-vm-host --bin mvm-libkrun-supervisor -- -D warnings`
Expected: PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs
git commit -m "feat(egress): run egress_server on EGRESS_PORT in libkrun supervisor (Phase A, gated)"
```

---

### Task 5: Inject `MVM_VSOCK_EGRESS=1` into the guest entrypoint env

So the baked-but-inert `mvm-egress-client` actually starts (mkGuest Stage 2.6 keys on the guest env var `MVM_VSOCK_EGRESS`). Build the env list in a pure, tested helper, then apply it via `KrunContext::with_guest_envp`.

**Files:**
- Modify: `crates/mvm-backend/src/libkrun.rs` (the guest-entrypoint construction — `krun_context_base`, lines 147–195, where `with_guest_envp` is/should be called)
- Test: `crates/mvm-backend/src/libkrun.rs` inline

**Interfaces:**
- Consumes: `mvm_build::libkrun_network_provider::vsock_egress_opt_in`, `mvm_backend::egress_shared::state_has_bound_secrets`
- Produces: `fn workload_guest_envp(base: &[String], opt_in: bool, has_bound_secrets: bool) -> Vec<String>`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn workload_guest_envp_adds_flag_only_when_eligible() {
    let base = vec!["PATH=/usr/bin".to_string()];
    // Eligible: opted in, no secrets → flag appended.
    let got = workload_guest_envp(&base, true, false);
    assert!(got.contains(&"MVM_VSOCK_EGRESS=1".to_string()));
    assert!(got.contains(&"PATH=/usr/bin".to_string()));
    // Not eligible → base returned unchanged (no flag).
    assert_eq!(workload_guest_envp(&base, false, false), base);
    assert_eq!(workload_guest_envp(&base, true, true), base);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-backend workload_guest_envp_adds_flag_only_when_eligible`
Expected: FAIL — `workload_guest_envp` not found.

- [ ] **Step 3: Implement the helper** (add near `krun_context_base` in `libkrun.rs`)

```rust
/// Append `MVM_VSOCK_EGRESS=1` to the guest entrypoint env when the host opted
/// in AND the workload carries no bound secrets. That flag is what mkGuest's
/// Stage 2.6 keys on to start the in-guest `mvm-egress-client` and point the
/// workload's proxy env at the loopback SOCKS5 listener. Otherwise the base env
/// is returned unchanged (legacy NIC path, no in-guest egress client).
fn workload_guest_envp(base: &[String], opt_in: bool, has_bound_secrets: bool) -> Vec<String> {
    let mut envp = base.to_vec();
    if opt_in && !has_bound_secrets {
        envp.push("MVM_VSOCK_EGRESS=1".to_string());
    }
    envp
}
```

- [ ] **Step 4: Apply it at the guest-entrypoint construction site**

In `krun_context_base` (or wherever the workload's `with_guest_envp(...)` is called — confirm via the Step-1 read of Task 4's file is different; here read `libkrun.rs:147–195`), route the env list through the helper. Concretely, where the guest envp is built for a **workload** (root_dir set), replace the direct `.with_guest_envp(base_env)` with:

```rust
let opt_in = mvm_build::libkrun_network_provider::vsock_egress_opt_in();
let has_secrets = crate::egress_shared::state_has_bound_secrets(state_dir).unwrap_or(false);
krun.with_guest_envp(workload_guest_envp(&base_env, opt_in, has_secrets))
```

(If `krun_context_base` does not currently set `with_guest_envp`, add the call on the workload branch only — it is a no-op unless `root_dir` is set, per the libkrun-sys doc at `lib.rs:503`.)

- [ ] **Step 5: Run tests + build**

Run: `cargo nextest run -p mvm-backend workload_guest_envp_adds_flag_only_when_eligible && cargo build -p mvm-backend`
Expected: PASS + clean build.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-backend/src/libkrun.rs
git commit -m "feat(egress): inject MVM_VSOCK_EGRESS=1 into eligible workload guest env (Phase A)"
```

---

### Task 6: Full gate + live-boot verification runbook (manual, gated)

Phase A is "done" only after a live libkrun boot proves the vsock path. This task is the runbook + the checklist that unblocks Phase B.

**Files:**
- Create: `specs/runbooks/slice1-phase-a-libkrun-vsock-egress.md`

- [ ] **Step 1: Run the full workspace gate**

Run: `cargo fmt --all -- --check && cargo nextest run --workspace && cargo test --workspace --doc && cargo clippy --workspace -- -D warnings`
Expected: all green.

- [ ] **Step 2: Rebuild the aux bin explicitly**

Run: `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor && cargo build`
Expected: clean (stale supervisor would fail the boot with a `deny_unknown_fields` error).

- [ ] **Step 3: Live boot — allow path** (macOS with `slp/krun/*` trio installed)

Boot a **no-secrets** workload with an allow-list policy admitting one `host:port`, with `MVM_VSOCK_EGRESS=1` set on the host `machine run`. From inside the guest, a `curl` (which honors `ALL_PROXY=socks5h://127.0.0.1:1080`) to the allow-listed target must succeed. Record the exact command in the runbook.

- [ ] **Step 4: Live boot — deny path**

Same VM, a target NOT on the allow-list: the fetch must fail (gate `Deny`, never dialed). Record.

- [ ] **Step 5: Confirm the NIC is still present (Phase A retains it)**

`ip link` inside the guest shows the NIC in addition to `lo` (Phase A does not remove it). Record — Phase B is what removes it and flips this assertion to "only `lo`".

- [ ] **Step 6: Write the runbook + commit**

Capture Steps 2–5 (commands, expected output, actual output) in `specs/runbooks/slice1-phase-a-libkrun-vsock-egress.md`, then:

```bash
git add specs/runbooks/slice1-phase-a-libkrun-vsock-egress.md
git commit -m "docs(runbook): Slice 1 Phase A libkrun vsock egress live-boot verification"
```

- [ ] **Step 7: Unblock Phase B**

Only once Steps 3–5 pass on a real boot: author the Phase B plan (fold claims-12/13 substitution onto the transparent-TCP front door as TLS-terminating behavior; remove `with_gvproxy`/`with_passt` + terminator/redirect; widen `check-vsock-only-egress` to `libkrun.rs` + the supervisor). Phase B is security-touching and requires maintainer review per the ADR-100 Step 2.3 note.

---

## Self-review notes

- **Spec coverage (design doc Slice 1):** Phase A covers the reversible, non-regressing half — vsock egress path stood up + live-proven with NIC retained. The design doc's Slice-1 items that remain (substitution fold, NIC delete, gate widening) are explicitly deferred to Phase B with a review gate, consistent with the ADR-100 Step 2.3 note that reserves the substitution unification for maintainer review. No silent scope drop.
- **Reuse:** gate built via `build_egress_gate`; secrets via `decode_plan_secrets_from_state`; env inject via existing `with_guest_envp`; supervisor wiring mirrors the existing exit-capture block. No reimplementation.
- **Type consistency:** `EGRESS_PORT: u32`; `host_listen_ports: Vec<u32>`; `vsock_socket_path(u32) -> PathBuf`; `build_egress_gate(&NetworkPolicy) -> EgressGate`; `egress_server::run(UnixListener, EgressGate)`. All match the signatures read from source.
- **Fail-closed:** every predicate requires all conditions; missing/undecodable policy ⇒ `deny_all`; ineligible ⇒ legacy path unchanged.
