# Plan 129 — Secrets subsystem (egress substitution)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement ADR-067 — a raw secret value never enters the guest — in **two tiers**: (1) **declared** secrets are substituted on egress (the workload routes a secret-bearing request through a host substitution endpoint with an opaque placeholder; the host injects (bearer) or signs (SigV4/HMAC) and makes the real TLS; values come from a pluggable resolver — local OS keyring or `mvmd` — with a software-first keyholder, hardware-sealed when present); (2) **undeclared** secrets/PII are caught by the egress detector — **no declaration required** — and redacted/blocked/audited (Phase E). Together they cover "specified *and* predicted." Restores claims 12 + 13.

**Architecture:** Builds on what exists. `mvm-ir`'s `SecretRef` already carries a reference, never bytes; `mvm-core`'s `KeyProvider` (`keystore.rs`) is the local resolver; `mvm-hostd`'s separate signer processes + the keyless `core::subprocess` scaffold are the keyholder substrate; the claim-10 default-deny egress proxy (`NetworkProvider`, ADR-064 / plan 123) is where substitution and leak-detection hang. This plan adds the auth-type metadata, the resolver trait, the keyholder, the substitution endpoint + placeholder protocol, leak-detection, and audit.

**Tech Stack:** `mvm-ir` (→ `mvm-sdk::ir` post-121), `mvm-core` (`keystore.rs`, `core::subprocess`), `mvm-hostd`, `mvm-sdk` (the SDK client + `runtime_substitution.rs` repurposed), the egress proxy in `mvm-network` (123). Existing crypto deps only (`ed25519-dalek`, `aes-gcm`, `keyring`, `zeroize`); no new deps.

**Prereqs / sequencing:**
- **ADR-067** is the design.
- **121** for the post-fold homes (`mvm-core`, `mvm-hostd`, `mvm-sdk::ir`).
- **123** for the egress proxy. **Phases A–C (IR, resolver, keyholder, CLI) are 123-independent and can land first; Phases D–E (substitution endpoint, leak-detection) attach to 123's proxy** and execute after it. Write the proxy in 123 with the substitution + scan seams this plan needs.
- **128** owns the claim-12/13 CI gate; this plan delivers the behavior it asserts.

---

## Phase A — IR contract (123-independent)

### Task A1: `SecretRef` gains `auth_type` + `allowed_hosts`

ADR-067 §4. The reference must say *how* the secret is used (so the keyholder picks signer vs injector) and *where* it may go (binding — claim 12). Still no bytes.

**Files:** `crates/mvm-ir/src/workload.rs` (the `SecretRef` struct ~line 393); `crates/mvm-ir/src/validate.rs`.

- [ ] **Step 1: Failing serde test** — a `SecretRef` round-trips with the new fields and rejects an unknown auth-type.
  ```rust
  #[test]
  fn secret_ref_carries_auth_type_and_hosts_never_bytes() {
      let r: SecretRef = serde_json::from_str(
          r#"{"name":"openai","auth_type":"bearer","allowed_hosts":["api.openai.com"]}"#).unwrap();
      assert_eq!(r.auth_type, AuthType::Bearer);
      assert_eq!(r.allowed_hosts, ["api.openai.com"]);
      // deny_unknown_fields keeps a stray "value" out — no bytes in the IR.
      assert!(serde_json::from_str::<SecretRef>(r#"{"name":"x","value":"sk-..."}"#).is_err());
  }
  ```
- [ ] **Step 2:** Add `auth_type: AuthType` (`#[serde] enum { Sigv4, Hmac, Bearer, Basic }`) and `allowed_hosts: Vec<String>` to `SecretRef`; keep `#[serde(deny_unknown_fields)]` so a literal value can't sneak in. `allowed_hosts` supports `*.` wildcards (a `host_matches(pattern, host)` helper with a unit test for the wildcard edge cases).
- [ ] **Step 3: Commit.**

### Task A2: lift the `SecretsNotImplemented` gate

`validate.rs:649` currently rejects every `SecretRef` env value. With resolution landing, replace the hard reject with real validation (name non-empty, at least one allowed host, auth-type valid).

- [ ] **Step 1:** Failing test — a well-formed `SecretRef` validates; an empty `allowed_hosts` is rejected with a *new* code `SecretWithoutBinding` (an unbound secret is a claim-12 violation, not "not implemented").
- [ ] **Step 2:** Replace the `SecretsNotImplemented` arm with the binding check; drop the now-dead `SecretsNotImplemented` code (and its `error_codes.rs` entry) — no back-compat (first version).
- [ ] **Step 3: Commit.**

## Phase B — resolver + CLI (123-independent)

### Task B1: the `SecretResolver` trait + `Local` impl

ADR-067 §2. One trait, value source swappable. `Local` reads the existing named-secret store.

**Files:** `crates/mvm-hostd/src/keyholder/resolver.rs` (new) + `keyholder/mod.rs`.

> **Reconciliation (post-plan-121):** the plan first named `crates/mvm-core/src/secret/resolver.rs` over `KeyProvider`. Two corrections: (1) `KeyProvider` (keystore.rs) is the *single* per-tenant master DEK — the actual named-secret backend is `SecretStore` (`mvm_core::crypto::secret_store`, the `mvmctl secret put/ls` backend); (2) `SecretRef` now lives in `mvm-sdk::ir`, and `mvm-core` is *below* `mvm-sdk`, so a resolver taking `&SecretRef` cannot live in mvm-core. `mvm-hostd` deps both `mvm-sdk` (SecretRef) and `mvm-core` (SecretStore) and is the admit-time/keyholder home — the resolver lives there, sibling to the Phase C keyholder.

- [x] **Step 1:** Failing test — `LocalResolver` resolves a `SecretRef` whose value was set in the file-backed `SecretStore`, returns it in a `SecretBox<Vec<u8>>` (zeroize on drop); plus an unbound-ref backstop and a missing-secret error path.
- [x] **Step 2:** Define `trait SecretResolver { fn resolve(&self, r: &SecretRef) -> Result<SecretBox<Vec<u8>>, ResolveError>; }`; implement `LocalResolver` over `SecretStore`. `ResolveError::Unbound` is the fail-closed claim-12 backstop (empty `allowed_hosts` never resolves). The `mvmd` resolver is a separate mvmd plan.
- [x] **Step 3: Commit.**

### Task B2: `mvmctl secret set` (the standalone-mvm DX)

ADR-067 §2 — the local define path so the demo needs no `mvmd`.

**Files:** extended `crates/mvm-cli/src/commands/ops/secret.rs` + new `crates/mvm-hostd/src/keyholder/binding.rs`.

> **Reconciliation:** the plan named a *new* `commands/secret.rs`, but a `secret` clap command already exists (`commands/ops/secret.rs`, Plan 63 `put/get/ls/rm`) — a second one would collide, so `set` is added to that enum. Binding metadata (auth-type + allowed-hosts) needs storage separate from the value (`SecretStore` is value-only); it lives in a parallel `FileBindingStore` in `mvm-hostd` (where `AuthType` from mvm-sdk + `SecretStore` from mvm-core are both visible, and the Phase C/D keyholder can reuse it). `rm` now drops the binding too.

- [x] **Step 1:** CLI tests — `cmd_set` stores value (`SecretStore`) + binding (`FileBindingStore`) and the binding sidecar never contains the value; `ls_line` shows name + `type=` + `hosts=` for a bound secret, name-only for a value-only (Plan 63) secret; `rm` removes the binding.
- [x] **Step 2:** `mvmctl secret set <name> --host <h>… --type <sigv4|hmac|bearer|basic>` (value via prompt/stdin/`--value -`/`--value-file`, never argv); value through the existing zeroizing path; `ls` reads the binding store, redacts the value. (The Phase C signing-key-for-sigv4 store is wired in Phase C.)
- [x] **Step 3: Commit.**

## Phase C — keyholder (123-independent)

> **Reconciliation:** both live under `crates/mvm-hostd/src/keyholder/` (`signer.rs`, `injector.rs`), not the plan's standalone `secret_signer/`/`secret_injector/` — ADR-067 §3 literally calls signer+injector "the keyholder, split by auth-type", so they sit with the resolver + binding store under one cohesive module. Both take a `&dyn SecretResolver`. The separate-process moat (a `[[bin]]` under the jailer) is **deferred** — see "deferred follow-ups" below; the in-process lib is what D/E wire against, and the jailer wrap is orthogonal to the signing/injecting logic.

### Task C1: the signer (signing-based: SigV4, HMAC)

ADR-067 §3 gold path. The signer takes a canonical request + a `SecretRef`, returns a signature; the key never leaves it. Hardware-sealed when a Secure Enclave/TPM is present, else a jailed software signer — **same interface**.

**Files:** `crates/mvm-hostd/src/keyholder/signer.rs`.

- [x] **Step 1:** Tests — `Signer::sign_hmac`/`sign_sigv4` return a signature; `Signature` has no key field (no key on the public surface; `check-no-display-on-secret-types` covers Debug). Verified against **published vectors**: RFC 4231 HMAC-SHA256 case 2 + aws-sig-v4-test-suite `get-vanilla`.
- [x] **Step 2:** SigV4 + HMAC over existing `hmac`/`sha2`; key resolved into confined memory; derived SigV4 keys live in `Zeroizing` buffers (no intermediate lingers); the resolved value is a `SecretBox` that wipes on drop. Wrong auth type (bearer/basic) refused → signer is signing-only. (Hardware-sealed handle + jailer wrap: deferred follow-up.)
- [x] **Step 3:** Software path runs with no hardware (the default; all tests exercise it). Sealed-handle path is the deferred hardware follow-up.
- [x] **Step 4: Commit.**

### Task C2: the injector (bearer / basic)

ADR-067 §3 fallback. The raw value must hit the wire, so confine it: decrypt only inside the injector, inject into the request, zeroize. Honest — not "never seen", but minimal + audited.

**Files:** `crates/mvm-hostd/src/keyholder/injector.rs`.

- [x] **Step 1:** Tests — `Injector::inject_placeholder` substitutes the resolved value into the outbound text and returns it `Zeroizing` (wipes on drop); a destination not in `allowed_hosts` returns `DestinationNotBound` (claim 12) and a spy resolver proves **no decrypt** happened; a signing auth type returns `WrongAuthType`, also without decrypting.
- [x] **Step 2:** `allowed_hosts` (and auth-type) checked *before* resolve — no decrypt for an unbound destination; `*.` wildcard binding honored via `host_matches`. (Encrypted-at-rest via 122's DEK/KEK is the value store's concern.)
- [x] **Step 3: Commit.**

### deferred follow-ups (Phase C)

- [ ] Separate-process moat: run the signer + injector as jailed `[[bin]]`s (ADR-066 §3 / `core::subprocess`) so a compromised signer can't read the supervisor's address space. The in-process lib is correct and tested; this is a confinement hardening, sequenced with the broker subprocess model.
- [ ] Hardware-sealed signing path: load the SigV4/HMAC key by handle from the OS keyring → Secure Enclave on macOS, so the host never sees the plaintext key. Same `Signer` interface; the software path is the no-hardware default already shipped.

## Phase D — substitution endpoint + SDK routing (needs 123's proxy)

### Task D1: the host substitution endpoint on the egress path

ADR-067 §1. The workload routes a secret-bearing request to a host endpoint (host-local hop) carrying an opaque placeholder; the endpoint binds-checks, calls the signer/injector, makes the real TLS, streams back.

**Files:** `crates/mvm-hostd/src/keyholder/substitution.rs` (dispatch core); the egress proxy in `mvm-network`/`gateway_bridge` (transport leg); `crates/mvm-sdk` client routing.

> **Reconciliation:** the dispatch *core* lives in `mvm-hostd/src/keyholder/substitution.rs` next to the resolver/keyholder it composes (mvm-hostd → mvm-network, so it can later be driven from the proxy). ADR-067 §1's mechanism is the **endpoint-hop** (host-local vsock/UDS, real-TLS to the destination from the host), not a packet-level rewrite inside the guest's TLS — so the A3 `SubstitutionStage` byte-rewrite seam is *not* the substitution path; it stays available for plaintext and the A3 `ScanStage` is Phase E's leak backstop.

- [x] **Step 1 (logic):** Tests — a placeholder for an `allowed_hosts` destination is substituted to the real credential (output carries the value, the placeholder is gone); a non-allowed destination is refused (`DestinationNotBound`) and a spy resolver proves **no decrypt**; an unknown placeholder is refused without decrypting; session isolation (a placeholder from another registry doesn't resolve). *(Full socket integration with a mock destination + the live bridge + audit emit = the transport-leg follow-up.)*
- [x] **Step 2 (core):** `Placeholder` = opaque high-entropy per-session token (`mvm-secret-<hex>`, not the secret name); `SubstitutionRegistry::mint` records token→`SecretRef`, `resolve` is session-scoped (cross-session replay impossible); `SubstitutionEndpoint::substitute` resolves token → `SecretRef` → injector with the claim-12 binding check. *(Wiring it as a stage in 123's proxy + the signer-path endpoint shape = transport-leg follow-up.)*
- [ ] **Step 3:** SDK routing — the `mvm-sdk` HTTP client (and a documented `HTTP_PROXY`-style escape for non-SDK clients) sends secret-bearing requests to the endpoint with the placeholder. `Sandbox` exposes `mvm.secret("openai")` returning the placeholder token.
- [ ] **Step 4: Commit.** *(dispatch core committed; remaining steps below.)*

### transport leg (D-T1 + D-T2 done)

- [x] **D-T1 — request prep** (`mvm-hostd/src/supervisor/substitution_proxy.rs::prepare_request`): finds the placeholder in each header (`find_placeholder`), resolves it, binding-checks the destination taken from the **request URL** (a guest can't bind to `api.openai.com` then send the bytes elsewhere — the bind-check uses the URL we will dial), substitutes the real credential. Sync, fully unit-tested.
- [x] **D-T2 — the running endpoint**: a host-local **UDS listener** (`SubstitutionService::serve`) speaking a length-prefixed JSON envelope (`WireRequest`/`WireResponse`, `deny_unknown_fields`, base64 body) + a `Forwarder` trait with a hardened-reqwest `ReqwestForwarder` (TLS 1.3 min, SSRF-filtered, no-redirect) for the real-TLS forward. Integration-tested over a **real Unix socket** with a mock forwarder: the destination receives the real credential, the guest never does; an unbound destination is refused and **never reaches the forward leg** (claim 12). The registry is read-only while serving (placeholders minted at admission, ADR-067 §4).

### lifecycle wiring (#1a + #1b-core done; bin glue pending a boot)

- [x] **#1a — admission registry assembly** (`keyholder/admission.rs::assemble_registry`): turns the plan's `SecretBinding`s into a `SubstitutionRegistry` (one opaque placeholder per `Keystore` secret), reconstructing each `SecretRef`'s auth-type + allow-list from the local `BindingStore` (the lowered plan dropped them). Returns `HandedPlaceholders` `(guest name, placeholder)` for the guest. Fails closed on a secret with no local binding; skips `Static`/`External`.
- [x] **#1b core — `SubstitutionService::from_plan`**: assembles the registry + a `LocalResolver` over the tenant secret store + a hardened `ReqwestForwarder`, returning the ready `Arc<SubstitutionService>` + `HandedPlaceholders`. The supervisor bin's remaining job is just bind-UDS + `serve`.

### deferred follow-ups (Phase D)

- [ ] **#1b bin glue** (needs a real boot to validate; backend-specific): in each per-VM host bin (`mvm-libkrun-supervisor`/`mvm-firecracker-bridge`/`mvm-vz-drainer`) call `from_plan`, bind the UDS at the substitution vsock-port path, spawn `serve` on a tokio runtime; declare the vsock port in `SupervisorConfig` + the `mvm-backend` launch so the guest reaches it; inject the `HandedPlaceholders` into the guest env. Pairs with the SDK-routing pass (the placeholders are only *used* once the SDK routes through them) — best landed + boot-validated together.
- [ ] `secret.substituted` / `secret.placeholder_dropped` audit emit (Phase E2) wired into the endpoint's success/refusal paths.
- [ ] Signer-path endpoint shape: the SigV4/HMAC path computes a signature over the canonical request and adds the `Authorization` header (different request shape than the injector's placeholder-substitute); route by `auth_type`.
- [ ] SDK routing (Step 3): `mvm-sdk` HTTP client → endpoint + `mvm.secret("openai")` returning a placeholder + the `HTTP_PROXY`-style escape for non-SDK clients. Reconcile/retire the legacy `mvm-sdk/src/runtime_substitution.rs` (`mvm-secret://`, dead ADR-049 scaffolding superseded by ADR-062) so there is one placeholder format — the opaque `mvm-secret-<hex>` (ADR-067 §4 requires opacity; `mvm-secret://name` embeds the name and must not be used).

## Phase E — leak-detection + audit (needs 123's proxy)

### Task E1: proxy leak-scan — declared secrets **and** predicted PII

ADR-067 §1 backstop, **expanded (owner, 2026-05-31):** the scan catches not just a declared placeholder/known-secret but **predicted PII and secret-shaped values** the workload may emit (it can't leak a *substituted* value — it never held one — but it can still emit an SSN, a card number, an email, or a high-entropy token it generated or got out-of-band). Detect → act (block | redact | audit-only, per the destination's profile) → audit.

**Detectors (dep-conscious — no ML/NLP on the hot path):**
- *declared:* the workload's `SecretRef` values + the minted opaque placeholders (already present).
- *secret-shaped:* regex + Shannon entropy for API-key/token/JWT patterns — the `secretscan` ruleset, or build on the existing `regex` dep with a curated gitleaks-style rule set.
- *PII:* a **Presidio-aligned regex layer** (SSN, card + **Luhn check**, email, phone, IBAN) — the `pii-vault` regex tier is the reference. **No Candle/NER on the default path;** the heavier ML detectors (`pii` NER, `velka` ensemble) are an **off-by-default feature**.

**Files:** the egress proxy scan stage in `mvm-network` (123 A3); `crates/mvm-core/src/redact/` (the detector ruleset — reused by 127 D1's no-secret-in-spans check so one ruleset governs both surfaces).

- [x] **Step 1 (placeholder baseline):** `PlaceholderLeakScan` (a `ScanStage` in `mvm-hostd/src/supervisor/network/stages.rs`) drops any egress carrying the host-reserved `PLACEHOLDER_PREFIX` (`mvm-secret-`) — the ADR-067 §1 "placeholder smuggled out a side channel" backstop. Unit tests: drops a placeholder-bearing egress, passes clean traffic, ignores ingress. Wired **live** into `build_egress_scan` as an always-on backstop (sibling to mandatory-deny); chain test proves it fires with no per-tenant policy. *(The drop is audited via the pipeline's generic flow-fault path carrying `by="placeholder-leak"`; the dedicated `secret.placeholder_dropped` event is the E2 audit refinement.)*
- [ ] **Step 2 (the larger detector set):** secret-shaped (regex + Shannon entropy, gitleaks-style) + PII (Presidio-aligned regex + **Luhn**) over a **bounded window** (`RegexSet`, not full-body buffering), ruleset in `core::redact` (new), per-destination action from the named profile (125 E4). **Owner flagged this as a core feature that may want its own ADR/brainstorm** — land it as its own slice.
- [ ] **Step 3: Commit.** *(placeholder baseline committed; the larger detector set is the remaining E1 work.)*

### Task E2: audit (claim 13 lineage)

**Files:** the chain-signed audit emitter (`mvm-hostd` / `audit_chain`).

- [ ] **Step 1:** Failing tests — every substitution emits `secret.substituted { name, destination, auth_type }`; the audit chain **carries no secret bytes** (assert no entry contains the value); `verify_audit_chain` passes; a tampered entry fails.
- [ ] **Step 2:** Emit the entries; reuse the claim-8 chain. Commit.

## Phase F — the claim-12/13 gate (with 128)

- [ ] **Step 1:** Coordinate with plan 128 to build the CI leak-gate asserting: (a) no code path writes a secret value toward the guest, (b) substitution fires only for bound destinations, (c) the audit chain carries no secret bytes. These are the claim-12/13 tests ADR-067 names; 128 wires them into `ci.yml`.

## Acceptance

- [ ] `SecretRef` carries `auth_type` + `allowed_hosts`, never bytes; the `SecretsNotImplemented` gate is gone, replaced by binding validation.
- [ ] `SecretResolver` with a `Local` (OS keyring) impl; `mvmctl secret set`/`ls` work standalone (no `mvmd`), value never on argv, `ls` redacts.
- [ ] Signer signs SigV4/HMAC without the key leaving it (hardware-sealed when present, software else); injector confines bearer values, refusing unbound destinations before decrypt. **No hardware required to pass the suite.**
- [ ] (post-123) substitution endpoint swaps a placeholder for the real credential only to bound destinations; non-bound placeholders dropped + audited; leak-scan catches side-channel placeholders.
- [ ] Audit emits substitution/drop entries with **no secret bytes**; `verify_audit_chain` green.
- [ ] Claims 12/13 gate (128) green. `cargo test --workspace` + clippy + fmt green; **no new dependency**.

### deferred follow-ups

- [ ] The **mvmd** `SecretResolver` impl + the tenant secret store + rotation → a separate mvmd plan (same trait; production source).
- [ ] OAuth client-assertion / JWT as additional signing auth-types (extend the signer).

## Self-review

- **Spec coverage (ADR-067):** mechanism C (D1), pluggable resolver (B1), software-first keyholder (C1/C2), IR contract + placeholder + audit (A/D/E), no-hardware (C1 §3), claims 12/13 (F). The mvmd resolver + tenant store are explicitly the deferred mvmd half.
- **Sequencing honesty:** A–C land without 123; D–E need 123's proxy and say so; F is 128's gate. No task pretends the proxy exists before 123.
- **No new deps / no secret leakage:** every task reuses an existing crate; the binding-before-decrypt order (C2) and the no-bytes-in-IR/audit assertions (A1/E2) are the load-bearing invariants, tested directly.
- **Voice:** comments mark the non-obvious (why bind-check before decrypt, why the placeholder is opaque/per-session, why argv is unsafe for the value), not the calls.
