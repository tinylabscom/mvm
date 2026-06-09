# Plan 129 — Secrets subsystem (egress substitution)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement ADR-067 — a raw secret value never enters the guest — in **two tiers**: (1) **declared** secrets are substituted on egress (the workload routes a secret-bearing request through a host substitution endpoint with an opaque placeholder; the host injects (bearer) or signs (SigV4/HMAC) and makes the real TLS; values come from a pluggable resolver — local OS keyring or `mvmd` — with a software-first keyholder, hardware-sealed when present); (2) **undeclared** secrets/PII are caught by the egress detector — **no declaration required** — and redacted/blocked/audited (Phase E). Together they cover "specified *and* predicted." Restores claims 12 + 13.

**Architecture:** Builds on what exists. `mvm-ir`'s `SecretRef` already carries a reference, never bytes; `mvm-core`'s `KeyProvider` (`keystore.rs`) is the local resolver; `mvm-hostd`'s separate signer processes + the keyless `core::subprocess` scaffold are the keyholder substrate; the claim-10 default-deny egress proxy (`NetworkProvider`, ADR-064 / plan 123) is where substitution and leak-detection hang. This plan adds the auth-type metadata, the resolver trait, the keyholder, the substitution endpoint + placeholder protocol, leak-detection, and audit.

**Tech Stack:** `mvm-ir` (→ `mvm-sdk::ir` post-121), `mvm-core` (`keystore.rs`, `core::subprocess`), `mvm-hostd`, `mvm-sdk` (the SDK client + `runtime_substitution.rs` repurposed), the egress proxy in `mvm-network` (123). Existing crypto deps only (`ed25519-dalek`, `aes-gcm`, `keyring`, `zeroize`); no new deps.

## Status (2026-06-08) — egress-substitution loop wired end-to-end (QEMU); remaining = on-box boot e2e + Python/TS surface

**The full path now exists on `main` (QEMU backend):** `mvmctl up` (secret-bearing plan) → `QemuBackend::start` spawns the `mvm-substitution-endpoint` moat → it opens the encrypted host store, mints opaque placeholders, hands them back (never values) → `invoke` injects `HTTP_PROXY` + placeholders into the workload → the workload's egress hits the in-guest forward proxy → relayed over vsock → the host endpoint substitutes the real credential → real TLS. The guest only ever holds opaque placeholders. PRs #710 (transport), #711 (`RunEntrypoint.env`), #713 (drop dead in-guest ADR-049), #715 (endpoint moat), #717 (QEMU spawn), #718 (invoke env + guest forward proxy). Each leg is unit/integration-tested; the live guest→host boot e2e is the one remaining validation. SDK `secret()` authoring (`type`/`hosts`) + the ADR-049 retirement also landed (#722/#723); the **SDK authoring half is done**.

**Follow-on direction — SDK-free egress (decided 2026-06-08):** the egress path above requires the workload to honor `HTTP_PROXY` / the in-guest forward proxy. Per the directive *egress is mvm's job, not the SDK's*, the next slice replaces that with a **host-side transparent terminator**: the gateway redirects guest egress (nft `nat OUTPUT REDIRECT`, scoped to passt's uid — feasibility proven on the box) to a host listener that reuses the existing substitution endpoint, so a generic `curl` (no SDK, no proxy env) gets substituted. `https` needs name-constrained TLS termination (ADR-006). Design + staged plan: `specs/notes/plan-129-egress-substitution-sdk-free-design.md` and `specs/notes/plan-129-stage1b-2-transparent-terminator-plan.md` (Stage 1b terminator core landed on branch `feat/plan-129-egress-terminator`; see that plan's "Resume state"). SDK-free authoring (`mvmctl run --secret NAME:HOST`): `specs/notes/plan-129-stage1-sdk-free-authoring-implementation.md`.

### On-box endpoint validation (2026-06-08, dev-kvm)

The real `mvm-substitution-endpoint` was driven over **real AF_VSOCK on the box
against a real encrypted `FileSecretStore`** (`mvmctl secret set`), not a mock:

- **Placeholder mint:** the endpoint minted `mvm-secret-<hex>` for the bound
  secret and handed back only that (the value never appears in the handshake).
- **Substitution success:** a request carrying `Authorization: Bearer <placeholder>`
  to the bound host → the endpoint substituted and forwarded over real TLS; the
  destination (`postman-echo.com`) echoed `Bearer sk-DUMMY-…` (the **real**
  credential), with the placeholder absent. Status 200.
- **Claim-12 refuse:** the same placeholder to an **unbound** host
  (`evil.example.com`) was refused before any forward — "destination
  `evil.example.com` is not in the secret's allowed_hosts".

So the endpoint + store-decrypt + bind-check + substitution + forward are proven
live. What remains is only the literal guest-VM origination (a guest connecting
to host CID 2 vs. the host-loopback CID 1 used here) — the host listener + wire
+ store + substitution path is identical regardless of which CID dials.

> ⚠️ **Operator note (TLS 1.3 floor):** the forward leg uses
> `hardened_client_builder` with a **TLS 1.3 minimum** (Plan 65 W7). A secret
> bound to a **TLS-1.2-only** destination (e.g. `httpbin.org`) fails the forward
> with `peer is incompatible: ServerTlsVersionIsDisabledByOurConfig` (surfaced
> clearly after #720's error-chain fix). This is intended hardening, but it
> means egress to legacy-TLS upstreams is refused — document per-destination, or
> revisit the floor if a real upstream needs 1.2.

### Boot e2e runbook (the remaining gate, dev-kvm box)

Proves the live guest→host leg end-to-end. Each component is already tested in
isolation (#710 host `serve_vsock` over real vsock loopback; #715 endpoint over
UDS; `build_substitution_env`; `secrets_from_signed_json`; **2026-06-08 on-box
endpoint validation above**); this ties them on a real QEMU guest.

1. **Local secret + binding** (host store the endpoint opens):
   `mvmctl secret put openai <key>` then
   `mvmctl secret set openai --host <echo-host> --type bearer`
   (use a header-echo host, e.g. an httpbin-style `/headers`, as the bound dst).
2. **Secret-declaring workload**: a minimal app whose entrypoint issues an HTTP
   request to `https://<echo-host>/headers` with `Authorization: Bearer <ph>`
   through `HTTP_PROXY`, and prints the response. Declares the secret via
   `mvm.secret("openai", type="bearer", hosts=["<echo-host>"])` so `up` lowers
   it into `plan.secrets` (`lower_workload_secrets`). **Built:**
   `examples/python/secret-egress/` (declares a bearer secret bound to
   postman-echo.com).
3. **Run** — `mvmctl compile <app> --out <dir>` then `mvmctl up --flake <dir>`.
   > ✅ **Resolved (2026-06-09): local secret-workload launch is wired (mvm's
   > domain).** Scope decision: admission (`admit_for_run`/`admit_plan_for_boot`),
   > the local secret store (`~/.mvm`), and the per-VM substitution endpoint all
   > live in mvm — admission ≠ deploy/tenant/`--prod` (those stay in mvmd). So
   > the dev/test launch on a `/dev/kvm` box is mvm-local. `mvmctl compile` now
   > **strips** the managed `SecretRef` from the baked image (secret-free rootfs;
   > the guest var is a boot-injected placeholder) and emits `workload.json`;
   > `mvmctl up --flake <dir>` auto-discovers it, lowers `plan.secrets`, admits,
   > and the QEMU backend spawns the endpoint (#717). The earlier "mvmd-only"
   > lean predated #717/#718 landing the endpoint spawn *in mvm*.
4. **Assert**: the echo response shows the **real** credential (substitution
   happened host-side), `~/.mvm/vms/<vm>/substitution.pid` existed during the
   run and is gone after `stop`, and a request to an **unbound** host is refused
   (502 from the forward proxy / `WireResponse::Refused`). Confirms guest→host
   AF_VSOCK (CID 2:5253) + endpoint substitution + the forward leg.

   > **Box validation (2026-06-09, dev-kvm `88.99.197.234`, QEMU):**
   > - ✅ `compile` produces a **secret-free image** (`launch.json` env `{}`),
   >   `workload.json` carries the `SecretRef`.
   > - ✅ `up --flake <dir>` auto-discovers `workload.json` → admits a plan whose
   >   `.secrets` carry the binding → **spawns `mvm-substitution-endpoint`**.
   >   (Required a fix: the main `up` path only threaded the signed plan to the
   >   backend under `MVM_GATEWAY_BRIDGE=1`; QEMU now threads it unconditionally.)
   > - ✅ The **guest holds only the placeholder** —
   >   `substitution-env.json = [["API_KEY","mvm-secret-…"]]`, the real value
   >   never present. The "never on the microVM" guarantee, validated live.
   > - ✅ Endpoint **lifecycle**: alive during the run, reaped on `down`.
   > - ✅ **`invoke <name> --attach`** dispatches a `RunEntrypoint` into the
   >   running `up` workload, reusing its endpoint + boot-minted placeholders —
   >   the function body runs with the injected `HTTP_PROXY` + placeholder env.
   >   (The ephemeral serverless `invoke <artifact>` path stays a follow-up:
   >   `boot_session_vm` skips plan-64 admission + auto-selects a non-endpoint
   >   backend.)
   > - ✅ **Guest loopback made functional (split to PR #749):** two independent
   >   bugs both broke the guest's own `lo` → the forward proxy on
   >   `127.0.0.1:18080` was unreachable. (1) netinit's interface-agnostic
   >   blackhole route for `127.0.0.0/8` (in `MANDATORY_DENY_RANGES`) — fixed by
   >   skipping loopback in the guest install (`Report.skipped_loopback`);
   >   on-box `skipped_loopback:["127.0.0.0/8"]`, the `EINVAL` is gone. (2) `/init`
   >   never brought `lo` up (the kernel creates it DOWN) → `ENETUNREACH` to
   >   `127.0.0.1` — fixed by an `ip link set lo up` early in PID-1 init. Either
   >   alone is insufficient.
   > - ⏳ **Destination-sees-real-credential — pending box re-validation** with
   >   #749's full loopback fix (#745 + #749 combined). The remaining residual
   >   risk is only the real-QEMU guest→host vsock-relay leg (proven over loopback
   >   CID in #710, not yet guest→host CID 2). Tracked below.

### Deferred follow-ups (surfaced by the local-launch e2e)

- [ ] **Live secret-egress on QEMU (box re-validation)** — with #749's loopback
      fix the forward-proxy ↔ vsock-relay ↔ endpoint path should complete;
      re-validate destination-sees-real-credential + claim-12 refusal +
      redact-to-`XXX` on QEMU (#745 + #749). Residual risk: the real-QEMU
      guest→host vsock-relay leg (CID 2), proven only over loopback CID in #710.
- [ ] **Forward proxy + `https`/`CONNECT`** — standard clients tunnel `https`
      through `HTTP_PROXY` via `CONNECT`, hiding headers from the proxy, so
      substitution only works for `http`/absolute-form today. TLS-destination
      support needs the proxy to handle `CONNECT` (or the SDK to ship an
      absolute-form client). The example uses `http://` for this reason.
- [ ] **Ephemeral serverless `invoke <artifact>`** — today `invoke --attach`
      dispatches into a running `up` workload; the one-shot ephemeral form needs
      the `boot_session_vm`/exec transient path wired through plan-64 admission +
      endpoint spawn + QEMU selection (a cross-subsystem change to the
      template/session-VM world).

### Original plan status (2026-06-07) — host + guest Rust foundation landed; remaining = boot + 2 design decisions

**Merged to `main` (12 PRs):** the entire unit/integration-testable Rust surface —
- **Host keyholder** (`mvm-hostd/src/keyholder/`): `resolver` (B1), `binding` store (B2), `injector` (C2), `signer` (C1, RFC 4231 + AWS get-vanilla vectors), `sigv4` canonical-request builder (exact-match + e2e signature vs get-vanilla), `substitution` (registry + endpoint dispatch: `substitute` inject path + `sign` signing path, claim-12 bind-check-before-decrypt), `admission` (`assemble_registry` + `from_plan`).
- **Host endpoint** (`mvm-hostd/src/supervisor/substitution_proxy.rs`): the UDS `SubstitutionService` (real-TLS `ReqwestForwarder`, `from_plan`, optional audit `Recorder`) + `secret_audit` (`secret.substituted`/`placeholder_dropped`, claim 13) + the live `PlaceholderLeakScan` (E1 baseline).
- **Shared contract** (`mvm-core/src/substitution_wire.rs`): `WireRequest`/`WireResponse`.
- **Guest** (`mvm-guest/src`): `substitution_client` (vsock relay) + `forward_proxy` (parse + render + serve, model ii).

> 🔴 **Box-validation finding (2026-06-07, dev-kvm `88.99.197.234`): the substitution transport is backend-shaped and the guest→host direction isn't established on QEMU.** The box (and Linux runtime) uses the **QEMU** backend (`mvm-backend/src/qemu.rs`) with **real AF_VSOCK** (`vhost-vsock`). Its existing vsock bridge is **host→guest** (`spawn_vsock_bridge`/`dial_vsock` — the host dials *into* the guest agent on 5252). Substitution needs **guest→host**, and `mvm-guest::substitution_client` calls `vsock::connect_to_port`, which is the **Firecracker UDS-multiplexer** model (`CONNECT <port>` handshake) — *not* QEMU AF_VSOCK. So before the boot wiring, the transport needs a **backend-aware guest→host vsock path**: a host AF_VSOCK listener on `SUBSTITUTION_PORT` (QEMU) / the UDS-multiplexer (Firecracker), and a guest connect that picks the right one. This is a real design gap the box surfaced — the box confirmed it *builds `mvmctl` + boots QEMU workload VMs with the agent up*, but egress substitution can't be wired guest→host until this transport exists.
> - [x] **Guest side fixed:** `mvm-guest::vsock::connect_host_vsock(port)` — a raw-libc **AF_VSOCK connect to `HOST_CID` (2)**, the backend-agnostic guest→host direction (mirrors `qemu.rs::dial_vsock`). `substitution_client::substitute` + `forward_proxy::start_forward_proxy` now use it (dropped the bogus `uds_path`/`connect_to_port` host→guest primitive they were inverted on). The AF_VSOCK fd wraps as a `UnixStream`, so the frame helpers + relay tests are unchanged.
> - [x] **Host side done:** `SubstitutionService::serve_vsock` + a `cfg(linux)` `vsock` module (`VsockListener` binds/listens AF_VSOCK `VMADDR_CID_ANY:port`; blocking `accept` via `spawn_blocking`; the accepted fd is adopted as a tokio `UnixStream` so it reuses `handle_connection`). QEMU uses `serve_vsock`; Firecracker/libkrun keep `serve` (per-port UDS). Raw libc, no new dep; compiles + clippy-clean on native Linux (box). **The transport is now complete both directions** — the per-VM bin selects `serve`/`serve_vsock` by backend, then the 4 wiring pieces.

**Remaining — all needs a real microVM boot to validate, plus the Python/TS toolchains; do NOT land on the live egress path unvalidated.** Two pieces also need a **design decision** first:

1. **Forward-path signing integration** — when a placeholder resolves to a SigV4/HMAC secret, the endpoint must build the `SigningInput` (`build_sigv4_input` / payload) → `sign` → add the `Authorization` header instead of injecting. **DECISION NEEDED:** (a) the **sign-request signal** the guest emits (which header/marker says "sign this with secret X" vs the inject path's `Bearer <placeholder>`), and (b) the **AWS credential shape** (SigV4 needs access-key-id + secret-key + optional session-token — store as one combined value per name, or multiple? ADR-049's `aws_credentials_from_placeholders` took them separately).
2. **Guest init wiring** — **helpers landed** (`forward_proxy::start_forward_proxy` binds loopback `FORWARD_PROXY_PORT` + serves with the real vsock relay; `forward_proxy::proxy_env_url()` is the `HTTP_PROXY` value). **Remaining (boot):** call `start_forward_proxy` on a thread at guest start, and set `HTTP_PROXY`/`HTTPS_PROXY=proxy_env_url()` in the workload's launch env.
   > ⚠️ **Finding (2026-06-07): there is no workload-env-injection path today.** `mvm-guest/src/entrypoint.rs::execute` runs the workload under **`.env_clear()`** and adds nothing; `CallCaps`/`ValidatedEntrypoint` carry **no env field**. So injecting `HTTP_PROXY` + the placeholder vars is **new cross-process plumbing**, not a thin call: (i) host computes `secret_placeholder_env` + `HTTP_PROXY`, puts it in the `RunEntrypoint` request / plan; (ii) the **signed agent protocol** (`RunEntrypoint`, a `cargo-fuzz` claim-5 surface) carries an `env: Vec<(String,String)>`; (iii) `execute` gains an env param and does `.envs(env)` after `env_clear`. This is launch-critical + touches the fuzzed wire protocol → **build + boot-validate on a KVM box; do not write blind.**
   > - [x] **(ii)+(iii) landed (PR pending):** `GuestRequest::RunEntrypoint` + `WorkerCallRequest` gained `env: Vec<(String,String)>` (`#[serde(default)]` = optional on the wire; schema `protocol-v0.json` regenerated). `execute` takes `env` and does `.env_clear().envs(safe_env)`, **filtering malformed entries** (empty key / key with `=`/NUL / value with NUL) so a host-supplied bad entry can't panic `Command::env` and DoS the agent. Cold path fully wired + tested (`test_execute_injects_env_and_clears_inherited`, `test_execute_skips_invalid_env_entries`, serde roundtrips). **Deferred follow-up:** the **warm-pool** path now *carries* `env` to the worker over `WorkerCallRequest`, but the SDK-built wrapper does not yet *apply* `req.env` — a warm worker ignores injected env until the SDK runner is taught to honor it. Track before enabling warm-pool on the live egress path.
   > - [x] **(i) landed (#718):** `invoke.rs` reads `mvm_core::config::vm_substitution_env_path` → `build_substitution_env` prepends `HTTP_PROXY`/`HTTPS_PROXY` (+lowercase) = `proxy_env_url()` to the placeholder vars → passes them as the `RunEntrypoint.env` arg; the guest agent starts `start_forward_proxy` on a startup thread. **Loop wired end-to-end.**
3. **`#1b` endpoint spawn** — **DECISION (2026-06-08, user): a dedicated per-VM moat process holds plaintext secrets, not the per-backend supervisor bin.** Rationale: the one process that decrypts secrets should be minimal + confinable (ADR-002 process-moat), separate from the general VM supervisor. The host (mvm-local) holds the encrypted secrets in `~/.mvm`; the endpoint opens them by path. QEMU-first (the only on-box-validatable backend; it has no supervisor bin anyway).
   > - [x] **Stage 1 landed (PR #715):** `mvm-substitution-endpoint` bin + `supervisor::substitution_endpoint` lib (sibling moat to `mvm-broker`/`mvm-host-signer`). Reads `EndpointConfig` on stdin (tenant, plan secrets, transport {Vsock{port}|Uds{path}}, optional store-dir overrides) → opens `FileSecretStore`+`FileBindingStore` by path → `from_plan` → binds listener → writes ONE stdout handshake line of `(guest var, placeholder)` pairs (never values) → serves (`serve_vsock` for QEMU / `serve` UDS for FC/libkrun). Tested: config serde + `assemble` + offline e2e of the real bin over UDS (spawn → handshake → unbound-destination request → claim-12 refuse, zero egress). Box-validated (vsock arm compiles on Linux).
   > - [x] **Stage 2 landed (#717 spawn, #718 invoke-env + guest forward proxy):** `QemuBackend::start` decodes the plan's secrets (`secrets_from_signed_json`) and — when non-empty — spawns `mvm-substitution-endpoint` detached (Vsock `SUBSTITUTION_PORT=5253`), reads the handshake → `substitution-env.json`; `stop()` reaps via `substitution.pid`; fail-closed (endpoint-spawn failure rolls back qemu). `invoke` injects `HTTP_PROXY` + placeholders; the guest agent runs the forward proxy. **W1.3 port-allowlist is N/A on QEMU** — the endpoint binds AF_VSOCK via the kernel (no mvm proxy in between); libkrun/FC will need the per-port UDS declared when those backends are wired.
   > - [ ] **Remaining: on-box boot e2e** — a secret-declaring workload making a bound-host request through `HTTP_PROXY` with a placeholder → assert the destination saw the real credential (substitution) and an unbound host is refused. Needs a small harness (secret workload + local secret + admitted plan + header-echo destination). The transport halves are each proven (#710 host `serve_vsock` over real vsock; guest `connect_host_vsock` is standard AF_VSOCK to CID 2); the e2e ties the live guest→host path together.
4. **Python `mvm.secret()` surface** — return the admission-minted placeholder (`sdks/python/mvm/_dsl.py`). (needs pytest)
5. **Retire the cross-language ADR-049 API** — Rust `mvm-sdk/src/runtime_substitution.rs` (0 crate callers) + Python `sdks/python/mvm/_runtime.py` + TS `sdks/typescript/src/runtime.ts` (all `mvm-secret://`, superseded by ADR-062), so one opaque format remains (`mvm-secret-<hex>`). (cross-language; needs pytest + npm test)
6. **F** — claim-12/13 CI gate (with Plan 128).

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
- [x] Signer-path endpoint shape (host-side dispatch): `SubstitutionEndpoint::sign(placeholder, destination, SigningInput)` resolves the placeholder, binding-checks the destination (claim 12), then dispatches to the C1 `Signer` (`SigningInput::SigV4` → `sign_sigv4`, `Hmac` → `sign_hmac`); the key never leaves the signer. Refuses unknown placeholder / unbound destination before resolving, and an injector (bearer/basic) secret via the signer's `WrongAuthType`. Tests use the published RFC 4231 + AWS get-vanilla vectors as oracles.
- [x] **SigV4 canonical-request builder** (`keyholder/sigv4.rs::build_sigv4_input`): turns an HTTP request (method/url/headers/body + region/service) into the `SigV4Input` the signer needs — canonical URI, sorted+encoded canonical query, sorted lowercased canonical+signed headers, SHA-256 payload hash, scope from the `x-amz-date` header. Validated **exact-match against the published AWS get-vanilla canonical request** *and* its end-to-end signature, plus structural tests. *Known limitation (tracked):* canonical-URI passes the path through as-is (clean API paths + S3 single-encode); the non-S3 double-encode + UTF-8/reserved-char path edge cases need the full aws-sig-v4-test-suite vector matrix.
- [ ] **Forward-path signing integration (boot):** in the endpoint, when a placeholder resolves to a SigV4/HMAC secret, build the `SigningInput` (`build_sigv4_input` for SigV4; payload for HMAC), call `sign`, and add the `Authorization` (+ for SigV4 the scope/credential) header to the forwarded request — instead of injecting. The SDK sets `x-amz-date` + `host`.
- [x] **#4a — shared wire contract:** `WireRequest`/`WireResponse` moved to `mvm_core::substitution_wire` (the only crate both the in-guest client and the host server share), with serde-roundtrip + `deny_unknown_fields` + tagged-enum tests; host `substitution_proxy` migrated to the shared types (no drift between guest and host bytes). mvm-core stays runtime-free (pure serde).
- [x] **#4b — guest substitution client (relay half):** `mvm-guest/src/substitution_client.rs::relay`/`substitute` — frames a `WireRequest` to the host endpoint over vsock (`SUBSTITUTION_PORT = 5253`, added to `vsock.rs`) and returns the `WireResponse`. Tested over a `UnixStream` socket pair (round-trip + refusal). **Decision (Option A):** the guest-local **`HTTP_PROXY` forward proxy** is the routing model (language-agnostic; a workload can't bypass substitution; matches ADR-067 §1) — this client is its relay leg.
- [x] **#4c — guest forward-proxy front** (`mvm-guest/src/forward_proxy.rs`, model ii): `parse_proxied_request` (absolute-form proxied HTTP → `WireRequest`; the real `https://` destination survives so the host makes the TLS — no in-guest MITM), `render_response` (host `WireResponse` → HTTP/1.1 with re-derived framing; a refusal → `502`), and `serve` (accept → read → parse → relay → render → write, one request/connection, bad-request/relay-error → 502, never panics). The `relay` is injected (production = a closure over `substitution_client::substitute`). End-to-end tested over local TCP with a mock relay + parser/renderer unit tests (malformed/oversized inputs fail closed). Hand-rolled minimal HTTP parse — no new dep.
- [ ] **#4 remainder (boot-validated):** wire `serve` into the guest init (bind the proxy listener, pass the real `substitute` relay) + `HTTP_PROXY`/`HTTPS_PROXY` env so the workload routes through it; the Python `mvm.secret("name")` surface returns the admission-minted placeholder (`sdks/python/mvm/_dsl.py`); `#1b` bin glue injects `HandedPlaceholders` into guest env + exposes `SUBSTITUTION_PORT` (incl. the host proxy port-allowlist W1.3); the `sign` wire op; retiring the legacy cross-language ADR-049 substitution API (Rust `runtime_substitution.rs` + Python `_runtime.py` + TS `runtime.ts`, all `mvm-secret://`, superseded by ADR-062) so there is one opaque format (`mvm-secret-<hex>`; ADR-067 §4 requires opacity).

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

**Files:** `mvm-hostd/src/supervisor/secret_audit.rs` (emit helpers) + `substitution_proxy.rs` (wiring).

- [x] **Step 1:** Tests — `emit_secret_substituted` writes `secret.substituted { name, destination, auth_type }` to the chain-signed stream; the chain **carries no secret value** (asserted); `verify_audit_chain` passes; a tampered entry fails verification. `emit_secret_placeholder_dropped` records `secret.placeholder_dropped { destination }`. Plus an end-to-end test: a successful substitution over the UDS endpoint emits `secret.substituted` (value absent from the chain).
- [x] **Step 2:** Both events emit via `Recorder::record_unbound(EventCategory::Secret, …)` (same claim-8 chain). `secret.substituted` is wired **live** into `SubstitutionService` (optional `Recorder` via `with_recorder`; `resolve_meta` supplies name+auth-type without touching the value; best-effort, never fails the request). Committed.

> **Deferred:** wiring `secret.placeholder_dropped` into the live packet pipeline (the drop is already audited via the generic `gateway.flow_observer_fault` with `by="placeholder-leak"`; the dedicated event is a refinement, landed with the #1b bin-glue pass).

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
