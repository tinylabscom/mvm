# Plan 104 — Host Services Broker over vsock

Companion ADRs: [`specs/adrs/059-host-services-broker.md`](../adrs/059-host-services-broker.md) (original two-process design — merged) + [`specs/adrs/061-host-services-broker-hardening.md`](../adrs/061-host-services-broker-hardening.md) (four-subprocess hardening — merged) + **[`specs/adrs/062-host-services-broker-rescope-drop-secrets.md`](../adrs/062-host-services-broker-rescope-drop-secrets.md) (rescope — drop secrets, add `host.audit.v1`; current source of truth as of 2026-05-28)**
Follow-up plan (sketched at end): host-logging — plan number TBD
Cross-repo mvmd dependency: `../mvmd/specs/plans/52-host-services-cross-vm-endpoints.md` + `../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md`
Tracking sprint: **Sprint 57** in `specs/SPRINT.md` (Sprint 56 = symmetric trust boundary + claim 10).

> **Rescope banner (2026-05-28 — ADR-062).** This plan was drafted around `host.secrets.v1` as the load-bearing forcing function. Project-direction review on 2026-05-28 dropped `host.secrets.v1` and `mvm-secrets-dispatcher` from v1 scope (see [ADR-062](../adrs/062-host-services-broker-rescope-drop-secrets.md) for the decision rationale). The architecture is now **3 subprocesses** (`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`), the broker hosts **`host.audit.v1` as a workload-callable service** in place of secrets, and the W1a–W1b.2b.3 hardening infrastructure (already merged via PRs #478, #480, #481, #482, #483, #486) is preserved unchanged.
>
> Where this plan still describes `host.secrets.v1`, `mvm-secrets-dispatcher`, the 4-subprocess architecture, the ADR-049 SDK matrix (W7), or the secret-specific S22/S24/S25/S26/S28 threats: those sections are **superseded by ADR-062** in their secrets-specific specifics. The non-secrets reasoning in those sections (process isolation patterns, hardening layers, audit chain integrity, mvmd cross-VM delegation, hardware enclave host signer in W8) stays valid and is the basis for the remaining work.
>
> W5 (`host.secrets.v1` implementation) is deleted from the build sequence. W7 (ADR-049 SDK matrix) is deleted. A new sibling of W3 (call it W3-audit) adds the `host.audit.v1` handler.

> **Plan-numbering note (2026-05-26).** This plan was first drafted as Plan 97 / ADR-056, then 98 / 057, then Plan 98 / ADR-059, and finally **Plan 104 / ADR-059** because `98-vz-builder-vm.md` and `103-w6a-implementation-tracker.md` landed on `origin/main` mid-conversation (taking Plan 98 and Plan 103 respectively). Per the saved "spec numbering chaos" guidance, re-verify ALL numbers with `gh pr list` + `git fetch && git log --diff-filter=A -- specs/plans/104-*.md` *immediately* before opening the implementation PR. **Do not propose explicit Claim 10/11 numbers in ADR-059** — Sprint 56 holds Claim 10 already. Let ADR-059 assign claim numbers against ADR-002's live list at write time.

## Context

Today, anything a microVM needs from the host arrives one of two ways:

1. **Boot-time only** — read-only ext4 drive mounted at `/mnt/secrets` or `/mnt/config` (`mvmctl up --volume host_dir:/mnt/secrets`). ADR-048 explicitly tags this `unsafe_guest_secret_materialization` and declines to make a non-leakage claim about it.
2. **A small fixed-verb reverse channel** — `HostBoundRequest` on vsock port 53 carries `WakeInstance`, `QueryInstanceStatus`, `QueryHostTime` (`crates/mvm-guest/src/vsock.rs`). Each new verb is a code change to an enum.

There's also a **half-built secrets path**: `ExecutionPlan.secrets: Vec<SecretBinding>` exists in `crates/mvm-plan/src/plan.rs:96`; `KeystoreReleaser` trait stubs in `crates/mvm-supervisor/src/keystore.rs` return `NotWired` / `NotImplemented`; the `secrets:` field is hardcoded empty in synthesis (`plan_builder.rs:216`). **ADR-049** has committed to a vsock side-channel for secret substitution as the v1 mechanism — described in prose, stubbed in code.

What's needed is broader than secrets: a **host-side services layer** microVMs call at runtime — secrets today, then cost / time / logging / audit / monitoring as the catalog grows — with one auth model, one capability model, one audit chain, and **one extension point that supports built-in *and* addon-provided services** without protocol churn.

This plan generalizes ADR-049's "vsock substitution service" into a **services broker** hosting `host.secrets.v1` as its first (and most security-critical) tenant. The broker pattern is the right substrate; secrets is the right forcing function.

Intended outcome: after this plan lands, ADR-049's substitution service exists as `host.secrets.v1`, `HostBoundRequest::QueryHostTime` is gone (replaced by `host.time.v1`), the supervisor exposes a registry that new services plug into without protocol churn, and the workload's permission to call a given service is declared in the signed `ExecutionPlan` and enforced by the supervisor before the handler ever runs.

## Architecture

### Wire shape

- **Two vsock ports per VM:**
  - **Port 5300 — general broker channel.** Hosts `host.time.v1`, `host.cost.v1`, `broker.v1` (observational / low-criticality services). Dispatched by an in-process task in the per-VM supervisor.
  - **Port 5301 — secrets channel.** Hosts `host.secrets.v1` only. Dispatched by a dedicated **secrets subprocess** that runs alongside the supervisor (uid 902, seccomp `standard`, no FS/net beyond the per-VM Unix-domain socket back to the supervisor for audit + UDS to listen for forwarded calls). The supervisor's broker is a transparent proxy: gates 1–4 run in the supervisor; gate 5 + handler dispatch happen inside the secrets subprocess.
  - Both ports use 4-byte big-endian length prefix; payload is **JSON** (`serde_json`). Frame is wrapped in `AuthenticatedFrame` (Ed25519 + session id + sequence — already implemented in `crates/mvm-guest/src/vsock.rs`). Authenticated from day one on both ports.
- **Envelope (host-bound):**
  ```rust
  #[serde(deny_unknown_fields)]
  pub struct ServiceCall {
      pub service: ServiceId,
      pub verb: String,
      pub correlation_id: Ulid,
      pub payload: serde_json::Value,
  }
  ```
- **Envelope (guest-bound):**
  ```rust
  #[serde(deny_unknown_fields)]
  pub enum ServiceResponse {
      Ok { correlation_id: Ulid, payload: serde_json::Value },
      Err { correlation_id: Ulid, code: ServiceErrorCode, message: String },
  }
  ```
- `ServiceId` is reverse-DNS-like with a version segment: `host.secrets.v1`, `host.time.v1`, `host.cost.v1`. Versions explicit so v2 can ship alongside v1 without breaking callers.
- **Why JSON not CBOR.** v1 has no genuinely binary payload (signed credentials base64 cleanly into a `credential_b64` field; time/cost are ints; list_services is strings). JSON wins on debuggability (`jq` works), cross-language story (every SDK ecosystem has a robust JSON parser; the W7 ADR-049 hook matrix avoids CBOR-library-quality friction), and consistency with the existing `GuestRequest` / `HostBoundRequest` JSON discipline in `crates/mvm-guest/src/vsock.rs`. If a future service ships actual binary, the field can be base64-in-JSON — 33% overhead on that *one field* at ~500-byte typical payloads is negligible.
- **Why two ports + secrets-in-subprocess (T4 production-ready isolation).** The supervisor's general-broker dispatcher and the secrets dispatcher share zero code paths and zero address space. A logic bug in the schema/dispatcher/quota path of the general broker cannot reach the secrets subprocess's memory or registry. This is the production-ready isolation pattern (industry analogues: AWS STS, HashiCorp Vault, Kubernetes ServiceAccount token controllers — all out-of-process). Same envelope + handler trait + audit chain, different runtime processes.

### Host-side: four-subprocess architecture

> The earlier draft of this section described a two-process design
> (supervisor in-process broker + secrets subprocess). It has been
> superseded by the four-subprocess design below per §Hardening
> posture Layer 1. The two-process design is preserved in commit
> history; the four-process design is the v1 target.

The supervisor is a pure launcher + admission controller + IPC router.
Four per-VM subprocesses share zero address space with the supervisor
and zero address space with one another. Each runs for the lifetime of
the guest, dies when the supervisor dies (via `PR_SET_PDEATHSIG` on
Linux or kqueue parent-pid watcher on macOS), and is restart-on-crash
up to three times per workload lifetime (after which the workload
pauses for operator review). See §Hardening posture L1 for the
isolation rationale and L3 for the per-subprocess hardening that
applies uniformly across all four.

**`mvm-broker` (uid 903 — general broker subprocess):**

- New crate `crates/mvm-broker/` producing a binary spawned by the
  supervisor per VM. Hosts `HostTimeV1Handler`, `HostCostV1Handler`,
  `BrokerV1Handler` (the introspection `list_services` verb).
- Listens on **vsock port 5300** directly (the supervisor sets up
  the listener via the backend-specific mechanism — see W1) AND on
  per-VM UDS `~/.mvm/vms/<vm>/services/broker.sock` for
  supervisor-proxied calls (mode 0600, supervisor-owned).
- Hosts the `ServiceHandler` trait registry for in-process handlers.
  For composed calls that cross into `host.secrets.v1`, the broker
  proxies to the secrets dispatcher via UDS (the composition
  boundary crosses two process boundaries: broker ↔ supervisor ↔
  secrets dispatcher).

**`mvm-secrets-dispatcher` (uid 902 — secrets subprocess):**

- New crate `crates/mvm-secrets-dispatcher/` producing a binary
  spawned by the supervisor per VM. Hosts ONLY `host.secrets.v1`;
  cannot register additional handlers at runtime.
- Listens on **vsock port 5301** directly + per-VM UDS
  `~/.mvm/vms/<vm>/services/secrets.sock` for supervisor-proxied
  calls (mode 0600).
- Read-only access to the host signer *public* key for verifying
  responses returned to it from `mvm-host-signer`. Holds no
  host-signing key material.

**`mvm-host-signer` (uid 904 — host-signing subprocess):**

- New crate `crates/mvm-host-signer/` producing a binary spawned by
  the supervisor per VM. Holds the host signer key (software path
  in W1; HW-enclave path in W8 per Layer 2).
- Listens on per-VM UDS `~/.mvm/vms/<vm>/services/host-signer.sock`
  for typed "sign this hash" RPCs from the supervisor (admission
  ceremony) and from `mvm-secrets-dispatcher` (signed-credential
  generation per ADR-049).
- No network, no FS beyond the UDS + the enclave handle (W8) or
  fallback key file (W1).

**`mvm-audit-signer` (uid 905 — audit-chain-signing subprocess):**

- New crate `crates/mvm-audit-signer/` producing a binary spawned
  by the supervisor per VM. Sole writer to
  `~/.mvm/audit/<tenant>.jsonl`; sole holder of the audit
  chain-signing key.
- Listens on per-VM UDS
  `~/.mvm/vms/<vm>/services/audit-signer.sock` for typed
  `EventCategory::*` entries from the supervisor and (via
  supervisor proxy) the other subprocesses.
- JCS-canonicalizes entries, computes `prev_hash`, signs, appends
  via an `O_APPEND` FD (H-L5.1) with dir-immutable enforcement.
  Persists `chain_head` to a secondary location on every entry
  (H-L5.2). Per-tenant ChaCha20-Poly1305 encryption at rest
  (H-L5.4).

**Supervisor (the orchestrator that remains):**

- Module `crates/mvm-supervisor/src/services/` holds the four UDS
  proxy clients (`broker_proxy.rs`, `secrets_proxy.rs`,
  `host_signer_proxy.rs`, `audit_signer_proxy.rs`), the
  registry assembly logic, circuit breakers, quotas, the
  `MvmdClient` trait, and the `ServiceHandler` trait definition
  (the trait is in `mvm-core` so all subprocesses can implement
  it). Supervisor itself implements no `ServiceHandler` — those
  live in the broker / secrets dispatcher subprocesses.

```rust
#[async_trait]
pub trait ServiceHandler: Send + Sync {
    fn id(&self) -> ServiceId;
    fn profiles(&self) -> &[AgentProfile];
    fn audit_durability(&self) -> AuditDurability;  // PerCall | Batched(Duration)
    fn response_size_cap(&self) -> usize;           // default 64 KiB
    fn idempotency(&self) -> Idempotency;           // see §C3
    fn call_timeout(&self) -> Duration;             // see §C4
    async fn dispatch(&self, ctx: &ServiceCallCtx, verb: &str, payload: serde_json::Value)
        -> Result<serde_json::Value, ServiceError>;
}
```

**Why four processes is mandatory, not optional:** see §Hardening
posture L1. Short version: a supervisor UAF previously exfiltrated
the host signer key (compromising all future plans), let a logic
bug forge audit entries (compromising forensic integrity), and let
a parser bug pivot into the credential-minting code. With four
subprocesses each in their own seccomp + setpriv + cgroup +
namespace compartment, none of these pivots survive.

### ExecutionPlan schema change

```rust
#[serde(default, deny_unknown_fields)]
pub services: Vec<ServiceBinding>,

pub struct ServiceBinding {
    pub service: ServiceId,
    #[serde(default)]
    pub policy: ServicePolicy,      // service-specific opaque JSON
    #[serde(default)]
    pub quotas: ServiceQuotas,      // per-workload-lifetime budgets (see §Security)
}
```

Existing `secrets: Vec<SecretBinding>` stays — it's the **policy blob** for the `host.secrets.v1` binding. The supervisor's broker assembly looks up `host.secrets.v1` and constructs a `HostSecretsV1Handler` parameterized by `plan.secrets`. No duplication.

### Capability gating — five sequential rules

Before any handler dispatch, a call traverses five rules in order. **They are sequential, not isolated within a single process** — for the general broker, all five run in the same supervisor task, in the same address space, parsing with the same `serde_json` parser, against state co-located in one process. **Process-level isolation only exists for `host.secrets.v1` calls**, which cross the UDS boundary to the secrets subprocess (gate 5 runs there in a separate address space; gates 1–4 still run in the supervisor — see §"Host-side: four-subprocess architecture").

1. **Schema gate** — `serde_json` parse of the envelope with `deny_unknown_fields`; 64 KiB max frame size enforced *before* parse; recursion cap 8; 50ms parse timeout. **Note:** `deny_unknown_fields` covers only the outer envelope (`service`, `verb`, `correlation_id`, `payload`) — the `payload` itself is `serde_json::Value`, which is dynamically typed and **does not get `deny_unknown_fields` at envelope-parse time**. The typed second-stage parse via `ServiceHandler::parse_payload` (gate 5 prerequisite) is the *real* payload schema gate. See §S19.
2. **Authentication gate** — `AuthenticatedFrame` Ed25519 verify against workload session key (minted at plan admission, discarded at workload stop). Monotonic-sequence replay rejection.
3. **Binding gate** — workload's `ExecutionPlan.services` must bind this `ServiceId`. Bindings can't be added at runtime.
4. **Profile + rate-limit + quota gate** — `AgentProfile` check; token-bucket per `(workload_id, service_id)`; in-flight cap; lifetime quota (see §Security S12).
5. **Handler-specific policy** — per-handler `parse_payload` with typed `deny_unknown_fields` (the real schema gate); destination-URL match for `host.secrets.v1`; mvmd tenant-scoped-authz (ADR-0008) for cross-VM verbs.

### Audit chain

Extend `EventCategory` in `crates/mvm-supervisor/src/audit_recorder.rs` with one new variant `ServiceCall`. Every dispatch — allowed or denied — emits one entry: `(service, verb, outcome, correlation_id)`. **Payload content is never logged** (ADR-053 §4 redaction invariant); per-handler audit subentries take typed `AuditFields` (no `String` payload param).

### Cross-VM data via mvmd (delegation pattern)

Cross-VM concerns (tenant-aggregated cost, peer discovery, tenant config) belong in **mvmd**, not the per-VM supervisor (CLAUDE.md: "mvmd owns tenant isolation; mvmctl never reaches across workloads").

- `MvmdClient` trait in `crates/mvm-supervisor/src/services/mvmd_client.rs`. Real impl uses **mvmd-agent's iroh ALPN transport** (`crates/mvmd-agent/src/transport.rs` — iroh's QUIC stack multiplexed via ALPN with typed `AgentRequest`/`AgentResponse` enums; **NOT raw QUIC+mTLS** as earlier drafts described). New broker verbs land as additional `AgentRequest` variants, not as HTTP routes the agent proxies. Test-mode in-process impl backs out for unit tests.
- **Cross-tenant authorization happens on mvmd's side** via tenant-scoped-authz (ADR-0008). Broker never assembles cross-tenant data itself.
- Built-in handler split:
  - **No mvmd dep**: `host.time.v1`, `host.secrets.v1`, `host.cost.v1::workload` verb.
  - **Mvmd-delegated**: `host.cost.v1::tenant` verb, `host.peers.v1` (future), `host.config.v1` (future), `host.logging.v1` forwarding (the host-logging follow-up plan).

### Guest side

- New module `crates/mvm-guest/src/services.rs` (broker client). `AuthenticatedFrame` + JSON.
- `GuestCapability::ServicesBroker` advertised in `ProtocolHello`, gated by `AgentProfile`.
- Broker exposes no code-execution verb; `host.secrets.v1` returns signed destination-bound credentials, not raw bytes. ADR-002 claim 4 and ADR-048 secret non-leakage preserved.

### SDK side

- `crates/mvm-sdk/src/services/`: `client.rs`, `host_secrets.rs` (ADR-049 hook-point dispatcher), `host_time.rs`, `host_cost.rs`.
- Python surface: `mvm.services.host_time()`, `mvm.services.host_cost()`. Secrets is invisible (auto-substitution at HTTP middleware level per ADR-049).

## Extensibility design

Extensibility is designed in along seven orthogonal axes:

### A1 — Versioned ServiceIds + parallel versions

- `ServiceId` carries `.v1` suffix. v2 ships alongside v1 on different IDs (`host.secrets.v1` and `host.secrets.v2` coexist in the registry).
- Workloads bind explicitly to a version. No silent upgrades.
- **Deprecation lifecycle:** a service is marked `deprecated_in("2027-Q1")` in its handler metadata. `broker.v1/list_services` surfaces the deprecation flag. At the deprecation date, the handler is hard-removed in a single PR (per saved rule "no backwards compatibility — this is the first version"). The migration window is explicit but not extended via shims.

### A2 — Cargo feature flags per built-in service

- `crates/mvm-supervisor/Cargo.toml` gains features: `service-host-secrets`, `service-host-time`, `service-host-cost`, `service-host-cost-mvmd` (the cross-VM verb), `service-broker-meta` (always on — `broker.v1/list_services`). All on by default.
- Slim builds (e.g., the builder VM init binary) can compile out unused services: `mvm-builder-init` ships with `--no-default-features --features service-host-time` only.
- Each handler module is `#[cfg(feature = "service-…")]`-gated; the static catalog assembles only enabled handlers.

### A3 — `ServicePolicy` as service-defined typed schema

- `ServicePolicy` is `serde_json::Value` in the wire schema, but each handler declares a **typed Rust schema** for its own policy:
  ```rust
  impl ServiceHandler for HostSecretsV1Handler {
      type Policy = SecretsPolicy;
      fn parse_policy(&self, raw: JsonValue) -> Result<Self::Policy, _> { … }
      …
  }
  ```
- Schema lives next to the handler. Adding a new policy field is a single-file change.
- `xtask check-handler-policy-schema` lint enforces every handler ships a typed `Policy` (no opaque-JSON escape hatch in built-ins).
- For v2 out-of-process addons (see A4), the addon manifest declares its policy schema as JSON Schema; the broker validates inbound policy against it at admission.

### A4 — Out-of-process handler substrate (v1 ships it; the secrets subprocess is its first consumer)

The out-of-process handler substrate has a **mandatory v1 consumer**: the secrets dispatcher (see §"Host-side: four-subprocess architecture"). This kills the "speculative substrate, no v1 consumer" criticism — every line of the proxy substrate is exercised by the security-critical secrets path on every workload start.

**Substrate (v1):**
- The supervisor's broker dispatches `HandlerRef::OutOfProcess(UdsProxy)` for any handler registered with an out-of-process reference. The proxy uses the same `ServiceCall`/`ServiceResponse` envelope over a per-VM Unix-domain socket at `~/.mvm/vms/<vm>/services/<service_id>.sock` (mode 0600, supervisor-owned).
- The supervisor performs gates 1–4 *before* forwarding (schema, auth, binding, profile/rate-limit/quota). Forwards only validated calls. The out-of-process handler performs gate 5 + dispatch.
- The handler subprocess runs under seccomp `standard` + setpriv (`--bounding-set=-all --no-new-privs`) + uid 902 (separate from agent uid 901 and supervisor uid 0). It has no FS or net access beyond the supervisor-owned UDS, and a read-only view of the host signer's *public* key for verification.
- Audit entries flow back to the supervisor over the UDS; the supervisor is the sole writer to the chain-signed log. The subprocess holds no audit key material.

**v1 consumer:** `mvm-secrets-dispatcher` binary hosting `host.secrets.v1` only.

**v2 consumer (separate plan):** third-party addon services declare themselves via a manifest at `~/.mvm/services/<service_id>/manifest.toml` carrying `id`, `version`, `binary`, `policy_schema_url`, `audit_subentry_schema_url`, `signature` (signed under existing claim-9 deps-audit pipeline). The supervisor scans `~/.mvm/services/` at admission, verifies signatures, and registers any addons bound by the workload's `ExecutionPlan.services` as `HandlerRef::OutOfProcess`. The wire protocol, audit flow, and lifecycle are *identical* to the v1 secrets dispatcher — when v2 ships, no protocol or substrate change is needed. **The v1 secrets dispatcher serves as the design's existence proof.**

**TCB:** broker stays minimal. Subprocess faults can't crash the supervisor. Subprocess code can't reach the supervisor's memory. Workload trusts the supervisor's signature on the envelope (which the supervisor adds *after* the subprocess returns), not the subprocess's — so a compromised subprocess can return wrong data within its service scope but cannot impersonate other services or forge audit entries.

### A5 — Service composition (services calling services)

- A handler may invoke other handlers via an in-process `ServiceCallContext::invoke(service_id, verb, payload)` — useful for, e.g., `host.config.v1` fetching a credential through `host.secrets.v1`.
- **Recursion cap:** invocation depth limited to 3. Beyond that → `ServiceErrorCode::CompositionDepth`. Audit chain records the call tree.
- **Capability requirement:** the calling handler must declare statically which services it composes (`fn composes_with() -> &[ServiceId]`). The CI lint `xtask check-handler-composition` verifies declared composition matches actual `invoke()` calls in the source. The composing-handler's plan binding doesn't automatically grant the composed service — the workload's plan must bind both.

### A6 — Version negotiation at plan admission

- During `admit_for_run`, the supervisor inspects the workload's `ExecutionPlan.services` binding set and verifies every requested `ServiceId` is in the static catalog (or, in v2, has a discovered addon manifest). Missing services → admission refused with a structured error listing the unsupported IDs.
- The SDK's compile-time decorator (`@mvm.bind("host.cost.v1")` or equivalent) inserts the binding into the workload's IR; if the host catalog doesn't support that ID, `mvmctl up` fails fast at admission rather than at first call.

### A7 — Per-tenant service catalogs (mvmd)

- mvmd Plan 52 exposes `GET /v1/host-services/tenant/{tenant_id}/catalog` returning the set of services this tenant is allowed to use. Different tenants can have different catalogs (a Free tenant might not see `host.cost.v1::tenant`; an Enterprise tenant might see `host.config.v1`).
- At workload admission, the per-VM supervisor pulls the tenant catalog from mvmd-agent, intersects it with the workload's `ExecutionPlan.services` bindings, and refuses any binding not in the tenant's catalog. The intersection is signed and recorded in the audit chain at admission.

## Build sequence

Each wave is independently mergeable and leaves `cargo test --workspace && cargo clippy -- -D warnings` green. **Check off as completed.**

- [ ] **W1 — Four-subprocess infrastructure substrate** *(no mvmd dep; ~3× the baseline W1 scope per §Hardening posture L1+L3)*
  - [ ] `ServiceCall` / `ServiceResponse` envelope types in `crates/mvm-broker/src/protocol.rs` (JSON via `serde_json`)
  - [ ] `ServiceId`, `ServiceErrorCode`, `ServiceCallCtx` newtypes (`mvm-core` so all subprocesses can share)
  - [ ] `ServiceHandler` trait + `ServiceRegistry` with `HandlerRef::{InProcess, OutOfProcess}` discriminator
  - [ ] **Algorithm-identifier byte in `AuthenticatedFrame`** (H-L4.1) — wire change; `0x01=Ed25519`, `0x02=ECDSA-P256` reserved for W8
  - [ ] **Per-spawn ephemeral keypair + response signing per subprocess** (H-L4.2)
  - [ ] **Supervisor-assigned correlation IDs at frame ingress** (H-L4.6)
  - [ ] **Two vsock listeners per VM (per backend; NOT uniform "wire it in"):**
    - [ ] **libkrun** — bind ports 5300 + 5301 via `add_vsock_port2(port, host_path, listen=true)` in `crates/mvm-libkrun/src/sys.rs`; `mvm-broker` subprocess reads 5300, `mvm-secrets-dispatcher` reads 5301
    - [ ] **Firecracker** — bind via the in-process `Supervisor` struct in `crates/mvm-supervisor/src/supervisor.rs`; supervisor passes accepted FDs to the respective subprocesses
    - [ ] **Apple Container** — host-as-listener path parallel to libkrun's, both ports
    - [ ] **vz (Apple Silicon)** — *new Swift work:* `VZVirtioSocketListener` class added to `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/` with `shouldAcceptNewConnection` plumbing, relays accepted sockets for BOTH ports to their respective subprocesses via host-side UDS. **The Swift supervisor has no listener path today** (`VsockProxy.swift` is host-as-client only). Substantial sub-task.
  - [ ] **`crates/mvm-broker/` NEW crate** (H-L1.3) — general broker subprocess, uid 903, hosts `host.time.v1` / `host.cost.v1` / `broker.v1`; listens on vsock 5300 + per-VM UDS `~/.mvm/vms/<vm>/services/broker.sock` (mode 0600). Seccomp `standard` per H-L3.3, setpriv `--bounding-set=-all --no-new-privs`.
  - [ ] **`crates/mvm-secrets-dispatcher/` NEW crate** — secrets subprocess, uid 902; listens on vsock 5301 + per-VM UDS `~/.mvm/vms/<vm>/services/secrets.sock` (mode 0600). Read-only access to host signer *public* key only.
  - [ ] **`crates/mvm-host-signer/` NEW crate** (H-L1.1) — host-signer subprocess, uid 904; listens on per-VM UDS `~/.mvm/vms/<vm>/services/host-signer.sock` for typed "sign this hash" RPCs from supervisor. Holds the host signer key (software path in W1; HW-enclave path lands in W8).
  - [ ] **`crates/mvm-audit-signer/` NEW crate** (H-L1.2) — audit-signer subprocess, uid 905; sole writer to `~/.mvm/audit/<tenant>.jsonl`; sole holder of audit chain-signing key. Listens on per-VM UDS `~/.mvm/vms/<vm>/services/audit-signer.sock` for typed entries.
  - [ ] **Cosign-verify every subprocess binary at spawn** (H-L3.1); refuse-to-spawn on mismatch; audit `<subprocess>.signature_invalid`
  - [ ] **TOCTOU-resistant verify-then-exec** (H-L3.2) — mmap + verify + `fexecve` / `posix_spawn`-with-FD
  - [ ] **Subprocess config-signing** (H-L3.6) — supervisor signs config JSON before passing on stdin; subprocess refuses to start unless signature verifies
  - [ ] **Explicit seccomp policy per subprocess** (H-L3.3) via `seccompiler`, per-arch (x86_64 + aarch64)
  - [ ] **macOS sandbox profile per subprocess** (H-L3.4) via `sandbox_init_with_parameters`
  - [ ] **Resource caps on every subprocess** (H-L3.9): `RLIMIT_CORE=0`, `RLIMIT_AS`, `mlockall(MCL_FUTURE)`, `PR_SET_DUMPABLE=0` / `PT_DENY_ATTACH`, `PR_SET_THP_DISABLE`
  - [ ] **Binary hardening flags + per-binary reproducibility lane** (H-L3.10): PIE + RELRO + canaries + FORTIFY_SOURCE=3; CI-asserted via `checksec`
  - [ ] **Static-link + W^X + no `dlopen` + anti-debug** (H-L3.11)
  - [ ] **No-shared-FDs invariant + CI lint `xtask check-subprocess-fd-inheritance`** (H-L3.8)
  - [ ] **Per-workload cgroup + namespace isolation** for the four-subprocess set (H-L1.4)
  - [ ] **CPU pinning** of each subprocess to a separate core where available (H-L7.4); doctor flags downgrade
  - [ ] Supervisor subprocess lifecycle for all four subprocesses: spawn at VM admission, attach via `PR_SET_PDEATHSIG` (Linux) / kqueue-monitored parent-pid watcher (macOS). Restart-on-crash with backoff (100ms, 500ms, 2s), max 3 restarts per workload lifetime; beyond → audit `<subprocess>.crashed_repeatedly` and workload pause.
  - [ ] **Subprocess slow-start detection** (H-L7.3): `BROKER_SUBPROCESS_START_DEADLINE_MS=2000`; refuse workload on breach
  - [ ] **Admission blocks until all four subprocesses healthy** (H-L5.7) — no in-supervisor audit buffer
  - [ ] `crates/mvm-supervisor/src/services/{broker_proxy.rs, secrets_proxy.rs, host_signer_proxy.rs, audit_signer_proxy.rs}` — UDS clients forwarding to each subprocess
  - [ ] **Zeroize at every proxy buffer** (H-L3.7) — `zeroize::Zeroizing<Vec<u8>>` on forward + return paths
  - [ ] All proxies reject every call with `NotBound` (no handlers registered yet; subprocesses ship stub-handler scaffolding in W1)
  - [ ] Service composition `ServiceCallContext::invoke` API with depth cap (composition crosses the process boundary; tested via stub handler) + **width cap** (H-L6.5)
  - [ ] Cargo feature flags: `service-host-secrets`, `service-host-time`, `service-host-cost`, `service-host-cost-mvmd`, `service-broker-meta`
  - [ ] **`mvmctl doctor` host-posture checks** (H-L7.2): KASLR, KPTI, SMEP/SMAP, Spectre-v2, LSM, `unprivileged_userns_clone=0`, `dmesg_restrict=1`, macOS SIP+AMFI+kext; refuse admission on weak hosts; `--insecure-host` audits + warns
  - [ ] **KSM off + THP off doctor enforcement** (H-L7.1)
  - [ ] **Constant-time comparisons via `subtle::ConstantTimeEq`** (H-L4.5) on all security-byte comparisons; CI grep lint
  - [ ] **`fido_touch_required()` stub** (G2 → H-L11.6) — `mvmctl up --prod` calls it, today no-ops + audits `operator.fido.unverified`; full impl in W11
  - [ ] Tests: envelope serde roundtrip (JSON), `deny_unknown_fields` on envelope rejection, `AuthenticatedFrame` happy path with algorithm-identifier byte, replay rejection, length-prefix tampering rejection, frame > 64 KiB rejection, recursion cap rejection, parse timeout, composition depth + width caps (including cross-process), subprocess crash isolation per-subprocess (kill any subprocess mid-call; supervisor survives; workload sees `Err(Unavailable)`), supervisor crash teardown (kill supervisor; all four subprocesses exit cleanly via pdeathsig/kqueue), cross-backend listener attaches and accepts on all four backends, both ports, cosign-verify rejects tampered binary, config-signing rejects tampered config, FD-inheritance lint catches stray FD, supervisor-side response-signature verify rejects stub-subprocess forgery (H-L9.1 hostile-subprocess test per subprocess kind), `subprocess_set_ready` barrier blocks admission until all four up, slow-start detection refuses workload
- [ ] **W2 — ExecutionPlan + admission wiring + audit-signer wiring** *(no mvmd dep)*
  - [ ] Add `services: Vec<ServiceBinding>` + `ServiceBinding` + `ServicePolicy` + `ServiceQuotas` to `crates/mvm-plan/src/plan.rs`; bump `SCHEMA_VERSION` 4→5 (no shim per no-backcompat rule)
  - [ ] Update synthesis (`plan_builder.rs:216`)
  - [ ] **Admission ceremony rewired to call `mvm-host-signer` for plan signing** (H-L1.1) — supervisor no longer reads the host signer key directly
  - [ ] Extend `admit_for_run` to assemble per-VM `ServiceRegistry`; refuse admission for unsupported service IDs (clear error listing them)
  - [ ] Per-handler typed `Policy` parsing via the `parse_policy` trait method
  - [ ] **`mvm-audit-signer` receives typed `EventCategory::ServiceCall` entries over UDS; JCS-canonicalizes + chain-signs + appends** (H-L1.2)
  - [ ] **`O_APPEND` audit-chain FD + dir-immutable enforcement** (H-L5.1): `chattr +a` (Linux) / `UF_APPEND` (macOS); test asserts `lseek` returns EBADF
  - [ ] **Anti-rollback chain-head persistence** (H-L5.2): persist `chain_head` to `~/.mvm/audit/HEAD` (fsync'd) or kernel keyring on every entry
  - [ ] **Audit-log encryption at rest** (H-L5.4): per-tenant ChaCha20-Poly1305 key (software KDF in W2; TPM/SE-derived in W8)
  - [ ] **Time-source integrity** (H-L5.5): use TPM monotonic counter or kernel boottime as integrity anchor; emit `audit.clock.jump_detected` on backward jumps
  - [ ] **Operator-action audit entries** (H-L6.1) — every privileged `mvmctl` invocation emits a chain-signed entry
  - [ ] **Audit fsync-failure → workload pause policy** (H-L6.6)
  - [ ] Token-bucket rate-limit + lifetime-quota + in-flight cap implementation in `quota.rs`
  - [ ] **Tenant-level secret call quota** stub in supervisor (H-L6.3); full mvmd-enforced cap lands in W4b
  - [ ] **Per-call ephemeral session-key rotation** (H-L4.3): `BROKER_SESSION_REKEY_CALLS=1000` / `BROKER_SESSION_REKEY_MS=60000`
  - [ ] Circuit breaker in `circuit_breaker.rs`
  - [ ] Tests: plan synthesis + verification with bindings, audit-chain entry shape (JCS-canonical), unknown-binding rejection at admission, lifetime quota exhaustion, circuit breaker opens after N failures, in-flight cap enforced, bootstrap-order (workload calls broker before broker ready) returns `NotReady`, audit chain head persisted to second location, `O_APPEND` audit FD rejects `lseek`, encryption-at-rest roundtrip, clock-jump backward detected and audited, session-key rotation triggers correctly
- [ ] **W3 — `host.time.v1`** *(no mvmd dep)*
  - [ ] Implement `HostTimeV1Handler`
  - [ ] Add `broker.v1/list_services` introspection verb (returns bound services + verbs + deprecation flags)
  - [ ] **Delete** `HostBoundRequest::QueryHostTime` and its host-side dispatch (no shim)
  - [ ] Update the only internal caller of `QueryHostTime` to use the broker
  - [ ] Tests: handler returns sane wall+monotonic, profile/binding gates, rate-limit triggers, list_services returns bound set + deprecation flags
- [ ] **W4a — `host.cost.v1` (workload-scope only)** *(no mvmd dep; ⚠️ hidden dependency on building cost accumulators)*
  - [ ] **Prerequisite: build per-workload cost accumulators in `crates/mvm-supervisor/src/cost.rs`** — they do NOT exist today (verified 2026-05-26: no `cost.rs`, no accumulator type in `crates/mvm-supervisor/src/`). Schema: `WorkloadCostAccumulator { cpu_seconds: f64, ram_mb_seconds: f64, vsock_bytes_in: u64, vsock_bytes_out: u64, ts_start: SystemTime }`. Updated by the supervisor's existing per-VM hooks (cgroup poll for CPU/RAM; the broker itself for vsock).
  - [ ] Implement `HostCostV1Handler` reading from those accumulators
  - [ ] Verb `workload`; verb `tenant` returns `NotImplemented` until W4b
  - [ ] Tests: returns right shape, quota enforcement, denied in `BuilderOnly` profile, accumulator updates correctly under simulated CPU/RAM load
  - [ ] **Alternative if W4a's accumulator scope is too big:** defer the workload verb to W4b alongside cross-tenant and ship W4a as `NotImplemented` for *both* verbs. Decision: leave to implementer based on scope estimate at W4a start.
- [ ] **W4b — `host.cost.v1` cross-tenant via mvmd** *(depends on mvmd Plan 52 W1+W2+W3)*
  - [ ] Add `MvmdClient` trait + real impl over mvmd-agent's iroh ALPN transport (new `AgentRequest` variants — NOT a new HTTP route, NOT raw QUIC+mTLS)
  - [ ] Test-mode in-process `MvmdClient`
  - [ ] mvmd response schema validation (refuse if mvmd returns unexpected fields/types — see §Security S15)
  - [ ] Implement `host.cost.v1::tenant` verb
  - [ ] Per-tenant catalog intersection at admission (§A7)
  - [ ] Tests: positive aggregation against mock client, cross-tenant authz denial, mvmd-unavailable → `ServiceErrorCode::Unavailable` (no stale data), forged workload-id rejected, malformed mvmd response rejected, tenant catalog intersection refuses out-of-catalog binding
- [x] **W5 — `host.secrets.v1` inside the secrets-dispatcher subprocess** — **DELETED by ADR-062 (2026-05-28).** `host.secrets.v1` and `mvm-secrets-dispatcher` are dropped from v1 scope. The subprocess scaffold merged via PR #480 is removed in PR C of the rescope sequence. The seccomp + side-channel + latency-floor hardening rationale was secrets-specific; nothing of equivalent shape applies to the remaining (broker / host-signer / audit-signer) subprocesses, all of which already have their own hardening waves.
- [ ] **W3-audit — `host.audit.v1` (workload-emitted audit entries)** *(no mvmd dep; new in ADR-062)*
  - [ ] Define `EventCategory::WorkloadAudit` variant in `mvm-audit-signer`'s allowed-category list, distinct from `ServiceCall` / `Admission`
  - [ ] Implement `HostAuditV1Handler` in `crates/mvm-broker/src/handlers/host_audit.rs`
  - [ ] Verbs: `emit` (single entry) + `emit_batch` (≤100 entries, ≤256 KiB total per call)
  - [ ] Per-record cap: `BROKER_AUDIT_RECORD_BYTES = 4096`
  - [ ] Rate limit: token-bucket `BROKER_AUDIT_TOKENS_PER_SEC = 20` per workload (handler-specific, in addition to broker-wide)
  - [ ] `audit_durability() = PerCall` (fsync before response)
  - [ ] Handler dispatch forwards each entry to `AuditSignerProxy::append_entry` with `category = "workload_audit"`
  - [ ] Cross-workload attribution check: `category = WorkloadAudit` + `workload_id` matches `ctx.workload_id` (refuse with `ServiceErrorCode::BadRequest` if mismatched)
  - [ ] Tests: positive emit + chain-head advances, emit_batch up to cap, record-too-large rejected with `ServiceErrorCode::BadRequest`, batch-too-large rejected, rate-limit triggers `ServiceErrorCode::RateLimitExceeded`, workload-id mismatch refused, chain verifier displays `WorkloadAudit` category distinctly from `ServiceCall`
- [ ] **W6 — Fuzz + CI** *(no mvmd dep)*
  - [ ] Add `crates/mvm-guest/fuzz/fuzz_service_call.rs` per ADR-002 §W4.2
  - [ ] Wire into existing `cargo-fuzz` lane (≥5min/PR)
  - [ ] Add `xtask check-handler-adr-coverage` lint
  - [ ] Add `xtask check-handler-policy-schema` lint
  - [ ] Add `xtask check-handler-composition` lint
  - [ ] Add `xtask check-no-mutable-handler-state` lint (see §Security S14)
  - [ ] Confirm `prod-agent-no-exec` still passes
  - [ ] Cross-backend test matrix: broker handshake + at least one handler call on each of libkrun / Firecracker / Apple Container / vz
- [x] **W7 — ADR-049 §W3 SDK matrix** — **DELETED by ADR-062 (2026-05-28).** The per-language credential-substitution hook libraries (Python / TypeScript / Rust) are no longer needed: `host.secrets.v1` is dropped, no `mvm-secret://` placeholder exists, no SDK has anything to substitute. ADR-049's hostile-guest matrix is similarly moot.
- [ ] **W8 — Hardware-enclave host signer** *(largest new wave; security-gated review per H-L9.5; macOS-SE + Linux-TPM in parallel)*
  - [ ] macOS: Apple Secure Enclave integration in `crates/mvm-host-signer` via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` (P-256); Swift bridge
  - [ ] Linux: TPM 2.0 integration via `tpm2-tss` (RSA-2048 or ECDSA-P256 depending on TPM capability)
  - [ ] Algorithm-identifier byte enables P-256 (`0x02`) on the SE path
  - [ ] Fallback: kernel keyring (Linux) or filesystem mode 0600 (universal); only with `--insecure-host-signer-software-fallback` flag; surfaced in doctor as a downgrade
  - [ ] **Host signer key rotation ceremony** + **TPM monotonic counter for rollback resistance** (H-L2.2); rotation increments embed in admission audit entries
  - [ ] **`mvmctl host-key rotate`** CLI verb; emits `operator.host_key_rotation` audit entry; rotates through dedicated `mvmctl services revoke <workload>` flow for in-flight workloads
  - [ ] **At-rest audit encryption key migration** (H-L5.4) — the per-tenant audit-encryption key derived from TPM/SE-bound master
  - [ ] Doctor reports the active host-signer backend + downgrade state on a dedicated row
  - [ ] Tests: enclave keygen + sign + verify on macOS SE, Linux TPM round-trip on `tpm2-emulator` in CI, monotonic counter increments on rotation, fallback path explicitly downgraded in doctor, key migration from software → enclave under no-backcompat (re-sign all running plans or refuse-to-resume), side-channel audit re-run on enclave path
- [ ] **W9 — Supply chain + release hardening** *(no mvmd dep; spans CI workflow files)*
  - [ ] **Sigstore / Rekor transparency log entries** per subprocess release (H-L8.1)
  - [ ] **In-toto attestations** alongside SLSA provenance (H-L8.2) for each subprocess binary
  - [ ] **Hermetic, network-isolated build lane** for each subprocess binary inside the existing claim-9 sealed-volume pattern (H-L8.3)
  - [ ] **Per-subprocess reproducibility-double-build CI lane** (H-L3.10 extension); fails on byte-divergence
  - [ ] **CODEOWNERS + branch protection** for the four subprocess crates + `crates/mvm-supervisor/src/services/` + ADR-059 (H-L9.6)
  - [ ] **`xtask check-subprocess-fd-inheritance`** lint (H-L3.8) added to `xtask` workspace; CI gate
  - [ ] **`cargo-mutants` mutation-testing lane** (H-L9.2) targeting security-critical functions in the four subprocess crates + supervisor services module
  - [ ] **Crypto-crate pinning + `deny.toml` enforcement** (H-L11.2): `ed25519-dalek` v2.x, `serde_jcs` (exact version + RFC 8785 corpus test in CI), `chacha20poly1305` (RustCrypto), `tpm2-tss`, `subtle`
  - [ ] Tests: cosign-verify rejects an unsigned subprocess binary, Sigstore log entry retrievable for a release artifact, hermetic build lane refuses to compile with network access, mutation testing surfaces a regression on a known-bad mutation
- [ ] **W10 — Documentation + threat model** *(no mvmd dep; doc-only)*
  - [ ] `specs/threat-models/02-host-services-broker.md` (H-L10.1) — STRIDE per service (host.secrets.v1, host.time.v1, host.cost.v1, broker.v1); cross-VM threats (mvmd path) included
  - [ ] `SECURITY.md` updated with CVE response runbook (H-L10.2): reporting channel, SLA, coordinated disclosure policy
  - [ ] `docs/security/audit-fields.md` (H-L10.3 / H-L5.6) — PII invariant; allowed field types; audit entry schema reference
  - [ ] `docs/security/deployment-modes.md` (H-L11.3) — single-dev / CI / fleet threat differentiation
  - [ ] Operator runbook for subprocess crash investigation, audit chain verification, key rotation
  - [ ] CLAUDE.md security model section updated to reference Plan 104's new subprocesses and claim numbers
- [ ] **W11 — Operator FIDO ceremony full implementation** *(may slip to Sprint 58 follow-on if W1–W10 fills Sprint 57)*
  - [ ] Wire `fido_touch_required()` (stub from W1 / H-L11.6) into a real `webauthn-authenticator-rs` / platform-FIDO API path on `mvmctl up --prod`
  - [ ] Fallback for hosts without FIDO: operator-key-on-encrypted-USB (passphrase + key file); audited downgrade
  - [ ] Doctor probes FIDO availability + reports
  - [ ] `mvmctl host-key rotate` requires FIDO touch (consistency with W8 rotation ceremony)
  - [ ] Tests: FIDO touch happy-path on USB-touch fixture, fallback rejects without passphrase, doctor reports correct availability

## Critical files to create or modify

**New crates (four subprocesses + their UDS protocol):**
- `crates/mvm-broker/` — **NEW crate** (H-L1.3), binary `mvm-broker`, general-broker subprocess at uid 903; hosts `HostTimeV1Handler`, `HostCostV1Handler`, `BrokerV1Handler`; listens on vsock 5300 + per-VM UDS `~/.mvm/vms/<vm>/services/broker.sock`
- `crates/mvm-secrets-dispatcher/` — **NEW crate**, binary `mvm-secrets-dispatcher`, secrets subprocess at uid 902; hosts `HostSecretsV1Handler`; listens on vsock 5301 + per-VM UDS `~/.mvm/vms/<vm>/services/secrets.sock`
- `crates/mvm-host-signer/` — **NEW crate** (H-L1.1), binary `mvm-host-signer`, host-signer subprocess at uid 904; holds the host signer key (software in W1, HW-enclave in W8); listens on per-VM UDS `~/.mvm/vms/<vm>/services/host-signer.sock`
- `crates/mvm-audit-signer/` — **NEW crate** (H-L1.2), binary `mvm-audit-signer`, audit-signer subprocess at uid 905; sole writer to `~/.mvm/audit/<tenant>.jsonl`; sole holder of audit chain-signing key; listens on per-VM UDS `~/.mvm/vms/<vm>/services/audit-signer.sock`

**New supervisor-side proxy + glue:**
- `crates/mvm-supervisor/src/services/{mod.rs, registry.rs, broker_proxy.rs, secrets_proxy.rs, host_signer_proxy.rs, audit_signer_proxy.rs, mvmd_client.rs, circuit_breaker.rs, quota.rs}` — UDS clients + subprocess lifecycle; supervisor no longer hosts in-process handlers or holds keys

**New guest + SDK + tooling:**
- `crates/mvm-guest/src/services.rs`
- `crates/mvm-sdk/src/services/{mod.rs, client.rs, host_secrets.rs, host_time.rs, host_cost.rs}`
- `crates/mvm-guest/fuzz/fuzz_service_call.rs`
- `crates/mvm-cli/src/commands/services.rs` (see §C2)
- `crates/mvm-cli/src/commands/host_key.rs` — `mvmctl host-key rotate` (W8)
- `crates/xtask/src/check_subprocess_fd_inheritance.rs` (H-L3.8)
- `specs/adrs/059-host-services-broker.md`
- `specs/threat-models/02-host-services-broker.md` (H-L10.1)
- `docs/security/audit-fields.md`, `docs/security/deployment-modes.md`

**Modify:**
- `crates/mvm-plan/src/plan.rs` — `services`, `ServiceBinding`, `ServicePolicy`, `ServiceQuotas` types; **`SCHEMA_VERSION` 4→5**
- `crates/mvm-plan/src/plan_builder.rs:216` — synthesize binding set instead of `Vec::new()`; admission ceremony now calls `mvm-host-signer` over UDS for plan signing (H-L1.1) — supervisor never reads the host signer key directly
- `crates/mvm-core/src/protocol.rs` (or new `crates/mvm-core/src/broker_protocol.rs`) — `ServiceCall`, `ServiceResponse`, `ServiceId`, `ServiceErrorCode` shared by all subprocesses
- `crates/mvm-core/src/signing.rs` — **algorithm-identifier byte in `AuthenticatedFrame`** (H-L4.1)
- `crates/mvm-supervisor/src/audit_recorder.rs` — refactor: supervisor *enqueues* typed audit entries to `mvm-audit-signer` over UDS; subprocess holds the chain-signing key and is the only writer (H-L1.2)
- `crates/mvm-guest/src/vsock.rs` — `GuestCapability::ServicesBroker`, port 5300, `ProtocolHello` capability; **remove** `HostBoundRequest::QueryHostTime` (W3)
- `crates/mvm-supervisor/src/keystore.rs` — **delete** in W5
- `crates/mvm-supervisor/src/host_signer.rs` — **delete** the in-process signing path in W2 (moves to `mvm-host-signer` subprocess); supervisor retains only the `host_signer_proxy.rs` UDS client
- `crates/mvm-supervisor/src/lib.rs` — `pub mod services;`
- `crates/mvm-libkrun/src/bin/mvm-libkrun-supervisor.rs` — spawn + supervise the four subprocesses with cosign-verify (H-L3.1), TOCTOU-resistant exec (H-L3.2), config-signing (H-L3.6), per-workload cgroup setup (H-L1.4), resource caps (H-L3.9), CPU pinning (H-L7.4); start listener tasks for both vsock ports
- `crates/mvm-supervisor/src/supervisor.rs` and the Firecracker dispatch path in `crates/mvm/src/vm/` — Firecracker uses the in-process `Supervisor` struct; the four subprocesses are spawned by that struct's lifecycle (same pattern as libkrun)
- `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/` — **new Swift listener class** (`VZVirtioSocketListener` + `shouldAcceptNewConnection`); host-side UDS relay to the four Rust subprocesses. The existing `VsockProxy.swift` is host-as-client only and doesn't cover this
- Apple Container backend entry — host-as-listener path parallel to libkrun's
- `crates/mvm-supervisor/src/cost.rs` (NEW) — per-workload cost accumulators built in W4a (does not exist today)
- `crates/mvm-cli/src/doctor.rs` — new posture checks: KASLR / KPTI / SMEP-SMAP / Spectre-v2 / LSM / `unprivileged_userns_clone` / `dmesg_restrict` / macOS SIP+AMFI+kext (H-L7.2); KSM + THP off (H-L7.1); FIDO availability (W11); CPU spare-core (H-L7.4); host-signer backend + downgrade (W8)
- `.github/workflows/ci.yml` — fuzz lane + cross-backend test matrix lane + mutation testing (H-L9.2) + per-subprocess reproducibility lane (H-L3.10/H-L8.3) + Sigstore/Rekor lane (H-L8.1) + in-toto attestation lane (H-L8.2) + hermetic-build lane (H-L8.3) + RFC-8785 JCS conformance lane (H-L11.2) + `checksec` lane (H-L3.10)
- `.github/CODEOWNERS` — entries for the four subprocess crates + supervisor services module + ADR-059 (H-L9.6)
- `deny.toml` — pin `ed25519-dalek`, `serde_jcs`, `chacha20poly1305`, `tpm2-tss`, `subtle` with allowlist for advisory/license (H-L11.2)
- `crates/mvm-broker/Cargo.toml` — `service-*` feature flags (moved from supervisor)
- `crates/mvm-cli/src/main.rs` — `fido_touch_required()` stub for `mvmctl up --prod` (W1 stub; W11 full impl)
- `CLAUDE.md` security model section — update to reference the four subprocesses + the narrowed "malicious host" clause (W10)
- `SECURITY.md` — CVE response runbook (W10)
- `specs/adrs/002-microvm-security-posture.md` — cross-reference ADR-059's narrowing of the "malicious host" clause; add Plan 104's two new claim numbers when assigned at write time

**Update or supersede:**
- `specs/adrs/049-secret-substitution-mechanism.md` — one-line "Implementation: lands as `host.secrets.v1` in the host services broker (ADR-059, Plan 104)." No semantic change.
- `specs/plans/74-claim-safe-sandbox-parity.md` §W3 — redirect to Plan 104 W5+W7.

### Subprocess lifecycle details

The same lifecycle pattern applies uniformly to all four subprocesses
(`mvm-broker`, `mvm-secrets-dispatcher`, `mvm-host-signer`,
`mvm-audit-signer`) per §Hardening posture L1. Only the binary name,
uid, allowed-bindings set, and listening UDS path differ. References
to "secrets dispatcher" below illustrate the pattern; substitute the
appropriate subprocess for the other three. Audit-relevant subprocess
events (`broker.subprocess.crashed_repeatedly`,
`audit_signer.subprocess.crashed_repeatedly`, etc.) follow the same
naming convention.

- **Spawn:** at VM admission, the supervisor's `admit_for_run`
  ceremony spawns each subprocess via `std::process::Command` with
  stdin piped for initial config exchange (signed config envelope
  per H-L3.6), then drops stdin once the subprocess is listening on
  its UDS. Cosign verification (H-L3.1) + TOCTOU-resistant exec
  (H-L3.2) precede every spawn.
- **Configuration:** supervisor passes via stdin a signed JSON
  config (host signer public-key location, audit-back-channel UDS
  path, vsock port assignment, agent profile, allowed bindings from
  the workload's `ExecutionPlan.services`). After consume, stdin
  closes.
- **Audit back-channel:** subprocesses other than `mvm-audit-signer`
  write audit subentries to a supervisor-owned UDS; the supervisor
  forwards them to `mvm-audit-signer`, which JCS-canonicalizes,
  computes `prev_hash`, signs with the audit chain-signing key, and
  appends to `~/.mvm/audit/<tenant>.jsonl`. No subprocess other than
  `mvm-audit-signer` holds the audit chain-signing key.
- **Inheritance:** each subprocess's parent is the supervisor;
  `PR_SET_PDEATHSIG(SIGTERM)` on Linux ensures the subprocess dies
  if the supervisor dies. macOS equivalent: a kqueue-monitored
  parent-pid watcher (or libdispatch's
  `dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, …)` watching
  the supervisor's PID).
- **Restart policy:** if any subprocess crashes, supervisor restarts
  it with exponential backoff (100ms, 500ms, 2s). After 3 restarts
  within the workload's lifetime, supervisor stops restarting,
  audits `<subprocess>.crashed_repeatedly`, and triggers a workload
  pause via Plan 82's harness. The workload sees `Err(Unavailable)`
  for the affected service's calls until resumed (which only
  happens after operator review).
- **In-flight call handling on crash:** outstanding correlation IDs
  return `Err(Unavailable)`. New session keys minted post-restart;
  old sessions invalidated (consistent with S8 pause/resume
  semantics).

## Reuse — existing pieces this plan leans on

- `AuthenticatedFrame` framing in `crates/mvm-guest/src/vsock.rs` — reused unchanged.
- `Recorder` trait + chain-signed JSONL audit — reused; one new `EventCategory` variant.
- `AgentProfile` enum — reused as the first capability gate.
- `ProtocolHello` capability negotiation (ADR-053) — reused.
- Per-VM supervisor process model — reused; broker is a task inside it.
- `ExecutionPlan.secrets: Vec<SecretBinding>` and `SecretReleasePolicy` — reused as policy blob for `host.secrets.v1`.
- Supervisor's per-workload cost accumulators — reused by `host.cost.v1`.

## Verification

**Per-wave smoke:**
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace -- -D warnings`

**End-to-end smoke (after W5):**
- [ ] `cargo run -- up --plan examples/secrets-broker/plan.json` — sealed-prod workload calls `host.secrets.v1`; supervisor audits.
- [ ] `cargo run -- audit verify` — chain integrity green including new `ServiceCall` entries.

**Security regression set (must pass on every PR after the respective wave):**
- [ ] `service_call_denied_when_unbound` (W2)
- [ ] `service_call_denied_outside_profile` (W2)
- [ ] `service_call_replay_rejected` (W1)
- [ ] `service_call_session_after_stop_rejected` (W2)
- [ ] `service_call_rate_limit_enforced` (W2)
- [ ] `service_call_lifetime_quota_exhausted` (W2)
- [ ] `service_call_response_size_cap_enforced` (W2)  ← S11
- [ ] `service_call_amplification_attack_refused` (W2)  ← S11
- [ ] `broker_cpu_budget_enforced` (W2)
- [ ] `broker_memory_cap_enforced` (W2)
- [ ] `broker_queue_full_returns_error` (W1)  ← S21
- [ ] `circuit_breaker_opens_after_failures` (W2)  ← S13
- [ ] `circuit_breaker_half_open_recovery` (W2)  ← S13
- [ ] `handler_panic_does_not_kill_supervisor` (W2)
- [ ] `handler_inter_call_memory_hygiene` (W5)  ← S14
- [ ] `handler_call_timeout_enforced` (W2)  ← C4
- [ ] `handler_idempotency_contract_per_handler` (W3/W4a/W5)  ← C3
- [ ] `broker_pause_resume_invalidates_old_session` (W2, Plan 82 harness)
- [ ] `audit_chain_contains_service_call_entries` (W2)
- [ ] `audit_chain_carries_no_payload_bytes` (W2)
- [ ] `host_secrets_v1_denied_outside_allowed_destinations` (W5)
- [ ] `zeroize_drop_zeros_secret_bytes` (W5)
- [ ] `cross_tenant_query_refused` (W4b)
- [ ] `forged_workload_id_refused` (W4b)
- [ ] `malformed_mvmd_response_rejected` (W4b)  ← S15
- [ ] `confused_deputy_via_mvmd_field_injection_refused` (W4b)  ← S15
- [ ] `bootstrap_order_returns_not_ready` (W1)  ← S16
- [ ] `cross_backend_broker_matrix_libkrun_fc_apple_vz` (W6)  ← S17
- [ ] `json_type_confusion_returns_bad_request_not_panic` (W2)  ← S19
- [ ] `composition_depth_cap_enforced` (W1)
- [ ] `addon_proxy_stub_round_trip` (W1; v2-ready substrate)
- [ ] `hostile_guest_raw_socket_bypass` (W7)
- [ ] `audit_entry_enqueued_before_response_returned` (W2)  ← S22
- [ ] `audit_batch_survives_supervisor_crash_mid_window` (W2)  ← S22
- [ ] `mvmd_unsigned_catalog_rejected` (W4b)  ← S23
- [ ] `mvmd_wrong_key_signed_catalog_rejected` (W4b)  ← S23
- [ ] `composed_secret_does_not_leak_via_composer_response` (W6 lint + W5 runtime)  ← S24
- [ ] `placeholder_in_outbound_request_dropped_and_audited` (W7 + gvproxy/passt)  ← S25
- [ ] `host_secrets_v1_latency_floor_holds_warm_and_cold` (W5)  ← S26
- [ ] `service_session_revoked_refuses_further_calls` (W2 + C2 CLI)  ← S27
- [ ] `host_secrets_v1_signed_payload_jcs_roundtrip` (W5)  ← S28
- [ ] `secrets_subprocess_crash_isolation` (W1)  ← T4 (subprocess crash → supervisor survives, workload sees Unavailable)
- [ ] `secrets_subprocess_cannot_reach_supervisor_memory` (W1)  ← T4 (process isolation invariant)
- [ ] `supervisor_crash_subprocess_exits_via_pdeathsig` (W1)  ← T4 (lifecycle)
- [ ] `secrets_subprocess_uid_902_seccomp_setpriv_enforced` (W5)  ← T4 (privilege confinement)
- [ ] Fuzz lane: `fuzz_service_call.rs` ≥5min/PR (W6)

**Hardening-layer regression set (Layers 1–11; gates per the
respective wave):**
- [ ] `host_signer_subprocess_uid_904_isolated` (W1)  ← H-L1.1
- [ ] `audit_signer_subprocess_uid_905_sole_writer` (W1)  ← H-L1.2
- [ ] `broker_subprocess_uid_903_isolated` (W1)  ← H-L1.3
- [ ] `per_workload_cgroup_namespace_enforced` (W1)  ← H-L1.4
- [ ] `host_signer_enclave_keygen_macos_se` (W8)  ← H-L2.1
- [ ] `host_signer_enclave_keygen_linux_tpm` (W8)  ← H-L2.1
- [ ] `host_signer_rotation_monotonic_counter_advances` (W8)  ← H-L2.2
- [ ] `host_signer_rollback_attack_refused_via_counter` (W8)  ← H-L2.2
- [ ] `cosign_verify_rejects_tampered_subprocess_binary` (W1)  ← H-L3.1
- [ ] `verify_then_exec_toctou_window_closed` (W1)  ← H-L3.2
- [ ] `seccomp_policy_denies_process_vm_readv_etc` (W5)  ← H-L3.3
- [ ] `macos_sandbox_profile_denies_unauth_fd_access` (W1)  ← H-L3.4
- [ ] `seccomp_per_arch_x86_64_aarch64_match` (W6)  ← H-L3.5
- [ ] `config_signing_rejects_tampered_subprocess_config` (W1)  ← H-L3.6
- [ ] `secrets_proxy_buffers_zeroized_on_drop` (W1)  ← H-L3.7
- [ ] `xtask_check_subprocess_fd_inheritance` (W9)  ← H-L3.8
- [ ] `subprocess_rlimit_core_zero_enforced` (W1)  ← H-L3.9
- [ ] `subprocess_rlimit_as_enforced` (W1)  ← H-L3.9
- [ ] `subprocess_mlock_secret_pages_present` (W5)  ← H-L3.9
- [ ] `subprocess_pr_set_dumpable_zero_or_pt_deny_attach` (W1)  ← H-L3.9
- [ ] `subprocess_checksec_pie_relro_canaries_fortify` (W9)  ← H-L3.10
- [ ] `subprocess_reproducibility_double_build_byte_identical` (W9)  ← H-L3.10
- [ ] `subprocess_static_linked_no_dlopen` (W1)  ← H-L3.11
- [ ] `subprocess_w_xor_x_after_init` (W1)  ← H-L3.11
- [ ] `subprocess_anti_debug_refuses_under_ptrace` (W1)  ← H-L3.11
- [ ] `authenticated_frame_alg_id_byte_roundtrip` (W1)  ← H-L4.1
- [ ] `subprocess_response_signature_verified_by_supervisor` (W1)  ← H-L4.2
- [ ] `stub_subprocess_wrong_signature_response_rejected` (W6)  ← H-L4.2 / H-L9.1
- [ ] `session_key_rotated_after_n_calls` (W2)  ← H-L4.3
- [ ] `session_key_rotated_after_m_ms` (W2)  ← H-L4.3
- [ ] `mvmd_tls_pinned_to_tls_1_3_chacha_x25519` (W4b)  ← H-L4.4
- [ ] `constant_time_session_id_comparison` (W1)  ← H-L4.5
- [ ] `constant_time_correlation_id_comparison` (W1)  ← H-L4.5
- [ ] `constant_time_destination_url_match` (W5)  ← H-L4.5
- [ ] `supervisor_assigned_correlation_ids_rewrite_workload_input` (W1)  ← H-L4.6 / G4
- [ ] `audit_chain_fd_is_o_append_only` (W2)  ← H-L5.1
- [ ] `audit_chain_dir_immutable_chattr_a_or_uf_append` (W2)  ← H-L5.1
- [ ] `chain_head_persisted_to_secondary_location` (W2)  ← H-L5.2
- [ ] `worm_audit_volume_append_only_enforced` (W2)  ← H-L5.3
- [ ] `audit_log_encryption_at_rest_per_tenant_aead_roundtrip` (W2)  ← H-L5.4
- [ ] `audit_log_encryption_key_derived_from_tpm_se_master` (W8)  ← H-L5.4
- [ ] `clock_jump_backward_detected_and_audited` (W2)  ← H-L5.5
- [ ] `correlation_id_contains_no_pii_lint` (W2)  ← H-L5.6
- [ ] `admission_blocks_until_four_subprocesses_healthy` (W1)  ← H-L5.7 / G3
- [ ] `operator_action_audit_entry_emitted_for_each_privileged_cli` (W2)  ← H-L6.1
- [ ] `audit_chain_rotation_continuity_prev_hash_match` (W2)  ← H-L6.2
- [ ] `tenant_secret_quota_enforced_across_workloads` (W4b)  ← H-L6.3
- [ ] `mvmd_identity_pin_missing_refuses_admission` (W4b)  ← H-L6.4
- [ ] `composition_width_cap_enforced` (W1)  ← H-L6.5
- [ ] `audit_fsync_failure_triggers_workload_pause` (W2)  ← H-L6.6
- [ ] `doctor_refuses_admission_on_ksm_or_thp_enabled` (W1)  ← H-L7.1
- [ ] `doctor_refuses_admission_on_weak_kernel_posture` (W1)  ← H-L7.2
- [ ] `subprocess_slow_start_refuses_workload` (W1)  ← H-L7.3
- [ ] `cpu_pinning_separates_subprocesses_from_supervisor_core` (W1)  ← H-L7.4
- [ ] `sigstore_rekor_log_entry_present_for_subprocess_release` (W9)  ← H-L8.1
- [ ] `in_toto_attestation_present_alongside_slsa` (W9)  ← H-L8.2
- [ ] `hermetic_build_lane_refuses_network_access` (W9)  ← H-L8.3
- [ ] `hostile_subprocess_test_each_kind_rejected` (W6)  ← H-L9.1
- [ ] `cargo_mutants_no_security_function_escapes` (W9)  ← H-L9.2
- [ ] `fuzz_uds_proxy_read_loop` (W6)  ← H-L9.3
- [ ] `side_channel_timing_audit_dudect_passes` (W5/W8)  ← H-L9.4
- [ ] `codeowners_require_security_reviewer_on_subprocess_crates` (W9)  ← H-L9.5 / H-L9.6
- [ ] `snapshot_restore_respawns_subprocesses_fresh_keys` (W1)  ← H-L11.1 / G6
- [ ] `crypto_crate_pinning_deny_toml_enforced` (W9)  ← H-L11.2 / G7
- [ ] `serde_jcs_rfc8785_conformance_corpus_passes` (W9)  ← H-L11.2
- [ ] `deployment_mode_doctor_row_correct` (W1)  ← H-L11.3 / G8
- [ ] `doctor_refuses_admission_on_known_vsock_cve_version` (W1)  ← H-L11.4 / G9
- [ ] `host_signer_software_fallback_doctor_downgrade_row` (W1)  ← H-L11.5 / G5
- [ ] `fido_touch_required_stub_audits_unverified` (W1)  ← H-L11.6 / G2 stub
- [ ] `fido_touch_required_full_enforcement` (W11)  ← G2 full

**Manual falsifiability check (post-W7):**
- [ ] Add a fourth service `host.dev.echo.v1` in a throwaway branch. Single new handler file + one registry line + `ServiceBinding` entry. If it requires touching the envelope, registry, or auth path, the design failed and v1 needs redesign before the host-logging follow-up plan starts.
- [ ] (Bonus) Wire a *stub* out-of-process addon at `~/.mvm/services/dev.echo.v1/` with a static manifest, verify the broker's addon-proxy path round-trips a call. Confirms A4 substrate is real.

## Decisions (resolving the earlier open questions)

1. **Cross-VM in scope; mvm broker delegates to mvmd over iroh ALPN.** Per-VM data stays in the supervisor handler. Cross-VM data via mvmd-agent's existing iroh transport with new `AgentRequest` variants. mvmd-side work: Plan 52 + ADR-0023.
2. **Encoding: JSON via `serde_json`** (DECIDED 2026-05-26, T3). Switched from CBOR. v1 has no genuinely binary payload; SDK-matrix friction + `jq` debuggability + consistency with existing JSON channels (`GuestRequest`, `HostBoundRequest`) win. Signed payloads use JCS (RFC 8785) for canonical bytes.
3. **`broker.v1/list_services` exposed.** Workloads enumerate bound services + verbs + deprecation flags at runtime.
4. **`host.secrets.v1` runs in a dedicated subprocess** (DECIDED 2026-05-26, T4 — production-ready isolation). Separate binary `mvm-secrets-dispatcher` at uid 902, seccomp `standard`, setpriv; UDS-only access to the supervisor. Industry pattern (AWS STS, HashiCorp Vault, Kubernetes ServiceAccount token controllers).
5. **The out-of-process handler substrate ships in v1 with secrets as its first consumer** (DECIDED 2026-05-26, T5). v2 third-party addons reuse the same substrate; no protocol change needed when they land.

## Comparison: SDK-hook vsock vs TLS-terminating proxy (ADR-049 alternatives)

ADR-049 considered two architectural shapes for secret substitution; Plan 104 implements the chosen default and adds a backstop from the alternative.

**(a) Host-side TLS-terminating proxy with injected CA** — a host-issued CA is installed in the guest's trust store; the proxy terminates TLS, injects credentials in plaintext, re-encrypts upstream. Simpler integration (no SDK matrix, library bypass is impossible since the proxy intercepts at L4/L7 regardless of what the guest does). The trade is significant: it **expands the host's trust boundary into the guest's trust store** — a CA the host controls is now trusted by the guest's TLS stack for *all* outbound connections, not just secret-bearing ones.

**(b) Vsock substitution via SDK hook** *(the default mvm chose)* — the SDK hooks the HTTP client *before* TLS, asks the host for a destination-bound signed credential, injects it into the outbound request, and the guest does its own TLS to upstream. **The guest's trust store is untouched.** Protocol-agnostic (HTTP/1.1, HTTP/2, HTTP/3, gRPC, mTLS). Cost: per-language hook matrix (ADR-049 §W3, Plan 104 W7) — Python `requests`/`httpx`/`aiohttp`, TypeScript `fetch`/`axios`, Rust `reqwest`/`hyper`.

ADR-049 chose (b) as default because preserving the guest's trust boundary outweighed the SDK-matrix cost. (a) ships separately as the `unsafe_guest_tls_inspection` opt-in for workloads that can't be modified (vendored binaries, third-party agents).

**Plan 104 takes the strongest property of each:** (b) is the primary path; **S25 adds the network-layer enforcement property from (a) as a fallback** — gvproxy/passt detects `mvm-secret://` token pattern in outbound HTTP bytes and drops the frame, emitting `secret.substitute.bypass_detected`. If an attacker substitutes the SDK with a malicious version that strips substitution hooks, S25 catches the unsubstituted placeholder at the L4/L7 boundary before it leaves the host. Combined: ADR-049 (b)'s untouched trust store *and* a library-bypass-resistant backstop.

## Security considerations and new surfaces

The broker is a new attack surface. Five independent gates protect every call (§"Capability gating"). Per-surface mitigations follow.

**S1 — JSON parser as TCB code.** `serde_json` (already in-tree, used by existing `GuestRequest` / `HostBoundRequest` channels — well-fuzzed). Knobs: `BROKER_MAX_FRAME_BYTES=65536`, `BROKER_MAX_DEPTH=8`, `BROKER_PARSE_TIMEOUT_MS=50`. Failure mode: supervisor dies → workload torn down → audit shows broker died mid-call → no exfil. The secrets subprocess uses its own `serde_json` instance — a parser bug exploited in the general broker doesn't pivot to the secrets subprocess's memory.

**S2 — Capability creep.** CI lint `xtask check-handler-adr-coverage`; static catalog at admission (no runtime registration in v1); every new verb requires fuzz-corpus seed.

**S3 — Timing / call-rate covert channels.** Rate limit applies to read-only services too; per-workload total-call/minute budget escalates to `ServiceCallAbuse` audit + (optional) workload pause via Plan 82.

**S4 — Cross-tenant information leakage.** mvmd's tenant-scoped-authz refuses any `tenant_id ≠ workload.tenant_id`. Workload-id signed by mvmd, unforgeable. Audit on both sides correlatable by `correlation_id`.

**S5 — Supervisor blast radius (revised: secrets isolated by process boundary).** The general broker (port 5300) runs in the supervisor; `host.secrets.v1` runs in the **secrets subprocess** with no shared address space. A use-after-free / integer overflow / logic bug in the general broker's schema/auth/binding/quota code cannot reach the credential-minting code, the in-flight grant table, or the keystore policy state. `zeroize::Zeroize` on secret-bearing types in the dispatcher. Subprocess crashes don't kill the supervisor; the supervisor returns `Err(Unavailable)` and restarts the subprocess (max 3 times per workload, then workload pause). v2 third-party addons reuse the same subprocess pattern.

**S6 — DoS / resource exhaustion.** Rate limit + size cap + per-workload broker-CPU budget (`BROKER_CPU_BUDGET_MS_PER_MIN=50`) + memory cap (`BROKER_INFLIGHT_MEM_CAP_BYTES=1048576`).

**S7 — Replay across workloads.** Session id minted at plan admission (128-bit ULID), monotonic sequence enforced; session id recorded in audit as `service.session.ended` at workload stop.

**S8 — Pause/resume + snapshot.** On pause, broker flushes in-flight (`Throttled` to outstanding), refuses new until resume. Resume mints fresh session — old correlation IDs invalidated.

**S9 — Logging vs redaction discipline.** `Recorder::record_service_call` API takes typed fields only — no payload-string param. Secret types must impl `RedactedDebug`, not `Debug`. CI sentinel-grep fixture.

**S10 — Out-of-process handler TCB scope.** v1 ships the out-of-process substrate with the **secrets dispatcher as its first consumer** (uid 902, seccomp `standard`, setpriv, UDS-only access). The substrate code lives in the supervisor TCB; the dispatcher binary (`crates/mvm-secrets-dispatcher/`) is a new line of TCB code — minimal, single-responsibility, dedicated security review per the no-`do_exec` discipline. v2 third-party addons reuse the same subprocess pattern; addon binaries are signed under claim-9 deps-audit pipeline at admission.

**S11 — Response-size amplification.** A small `ServiceCall` could trigger a large `ServiceResponse` (e.g., `broker.v1/list_services` for a workload with 50 bindings). Mitigation: per-handler `response_size_cap()` (default 64 KiB); if exceeded → `Err(ResponseTooLarge)` + audited. Knob: `BROKER_RESPONSE_CAP_DEFAULT_BYTES=65536`.

**S12 — Cumulative lifetime quota per workload.** Token-bucket covers per-window load; lifetime quota covers total budget. `ServiceQuotas { lifetime_calls: u64, lifetime_bytes_out: u64 }` per `ServiceBinding`. Exceeded → `Err(LifetimeQuotaExhausted)` + audited; workload may pause (Plan 82) or be hard-refused per its plan policy. Lifetime quotas survive pause/resume (carried in workload state).

**S13 — Circuit breaker for unhealthy handlers.** A handler that fails N consecutive calls (e.g., mvmd is down for `host.cost.v1::tenant`) opens a circuit breaker for that handler; subsequent calls return `Err(Unavailable)` immediately without dispatch. Half-open recovery after a backoff. Prevents both (a) wasting supervisor CPU on repeated-fail handlers and (b) timing-amplification attacks (slow-fail handlers leaking timing info). Knobs: `BROKER_CB_FAIL_THRESHOLD=5`, `BROKER_CB_HALF_OPEN_AFTER_MS=10000`.

**S14 — Inter-call memory hygiene.** A handler must not leak material from call N to call N+1 (e.g., a left-over key in `Arc<Mutex<_>>`). Mitigation: `ServiceHandler::dispatch` constructs fresh per-call state; any handler-internal cache uses `zeroize::Zeroizing<…>` wrappers. CI lint `xtask check-no-mutable-handler-state` scans handler modules for `Mutex<T> where T: !Zeroize`, fails build on findings (with allowlist for known-safe caches).

**S15 — Confused-deputy via mvmd response injection.** Cross-VM handlers call mvmd and use the response to make decisions. A compromised mvmd could inject fields the broker uses as authority signals. Mitigation: mvmd responses parsed with `deny_unknown_fields`; any field used in a decision path is typed strictly; the broker never reads "trust signals" from mvmd response payloads — only the decision (allow/deny) is consumed, and mvmd is the authz authority by design.

**S16 — Bootstrap-order failure mode.** A workload boots faster than the broker listener. Mitigation: broker listens *before* the guest process is spawned; if a workload reaches the broker port before fully initialized, broker returns `Err(NotReady)` (not crash, not silent drop).

**S17 — Cross-backend behavioral parity.** Broker must behave identically on libkrun (macOS), Firecracker (Linux), Apple Container (macOS), and vz (Apple Silicon, Sprint 55). Vsock semantics differ subtly. Mitigation: cross-backend test matrix in CI exercising the broker handshake + at least one handler call on each backend. Failure: backend-specific shims rather than divergent behavior.

**S18 — Audit log size and rotation (carried, decided in the host-logging follow-up plan).** Once `host.audit.v1` ships (the host-logging follow-up plan), workloads can write to the chain — the chain can grow unboundedly. Rotation strategy is the host-logging follow-up plan's responsibility, but Plan 104's `ServiceCall` entries are short and bounded (~200 B each), so Plan 104 doesn't worsen the problem materially.

**S19 — JSON `Value` type confusion.** The envelope's `payload: serde_json::Value` is dynamically typed; a handler expecting an int could receive a string. JSON is less prone than CBOR to numeric ambiguity (no int-vs-float distinction issue) but still requires typed parsing. Mitigation: per-handler `parse_policy` and `parse_payload` methods use typed `serde` deserialization with `deny_unknown_fields`; type mismatch → `Err(BadRequest)` not panic.

**S20 — Session key handling on host signer rotation (minor).** If the host signer key rotates mid-workload, existing workload session keys (minted from admission ceremony) keep working — they're independent. Documented; no code change required.

**S21 — Vsock back-pressure as covert channel.** If the guest queues `ServiceCall`s faster than the broker drains, queue depth itself encodes a signal. Mitigation: bounded vsock receive queue per workload (default 16) with explicit drop policy — over → `Err(QueueFull)` immediate, no blocking. Knob: `BROKER_QUEUE_DEPTH=16`.

**S22 — Audit batch durability window (BLOCKING).** `audit_durability = Batched(100ms)` (§Efficiency posture) means a supervisor crash within the batch window loses the audit entry for any call admitted in that window. A crafted payload (or a panicking handler) inside the window leaves no forensic trace.
- Mitigation: the audit *enqueue* must precede the caller response — batching applies only to `fsync`, not to in-memory queue insertion. The `Recorder` API takes the entry synchronously before `dispatch` returns; the batch flusher fsyncs to disk on a 100ms timer.
- Test: `audit_entry_enqueued_before_response_returned` — synthesize a call, observe enqueue order vs response; kill the supervisor mid-batch, restart, assert the chain contains the entry.

**S23 — Tenant catalog must be mvmd-signed (BLOCKING).** Per §A7, the per-VM supervisor pulls the tenant catalog from mvmd-agent and intersects it with the workload's bindings. A compromised mvmd-agent (or a MITM in the iroh transport, even with mTLS) could return a wider catalog than the tenant is entitled to, and the supervisor would chain-sign the bogus intersection.
- Mitigation: the catalog response carries an mvmd-fleet-credential-signed envelope (the same ADR-0023 §Trust model signature mvmd uses on tenant authorization). The supervisor verifies the signature against a pinned mvmd public key before trusting the catalog payload. Without this, ADR-0023's "tenant-scoped authz lives in mvmd" claim is weaker than advertised.
- Test: `mvmd_unsigned_catalog_rejected` — fixture mvmd returns an unsigned (or wrong-key-signed) catalog; supervisor refuses admission with audit `service.catalog.signature_invalid`.

**S24 — Privileged composition can leak secrets (BLOCKING).** §A5 allows a handler to invoke `host.secrets.v1` via `ServiceCallContext::invoke`. Claim 13 covers raw-secret leakage *through* `host.secrets.v1`'s response, but a composing handler (e.g., `host.config.v1` fetching a credential to call mvmd) could inadvertently include the composed credential in its *own* outbound `ServiceResponse`. Bug-in-composer = secret-leak-via-composer.
- Mitigation: handlers declaring `composes_with([host.secrets.v1])` are statically constrained — the composing handler's return type may not embed `serde_json::Value` borrowed from the composed result. The new `xtask check-handler-composition` (already in W6) extends to lint this: any handler that calls `ctx.invoke("host.secrets.v1", …)` and whose response payload contains a field assigned from the invoke result fails the build. A whitelist (`#[allow(secret_passthrough)]` on the specific field) is available with mandatory review.
- Test: `composed_secret_does_not_leak_via_composer_response` — fixture composer handler attempts to embed the secret; lint fails the build (positive); whitelisted path tested separately.

**S25 — SDK integrity / placeholder egress backstop (BLOCKING).** ADR-049 §"Opt-out by raw socket" notes that a guest ignoring `mvm-sdk-runtime` can call `socket(2)` directly. The deeper risk: if an attacker substitutes the deps volume with a malicious SDK that *appears* to be `mvm-sdk-runtime` but silently strips substitution hooks, `mvm-secret://01H…` placeholders egress *as-is* to the destination. The destination sees a useless string, but the workload's tracking that a credential "left the workload" is broken — and any logging at the destination now contains the placeholder string.
- Mitigation: the host-side egress proxy (gvproxy on macOS, passt on Linux) detects the `mvm-secret://` token pattern in outbound HTTP request bytes (URI, headers, body — at the point flow-audit already inspects per Plan 101) and **drops the frame**, emitting `secret.substitute.bypass_detected` to the audit chain. This is a backstop at the L7 boundary; the SDK is best-effort. Claim 9 (signed deps volume + CVE scan) is the primary defense; this is the belt for the suspenders.
- Test: `placeholder_in_outbound_request_dropped_and_audited` — guest sends a raw HTTP request containing the placeholder; egress proxy drops; audit chain shows the bypass detection.

**S26 — First-call cold-cache timing oracle on `host.secrets.v1`.** Per §C3, `host.secrets.v1` is `Idempotency::MintFresh` — but the first call to a given grant must perform lookup + verify + mint, while subsequent calls hit a warmer code path. A workload can use first-call latency relative to subsequent-call latency as an oracle on grant presence or system state.
- Mitigation: `host.secrets.v1` pads response latency to a fixed floor (default 5ms) regardless of cache state. The audit-write latency for the `PerCall` durability is included in the floor budget.
- Knob: `BROKER_SECRETS_LATENCY_FLOOR_MS=5`. Test: `host_secrets_v1_latency_floor_holds_warm_and_cold`.

**S27 — Signed-plan revocation: no in-session invalidation when host signer key is rotated for cause.** S20 covers the cryptographic-independence case (rotation doesn't break in-flight sessions). S27 covers the *intentional* revocation case: operator rotates the key specifically because a plan was compromised; the workload is still running and the broker continues serving it.
- Mitigation: new `mvmctl services revoke <workload>` operation (extends §C2 CLI) flushes the workload's broker session, emits `service.session.revoked { reason }` to the audit chain, and refuses further calls. Distinct from workload stop (which tears down the whole VM). Available via mvmd-agent for fleet operators (extends mvmd Plan 52 catalog endpoint with a revocation action).
- Test: `service_session_revoked_refuses_further_calls`.

**S28 — JSON canonical encoding for signed credential payloads.** Signed credentials returned by `host.secrets.v1` are JSON. JSON is not canonically encoded by default — key ordering, whitespace, and Unicode normalization can all vary. If the signed payload is re-serialized between sign and verify, the signature could fail (or, worse, a different encoding could pass).
- Mitigation: signed payloads use **JCS (JSON Canonicalization Scheme, RFC 8785)** for the bytes-to-sign. Sorted keys, no whitespace, defined number serialization, NFC Unicode. Specified in ADR-059 at write time; the dispatcher's signing path uses the `serde_jcs` crate (or equivalent) to produce canonical bytes before Ed25519 signing.
- Test: `host_secrets_v1_signed_payload_jcs_roundtrip` — re-encode the signed payload through JCS, assert byte-identical to the original.

### Efficiency posture

- Parse + auth + binding-check (general broker, in-process): ~150µs (JSON is faster to parse than CBOR for typical envelopes).
- In-supervisor handler latency: sub-millisecond target.
- **Secrets subprocess round-trip:** supervisor → UDS → subprocess → handler → UDS → supervisor. Adds ~100–300µs over an in-process call (one extra memcpy + context switch). Acceptable: secrets calls are rare relative to time/cost, and ADR-049's budget (one vsock round-trip + Ed25519 sign per egress) already comfortably accommodates it.
- mvmd-delegated handler: sub-100ms (pre-warmed iroh connection + agent-local TTL cache).
- Audit append: per-handler `audit_durability()` — `Batched(100ms)` for non-secret services (S22: enqueue precedes response; batch only on fsync), `PerCall` for `host.secrets.v1` + future `host.audit.v1`.
- Circuit breaker prevents CPU waste on failing handlers (incl. crashed-subprocess detection on the secrets path).

### Security claim additions — Claims 12 + 13

The two new claims are locked at numbers **12** and **13** per the parallel `worktree-adr-002-claims-12-13` branch (ADR-002 update PR-pending). Wording mirrors what that branch encodes — both plan + the ADR-002 update need to land together; ADR-061 carries the architectural decision record for the four-subprocess hardening under which Claim 13's wording reads through cleanly.

> **Claim 12.** Every host-side service the broker exposes is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited via the chain-signed log. A tampered binding fails plan verification; an unbound call is refused with an audited deny.

> **Claim 13** *(rewritten 2026-05-28 by ADR-062 — the prior wording about "no raw secret value crosses the broker channel" is superseded; secrets are no longer an mvm responsibility)*. Every workload-emitted audit entry (via `host.audit.v1`) is chain-signed by `mvm-audit-signer` under the `WorkloadAudit` category, distinguishable from supervisor-emitted entries in the audit chain. An entry whose bytes are tampered with after signing fails `mvmctl audit verify`; an entry claiming a workload id the caller doesn't own is refused at admission.
>
> *Implementation note.* The W3-audit handler in `mvm-broker` is the sole emitter; the supervisor's `AuditSignerProxy::append_entry` is the sole forwarder. `mvm-audit-signer`'s existing chain-integrity invariants (Plan 104 §H-L5.1 / §H-L5.2) cover the rest. Tests: `workload_audit_entries_chain_signed_with_workload_audit_category` + `workload_audit_entry_workload_id_mismatch_refused` + `audit_chain_verifier_distinguishes_workload_from_system_entries`.

### Surfaces that don't expand

- New host subprocesses in v1: `mvm-host-signer` (uid 904), `mvm-audit-signer` (uid 905), `mvm-broker` (uid 903). ~~`mvm-secrets-dispatcher` (uid 902)~~ — **dropped by ADR-062 (2026-05-28)**. All per-VM, supervised by the per-VM supervisor, killed via parent-death signal. See §"Hardening posture" for the rationale (TCB minimization across **three** discrete process boundaries — the fourth-process reasoning specific to secrets-credential isolation is no longer applicable).
- Trust boundary narrowed (see §"Hardening posture, threat model expansion"). ADR-002's "malicious host" out-of-scope clause is preserved for *physical* attacks (cold-boot, DMA, hardware tampering) but narrowed for *software* insider attacks under the Layer-1/2/5 hardening.
- Egress policy unchanged — broker is host↔guest only.
- `prod-agent-no-exec` unchanged — no broker verb is code-execution-shaped.

## Hardening posture (Layers 1–11)

This section consolidates the hardening commitments that take the
broker from "subprocess-isolated secrets" (the baseline §Architecture
above) to "as tight as practical for v1." Each layer answers a
specific failure mode; each item names the threat it addresses and
the cost it carries. The build sequence (W1–W11) realises these
layers; §Critical files lists the artefacts; §Verification names the
tests.

### Layer 1 — Process isolation (TCB minimization)

The baseline puts everything except `host.secrets.v1` in the
supervisor. A supervisor UAF therefore exfiltrates the host signer
key, can forge audit entries, can mint plans with arbitrary
bindings, and can lie to mvmd about the workload identity.
Hardening splits these out:

- **H-L1.1 — `mvm-host-signer` subprocess (uid 904).** Host signer
  Ed25519/P-256 key never loaded into the supervisor; supervisor
  sends typed "sign this hash" RPCs over a per-VM UDS. New crate
  `crates/mvm-host-signer/`. Subprocess inherits only the UDS FD +
  a read-only mmap of the host signer public key for self-check;
  cosign-verified at spawn (H-L3.1) with TOCTOU-resistant
  verify-then-exec (H-L3.2).
- **H-L1.2 — `mvm-audit-signer` subprocess (uid 905).** Sole writer
  to `~/.mvm/audit/<tenant>.jsonl`, sole holder of the audit
  chain-signing key, sole computer of `prev_hash`. Supervisor sends
  typed entries; signer JCS-canonicalizes, signs, appends. New crate
  `crates/mvm-audit-signer/`.
- **H-L1.3 — `mvm-broker` subprocess (uid 903).** General broker
  (port 5300, the `host.time.v1` / `host.cost.v1` / `broker.v1`
  handlers) split out of the supervisor. Supervisor becomes pure
  launcher + admission controller + IPC router. New crate
  `crates/mvm-broker/`. (`host.secrets.v1` continues to live in
  `crates/mvm-secrets-dispatcher/` per the baseline.)
- **H-L1.4 — Per-workload cgroup + namespace isolation for the
  subprocess set.** Each workload's four subprocesses share a
  workload-specific cgroup v2 with strict memory / CPU / PID / IO
  limits; each subprocess additionally gets its own PID namespace +
  mount namespace (read-only-bind everything outside the per-VM UDS
  dir). macOS approximations: `sandbox_init_with_parameters` per
  subprocess + `posix_spawnattr_setpgroup` for resource grouping.
- **H-L1.5 — Supervisor split deferred to v2.** Supervisor's
  remaining responsibilities (admission verification, IPC routing,
  subprocess lifecycle) stay co-located in v1. Splitting further is
  worth tracking; defer.

### Layer 2 — Hardware-backed key material

- **H-L2.1 — Hardware-enclave host signer key.** macOS: Apple
  Secure Enclave (P-256; wire `sig_alg=0x02`) via
  `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`. Linux:
  TPM 2.0 via `tpm2-tss` (RSA-2048 or ECDSA-P256 depending on TPM
  capability). Fallback: kernel keyring (Linux) or filesystem mode
  0600 (universal) — only with an explicit downgrade flag, surfaced
  in `mvmctl doctor` as a security-claim downgrade. Lands in W8.
- **H-L2.2 — TPM monotonic counter for host signer key rotation.**
  Each key rotation increments a TPM-backed monotonic counter; the
  value embeds in admission audit entries. Defeats key-rollback
  attacks where an attacker reinstalls a previously-leaked key.
  Requires H-L2.1.

### Layer 3 — Subprocess + binary hardening

- **H-L3.1 — Cosign-verify every subprocess binary at spawn.**
  Signature pinned against a release-time public key bundled with
  `mvmctl`. Refuse-to-spawn on mismatch; audit
  `<subprocess>.signature_invalid`. Applies to all four
  subprocesses, not only the secrets dispatcher.
- **H-L3.2 — TOCTOU-resistant verify-then-exec.** Open the binary
  read-only, mmap, verify the mmap'd bytes, then `fexecve` (Linux)
  / `posix_spawn` with FD (macOS). Narrows the
  verify-then-replace window from "any wall-clock interval" to the
  kernel's syscall handoff.
- **H-L3.3 — Explicit seccomp policy in ADR-059 (not "standard").**
  Allow-list: `read`, `write`, `recvmsg`, `sendmsg`, `poll`,
  `epoll_wait`, `clock_gettime`, `exit`, `exit_group`,
  `rt_sigreturn`, `futex`, `mmap`/`munmap` (anon only), `brk`,
  `mprotect` (no PROT_EXEC after init). **Explicitly denied:**
  `process_vm_readv`/`process_vm_writev`, `ptrace`, `kcmp`,
  `pidfd_open`, `userfaultfd`, `bpf`, `perf_event_open`. Per-arch
  (x86_64 + aarch64) syscall numbers via `seccompiler`.
- **H-L3.4 — macOS sandbox profile equivalent.** Without this the
  hardening is Linux-only. Per-subprocess profile via
  `sandbox_init_with_parameters` enumerating allowed system services
  (`mach`, `file-read*` on the per-VM dir, `network-outbound` deny);
  `EXC_GUARD` for unauthorized FD usage.
- **H-L3.5 — Multi-arch seccomp explicit, CI-tested.** Per-arch
  deny-list expressed in `seccompiler`; CI-tested on x86_64 +
  aarch64 (existing project matrix).
- **H-L3.6 — Subprocess config-signing (G1).** Supervisor's spawn
  passes a JSON config to subprocess stdin (audit-back-channel UDS,
  vsock port, allowed bindings). The config envelope is signed
  under the same release-time key as the binary (H-L3.1);
  subprocess refuses to start unless config signature verifies.
  Closes "supervisor-survives-long-enough-to-poison-config" path.
- **H-L3.7 — Zeroize at supervisor's `secrets_proxy.rs` buffers.**
  UDS proxy uses `zeroize::Zeroizing<Vec<u8>>` for forward +
  return buffers. Return-path bytes contain signed-credential
  payload briefly between dispatcher response and vsock send.
- **H-L3.8 — No shared FDs / no shared memory invariant.** CI lint
  `xtask check-subprocess-fd-inheritance` parses the spawn call
  site; subprocess inherits only its UDS sockets + the host signer
  public-key FD; everything else closed via `close_range` after
  fork.
- **H-L3.9 — Resource caps on every subprocess.**
  `RLIMIT_CORE=0` (no core dumps with secrets), `RLIMIT_AS` and
  cgroup memory cap, `mlock`/`mlockall(MCL_FUTURE)` on
  secret-bearing pages, `prctl(PR_SET_DUMPABLE, 0)` (Linux) /
  `PT_DENY_ATTACH` (macOS), `prctl(PR_SET_THP_DISABLE, 1)` for
  secret arena.
- **H-L3.10 — Binary hardening flags + reproducibility lane.**
  PIE + RELRO (full) + stack canaries + `-D_FORTIFY_SOURCE=3` +
  `-fstack-clash-protection`. CI-asserted via `checksec`. Each
  subprocess binary gets its own reproducibility-double-build lane
  (claim-7 reproducibility extended per-binary).
- **H-L3.11 — Static-link + W^X + no `dlopen` + anti-debug.**
  musl-static on Linux; libSystem on macOS. `mprotect(…,
  PROT_EXEC|PROT_READ)` at startup; `PROT_NONE` for everything
  thereafter (no JIT). Startup check: refuse-to-run if
  `/proc/self/status:TracerPid != 0` (Linux) /
  `PT_DENY_ATTACH` invocation succeeds before any sensitive code
  runs (macOS).

### Layer 4 — Protocol + cryptography

- **H-L4.1 — Algorithm-identifier byte in `AuthenticatedFrame`.**
  Adds 1 byte to the frame header. v1 ships `0x01=Ed25519` and
  `0x02=ECDSA-P256` (the macOS SE host-signer path). Lets us swap
  algorithm (Ed448, PQC scheme) later without a hard fork.
- **H-L4.2 — Subprocess response signing.** Each subprocess gets
  its own per-spawn ephemeral keypair (never persisted). Every
  `ServiceResponse` is signed by the subprocess's key before
  crossing the UDS; the supervisor verifies before relaying to the
  guest. Two-key chain (subprocess → supervisor) prevents
  stub-subprocess forgery even if cosign verify (H-L3.1) had a hole.
- **H-L4.3 — Per-call ephemeral session-key rotation.** Workload
  session key rotates every `BROKER_SESSION_REKEY_CALLS=1000` or
  every `BROKER_SESSION_REKEY_MS=60000`. Limits value of a
  session-key compromise to a small window.
- **H-L4.4 — TLS-1.3-only + single suite to mvmd.** Pin TLS 1.3,
  ChaCha20-Poly1305-SHA256, X25519, ALPN matching our protocol.
  No downgrade, no negotiation flexibility.
- **H-L4.5 — Constant-time comparisons.** All
  workload-controllable-byte-string comparisons use
  `subtle::ConstantTimeEq` (session IDs, correlation IDs,
  destination URLs, audit-chain hashes). CI grep lints `==`/`!=`
  on known security-byte types.
- **H-L4.6 — Supervisor-assigned correlation IDs (G4).** Supervisor
  assigns correlation IDs at frame ingress and rewrites or rejects
  workload-supplied ones. Prevents a workload from forging another
  workload's correlation sequence for audit-trail confusion.

### Layer 5 — Audit chain integrity + confidentiality

- **H-L5.1 — `O_APPEND` audit chain FD + dir-immutable.**
  Audit-signer subprocess holds an `O_APPEND` FD to the audit
  JSONL; `chattr +a` on the directory on Linux, `UF_APPEND` on
  macOS. Test asserts FD has `O_APPEND` and `lseek` returns EBADF.
- **H-L5.2 — Anti-rollback chain-head persistence.** `chain_head`
  persisted to a second location on every entry (`~/.mvm/audit/HEAD`
  fsync'd file or kernel keyring entry). Tampering with the JSONL
  fails the secondary check.
- **H-L5.3 — WORM backing for audit logs.** Append-only mount
  where the FS supports it (Linux `chattr +a` enforced; macOS
  `UF_APPEND`). Periodic snapshot to immutable cloud storage is a
  follow-on plan (S3 Object Lock-equivalent — named but not
  in this scope).
- **H-L5.4 — Audit log encryption at rest.** Per-tenant
  ChaCha20-Poly1305 key derived from a TPM/SE-bound master
  (H-L2.1). Today disk-image-theft = audit log plaintext readable;
  with this, theft yields ciphertext. The chain-sign protects
  integrity separately.
- **H-L5.5 — Time-source integrity for audit timestamps.** Use TPM
  monotonic counter or kernel boottime as integrity anchor; flag
  clock jumps in audit (`audit.clock.jump_detected`). Defends
  against NTP-poisoning-driven log backdating.
- **H-L5.6 — No PII in correlation IDs.** Documented invariant.
  ULIDs are time-ordered + random; never derived from
  user-identifiable data.
- **H-L5.7 — Admission blocks until audit-signer is healthy (G3).**
  S22 covers post-up durability. Pre-up: admission ceremony
  refuses to proceed until all four subprocesses report healthy
  via their respective UDS handshake. No in-supervisor audit
  buffer that could be lost on early crash.

### Layer 6 — Admission + capability tightening

- **H-L6.1 — Operator-action audit entries.** `mvmctl services
  revoke`, `mvmctl host-key rotate`, `mvmctl audit verify`,
  `mvmctl services call` (debug path), `mvmctl up --insecure-host`,
  and any other privileged invocation emit chain-signed
  audit entries via `mvm-audit-signer`.
- **H-L6.2 — Audit log rotation policy named.** Rotated file's
  last entry hash = active file's first `prev_hash`; doctor flags
  any chain that fails this continuity invariant. Concrete
  rotation triggers (size, age) land in the host-logging
  follow-up plan.
- **H-L6.3 — Tenant-level secret call quotas.** In addition to
  per-workload quotas (S12). mvmd-enforced tenant cap so N
  workloads under one tenant cannot collectively exceed it.
- **H-L6.4 — mvmd identity pinning explicit.** Pinned in
  `~/.mvm/keys/mvmd-pubkey` (or in the existing fleet-credential
  bundle). Doctor flags pin absence. MITM mitigation during
  initial bootstrap is explicit (the supervisor refuses to talk to
  mvmd without a pinned key).
- **H-L6.5 — Composition width cap.** A5's depth cap is in (≤3);
  add width cap (`BROKER_COMPOSITION_WIDTH=5` — max fan-out
  sub-invocations per call).
- **H-L6.6 — Audit fsync failure policy.** Any audit fsync failure
  → workload pause (not just error to caller); operator review
  required to resume. Audit-signer subprocess surfaces fsync
  failures via the UDS audit-back-channel.

### Layer 7 — Host posture + observability

- **H-L7.1 — KSM off + THP off for workload-adjacent memory.**
  Doctor sets and enforces. Without this, H-L3.7 zeroize has
  cross-process leaks via shared/merged pages.
- **H-L7.2 — Doctor enforces host-kernel hardening; refuses
  admission on weak hosts.** KASLR, KPTI, SMEP/SMAP, Spectre-v2
  mitigations, LSM available, `kernel.unprivileged_userns_clone=0`,
  `kernel.dmesg_restrict=1`, macOS SIP+AMFI+kext-loading checks.
  Refusal mode: `mvmctl up` exits nonzero with a remediation
  list; overridable only with `--insecure-host` (which itself
  audits and warns loudly).
- **H-L7.3 — Subprocess slow-start detection.** If any subprocess
  exceeds `BROKER_SUBPROCESS_START_DEADLINE_MS=2000`, audit
  `<subprocess>.slow_start` and refuse the workload. Defends
  against attacker stalling startup to coincide with another
  event.
- **H-L7.4 — CPU side-channel posture.** Pin each subprocess to a
  CPU core not shared with the supervisor (cpuset where the host
  has spare cores). Best-effort; doctor flags downgrade on hosts
  without spare cores.

### Layer 8 — Supply chain + build + release

- **H-L8.1 — Sigstore / Rekor transparency log entry per
  subprocess release.** Public, append-only ledger of every signed
  binary. Defense against secretly-signed-compromised builds.
- **H-L8.2 — In-toto attestations alongside SLSA.** Build
  provenance with explicit step-by-step materials/products.
  Complements cosign (identity) and SLSA (metadata).
- **H-L8.3 — Hermetic, network-isolated build of subprocess
  binaries.** Explicit (implied by the claim-9 sealed-volume
  pattern). No network during compile; sealed builder VM at a
  distinct uid. Each subprocess's reproducibility-double-build
  lane runs in this hermetic environment.

### Layer 9 — Testing + review process

- **H-L9.1 — Hostile-subprocess test.** Stub subprocess binaries
  (one per kind: host-signer-stub, audit-signer-stub,
  broker-stub, secrets-dispatcher-stub) that pass cosign-verify
  but return wrong-but-well-formed responses. Supervisor MUST
  reject each for failing the subprocess's response signature
  (H-L4.2). Tests the H-L4.2 boundary independently for each
  subprocess kind.
- **H-L9.2 — Mutation testing on security-critical functions.**
  `cargo-mutants` lane targeting
  `crates/mvm-{supervisor,broker,secrets-dispatcher,host-signer,audit-signer}/`.
  Asserts no mutation passes existing tests — escapes are bugs.
- **H-L9.3 — Fuzz the UDS proxy specifically.** Existing W6 fuzz
  extends to the supervisor-side UDS read loop (different code
  path from vsock framing fuzz).
- **H-L9.4 — Side-channel / timing audit.** Run `dudect` or
  `CTGrind` against the secrets dispatcher + host-signer
  subprocess before W5 / W8 merges. Document the run in W5/W8 PR
  description.
- **H-L9.5 — W1, W5, W8 dispatcher review gate.** Mandatory
  dedicated security reviewer sign-off before merge for the
  subprocess scaffolding + secrets-dispatcher implementation +
  hardware-enclave host signer. Extends repo CODEOWNERS pattern.
- **H-L9.6 — CODEOWNERS + multi-reviewer requirement.** Branch
  protection requires a second reviewer for
  `crates/mvm-secrets-dispatcher/`, `crates/mvm-host-signer/`,
  `crates/mvm-audit-signer/`, `crates/mvm-broker/`,
  `crates/mvm-supervisor/src/services/`, and ADR-059.

### Layer 10 — Documentation + threat model

- **H-L10.1 — Threat model document distinct from ADR-059.**
  `specs/threat-models/02-host-services-broker.md` walks STRIDE
  per service (host.secrets.v1, host.time.v1, host.cost.v1,
  broker.v1) with mitigations cross-referenced. ADR-059 stays a
  decision record; the STRIDE walk lives separately.
- **H-L10.2 — CVE response runbook.** `SECURITY.md` says: where
  to report, our SLA, coordinated disclosure policy,
  fix-and-publish workflow, public Sigstore/Rekor entry policy.
- **H-L10.3 — PII invariant documented** in
  `docs/security/audit-fields.md` and inline in the chain entry
  type.

### Layer 11 — Snapshot + restore + recovery semantics (Round-4 gaps)

- **H-L11.1 — Snapshot + restore re-handshake protocol (G6).** On
  workload restore: re-spawn all four subprocesses with fresh
  ephemeral keys; old session keys treated as revoked per S8.
  Stale subprocess state across PID reuse is not preserved.
- **H-L11.2 — Cryptographic-crate pinning (G7).** ADR-059
  §"Implementation choices" pins exact crates + versions:
  `ed25519-dalek` v2.x (constant-time verified), `serde_jcs`
  (pin exact version; CI runs RFC 8785 conformance corpus on
  every PR), `chacha20poly1305` (RustCrypto, audited),
  `tpm2-tss` (Intel) for Linux TPM path, `subtle` for
  constant-time comparisons (H-L4.5). All present in `deny.toml`
  for advisory + license enforcement.
- **H-L11.3 — Deployment-mode threat differentiation (G8).**
  ADR-059 §"Deployment modes" maps single-dev / CI / fleet mode
  → applicable threats so users know which mitigations are
  load-bearing for their use. Doctor surfaces which mode the
  current host is operating in.
- **H-L11.4 — Vsock CVE surface enumeration (G9).** ADR-059
  §"Dependency CVE surface" enumerates KVM vhost-vsock,
  Firecracker, libkrun, cloud-hypervisor, Apple vz vsock by name
  with stated response posture: "a vsock CVE → emergency host
  upgrade required; doctor refuses admission on known-affected
  kernel/VMM versions; affected-version list shipped in `mvmctl`
  and refreshed per release."
- **H-L11.5 — Honest TOFU naming (G5).** ADR-059 explicitly says
  the host signer is TOFU on non-enclave hosts; doctor flags the
  downgrade.
- **H-L11.6 — Operator FIDO ceremony stub (G2).** `mvmctl up
  --prod` runs a `fido_touch_required()` gate that today no-ops
  + audits `operator.fido.unverified` with a loud warning. Full
  FIDO2/Yubikey-touch ceremony lands in W11.

### Tightening deliberately not folded into v1

Named here so future readers don't assume they were missed:

- **m-of-n quorum for host signer key rotation.** Operationally
  heavy; single-operator rotation with audit acceptable for v1.
  Named as a future plan.
- **Hybrid Ed25519 + Dilithium signatures.** PQC matters when CRQC
  arrives; the algorithm-identifier byte (H-L4.1) is sufficient
  preparation.
- **Remote attestation of workload identity** (TPM PCR-bound
  workload signing). Research-grade; existing signed-`ExecutionPlan`
  + cosigned-image sufficient.
- **Full memory-snapshot encryption.** Adds significant complexity
  to snapshot/resume; the realistic threat (disk-imaging the
  snapshot file) is mitigated by host FDE (operator's
  responsibility).
- **mvmd as redundant audit-chain anchor on every entry.** Latency
  cost too high; C7-pinned `chain_head` polling is sufficient.
- **PFS-via-broker-encryption.** Vsock channel is host-local; no
  network attacker. Adding AEAD here is security theater against
  the actual threat.
- **Detection / alerting** (G10). Audit logs are forensics, not
  detection. `host.alert.v1` reserved as a future broker service
  in the host-logging follow-on plan.
- **Disaster recovery / key escrow** (G11). Operator-held escrow
  signed under operator FIDO key is the right shape but a major
  operational lift. Future plan.
- **Subprocess-restart accumulation attack** (G12). Considered:
  no traffic encryption to decrypt; per-spawn keys give attacker
  no cryptographic leverage. Named and dismissed in ADR-059
  §"Considered and rejected threats" so a future reader doesn't
  re-litigate.

### Threat-model expansion this hardening buys

With H-L1.1, H-L1.2, H-L2.1, H-L5.4, and H-L1.4 in:

> **In scope (new):** A hostile host *operator* (insider) with
> shell access who is not authorized to read workload secrets.
> With HW-enclave host signer (H-L2.1), at-rest audit encryption
> (H-L5.4), and key-isolation subprocesses (H-L1.1, H-L1.2),
> shell access to the host no longer yields the host signer key,
> the audit-signing key, or the audit log plaintext. Workload
> secrets are still mediated by `host.secrets.v1`'s
> destination-bound signed credentials (claim-Y design); insider
> with shell can request the broker to mint credentials but
> cannot extract them from process memory thanks to the seccomp
> + setpriv + mlock + cgroup compartment.

ADR-002's existing "malicious host" out-of-scope clause needs an
update: it remains true for *physical* host attacks (cold-boot,
DMA, hardware tampering) but is now narrowed for *software*
insider attacks. ADR-059 carries the cross-reference.

## mvmd-side extension — Plan 52 + ADR-0023 (drafts, to be written to mvmd repo on approval)

### `../mvmd/specs/plans/52-host-services-cross-vm-endpoints.md` (draft)

> **Plan 52 — Host services cross-VM endpoints**
>
> ### Context
>
> mvm's Plan 104 lands a host-services broker. Cross-VM services need data only mvmd has. This plan adds the mvmd-side endpoints and proxy plumbing.
>
> ### Architecture
>
> - **New gateway endpoints** in `crates/mvmd-gateway/src/routes/host_services.rs`:
>   - `GET /v1/host-services/tenant/{tenant_id}/cost?window=…`
>   - `GET /v1/host-services/tenant/{tenant_id}/peers?label_selector=…`
>   - `GET /v1/host-services/tenant/{tenant_id}/config/{key}`
>   - `GET /v1/host-services/tenant/{tenant_id}/rate-budget/{service}`
>   - `GET /v1/host-services/tenant/{tenant_id}/catalog` (the tenant's allowed service set; see mvm §A7)
> - Endpoints gated by mvmd's HMAC-SHA256 API key auth + tenant-scoped-authz. Per-node supervisor authenticates with its fleet credential AND carries a signed `X-MVM-Workload-Id` header verified against mvmd's instance registry. mvmd rejects any query whose `tenant_id` doesn't match the workload's tenant.
> - **Agent-side proxy** in `crates/mvmd-agent/src/host_services_proxy.rs`. Same shape as `sandbox_proxy.rs`. **Transport detail:** new verbs land as `AgentRequest` enum variants over iroh ALPN (existing `crates/mvmd-agent/src/transport.rs` pattern), NOT as a new HTTP route dispatched by the agent. The gateway HTTP routes above are for fleet operators and external integrators; the broker → agent path is iroh-native.
> - **Audit:** every cross-VM call logged in both mvmd's audit stream AND mvm-supervisor's chain — correlatable by `correlation_id`.
>
> ### Build sequence
>
> - [ ] **W1 — Endpoints + auth.** Five routes, workload-id verification, tenant-scoped-authz refusal tests.
> - [ ] **W2 — Agent proxy.** `host_services_proxy.rs`, QUIC dispatcher wiring.
> - [ ] **W3 — Cost + catalog handlers.** Aggregator + tenant catalog endpoint.
> - [ ] **W4 — Hostile-tenant tests.** Cross-tenant attempts, forged workload-id, response replay, malformed-response-side fuzz.
>
> ### Risks
>
> - **R1 — Latency.** Mitigation: agent-local TTL cache for hot keys.
> - **R2 — mvmd-down.** Mitigation: 500ms timeout, `ServiceErrorCode::Unavailable` propagated to guest; never stale data.

### `../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md` (draft)

> **ADR-0023 — mvmd as the cross-VM delegate for the host services broker**
>
> - Status: Proposed
> - Date: 2026-05-26
> - Owner: MVM Project
> - Related: ADR-002, ADR-049, ADR-008, mvm-side ADR-059 (host services broker, proposed)
>
> ### Context
>
> mvm's Plan 104 / ADR-059 introduce a host services broker. Cross-VM services need mvmd-only data. Two shapes:
>
> - **(a) mvm supervisor reaches across workloads directly.** Rejected: violates CLAUDE.md's tenant isolation rule; forces redundant tenant-scoped-authz in mvm; makes per-VM blast radius cover other tenants.
> - **(b) mvm supervisor delegates to mvmd.** Cross-VM data via mvmd's tenant-scoped-authz + audit.
>
> ### Decision
>
> **(b).** mvmd is the single point of tenant-aggregated data and tenant-scoped authorization.
>
> ### Trust model
>
> Two identities per call:
> - **Node identity** (existing): fleet credential. Transport trust.
> - **Workload identity** (new): signed `X-MVM-Workload-Id` header. mvmd verifies against instance registry and refuses tenant_id mismatches.
>
> Both required: node identity is transport-level; workload identity binds the request to one tenant.
>
> ### Consequences
>
> - **Positive:** single tenant-scoped-authz; correlatable audit; mvm per-VM blast radius stays single-tenant.
> - **Negative:** cross-VM calls have higher latency. Mitigated by agent-local cache.
>
> ### Non-goals
>
> - Cross-tenant aggregation. No endpoint exposes data across tenants.
> - Mutation. v1 cross-VM endpoints are read-only.

**Both files written to mvmd repo verbatim from this draft on Plan 104 approval.**

## Follow-up — Host logging + workload audit (sketched, separate plan; number TBD)

(Numbering note: this follow-up was originally drafted as Plan 99, then renumbered through 103 as vz-phase-c-completion, symmetric-builder-vm, in-guest-volume-encryption, and gateway-audit-substrate plans took 99–102. Plan 103 is currently contested by a separate "egress secret detection + obfuscation" proposal flagged 2026-05-26; re-check `gh pr list` + `ls specs/plans/` and pick the next free number when this follow-up actually lands.)

**`host.logging.v1` — workload-emitted structured logs.** Verbs `emit`, `emit_batch` (≤100 records), `tail`. Per-record cap 8 KiB. Rate limit `BROKER_LOGGING_TOKENS_PER_SEC=200`. Audit chain records only `(service, verb, record_count, outcome)`. Cross-VM via mvmd Plan 52 W3 → tenant log sink. Workload-trusted content; opt-in regex redaction via `policy.redact`.

**`host.audit.v1` — workload-emitted audit chain entries.** Verb `record(category, fields)`. Per-record cap 4 KiB, `BROKER_AUDIT_TOKENS_PER_SEC=20`. New `EventCategory::WorkloadAudit` (distinct from `ServiceCall`). `audit_durability() = PerCall`. Verifier distinguishes workload-asserted from host-asserted entries.

**Companion ADR-060** — workload-audit semantics (workload-asserted vs host-asserted entries; verifier behavior; chain rotation policy — addresses S18).

**Depends on:** Plan 104 W1+W2 + mvmd Plan 52 W3.

## Additional considerations

These are decisions pinned for the implementer:

**C1 — Observability: Prometheus metrics from the broker.**
- Per-service latency histograms (`mvm_broker_dispatch_seconds{service=…}`)
- Error-rate counters (`mvm_broker_errors_total{service,code}`)
- Cap-breach counters (`mvm_broker_cap_breach_total{cap=…}` — frame-size, response-size, rate-limit, lifetime-quota, cpu-budget, memory-cap)
- Circuit-breaker state (`mvm_broker_cb_state{service,state}`)
- Lifetime-quota utilization (`mvm_broker_quota_remaining{service,kind}`)
- Wire into `tracing-prometheus` or the existing `mvm-metrics` crate.

**C2 — Dev experience: `mvmctl services` CLI subcommands.**
- `mvmctl services list <workload>` — shows bound services, remaining quotas, circuit-breaker state.
- `mvmctl services call <workload> <service> <verb> --payload <json>` — manual call for debugging (subject to plan binding gate; doesn't bypass auth).
- `mvmctl services catalog` — host's static catalog (which built-in handlers this build has compiled in, post-Cargo-features).
- Wire into `mvm-cli/src/commands/services.rs`.

**C3 — Per-handler idempotency declaration.**
- Different services need different retry semantics. Encode on the trait:
  ```rust
  pub enum Idempotency {
      MintFresh,                   // each call → new result, e.g. host.secrets.v1
      CacheRecent(Duration),       // cache N ms, e.g. host.cost.v1 → 1s
      DedupByCorrelation,          // same correlation_id → reject duplicate, e.g. host.audit.v1
  }
  fn idempotency(&self) -> Idempotency;
  ```

**C4 — Per-handler call timeout, not global.**
- The 50ms global cap is *parse*. Handlers can legitimately take longer.
- Encode `fn call_timeout(&self) -> Duration` on the trait. Defaults: `host.secrets.v1=20ms`, `host.time.v1=2ms`, `host.cost.v1::workload=5ms`, `host.cost.v1::tenant=150ms`, `host.audit.v1=20ms`, `host.logging.v1=10ms`.
- Beyond timeout → `Err(Timeout)` + audit; never blocks the supervisor's reconcile loop.

**C5 — Plans are immutable post-admission.**
- Adding a service binding to a running workload requires workload restart. Fits the signed-plan model.
- If demand emerges for runtime-mutable bindings, that's a future plan (likely a "supplemental binding signature" mechanism).

**C6 — TOCTOU between admission and dispatch.**
- The binding gate confirms "workload may call `host.secrets.v1`." The *grant* inside `host.secrets.v1` has its own expiry (per ADR-049).
- Be explicit in ADR-059: binding is "permission to call," handler enforces "freshness of underlying authority." Two layers, deliberately separate.

**C7 — Audit chain origin durability (DECIDED 2026-05-26: confirmed approach; concrete constraint pinned).**
- Each entry's `prev_hash` chains; tampering inside is detectable. An attacker deleting the chain file and starting fresh defeats this.
- **Mitigation (confirmed):** mvmd-agent syncs the chain head (the latest entry's hash) to durable cluster storage. Off-host anchor lets us detect a wholesale chain reset.
- **Concrete forward-looking constraint on Plan 104 W2** (so this isn't a wish): the `EventCategory::ServiceCall` audit entries must be:
  1. **Append-only with a stable canonical byte serialization** — entries are length-prefixed JSON canonicalized via JCS (RFC 8785, per S28) so a sync-shim can hash the entry bytes and `prev_hash` without re-serializing.
  2. **Self-contained per entry** — each entry carries `(prev_hash, ts, category, fields, sig)` with no out-of-band state needed to verify. A future sync mechanism can stream entries to mvmd-agent without needing to replay the whole chain.
  3. **`chain_head` exposed** — the supervisor exposes the latest entry's hash via an internal API (`AuditRecorder::current_head() -> Hash`) so a future sync agent can poll/push without rooting around in the JSONL file.
- Concrete sync impl lands in the host-logging follow-up plan; the three bullets above are the *contract* Plan 104 W2 must satisfy. If the entry serialization changes later, the sync mechanism breaks — so getting the canonical form right in W2 is load-bearing.

**C8 — Vsock back-pressure as covert channel.**
- See S21. Bounded receive queue (`BROKER_QUEUE_DEPTH=16`) with `Err(QueueFull)` drop policy.

**C9 — Naming consistency: ServiceId is `host.secrets.v1` (DECIDED 2026-05-26).**
- Original draft used `secrets.v1` (unprefixed) — inconsistent with `host.time.v1` / `host.cost.v1`.
- **Rename applied throughout this plan:** wire ServiceId is `host.secrets.v1`; handler type is `HostSecretsV1Handler`; supervisor handler file is `crates/mvm-supervisor/src/services/host_secrets.rs`; SDK dispatcher file is `crates/mvm-sdk/src/services/host_secrets.rs`; Cargo feature is `service-host-secrets`; test name prefix is `host_secrets_v1_*`.
- ADR-049's prose must be updated to mention `host.secrets.v1` as the broker-namespaced identifier when ADR-049 is touched in W5 (no semantic change to ADR-049; just an identifier substitution in the "Implementation: lands as …" line).

## Tensions and unresolved premise questions

Surfaced by adversarial review 2026-05-26. These are framing/design tensions the plan needs an explicit position on. Not bugs — choices that look load-bearing at second glance.

**T1 — "Five sequential rules in one substrate" — be honest about the failure model.**
The capability-gating section now says explicitly: all five gates run in the same supervisor task, in one address space, sharing the same parser and registry state. They're defense-in-depth against bugs in a *single rule*, not against substrate compromise. If the supervisor task is compromised (e.g., use-after-free in the schema parser corrupts the registry), gates 3, 4, 5 are also compromised. Updated the §"Capability gating" section to lead with this. No code change required; the framing was overselling.

**T2 — In-process broker forecloses operational moves.**
The "no new daemon" choice is presented as upside, but it also rules out: (a) hot-swap of a buggy handler without VM restart, (b) true crash isolation (`catch_unwind` does NOT catch aborts or stack overflows — a handler can still kill the supervisor), (c) broker restart mid-workload, (d) running the broker under stricter seccomp than the supervisor. Combined with C5 (plans immutable post-admission) + A7 (per-tenant catalogs from mvmd), the operational picture is: **a tenant catalog change in mvmd forces every running workload of that tenant to restart to pick it up.** This is not currently surfaced as a contract. Two paths:
- **Acceptable:** workloads under this broker are expected to be short-lived (sandbox runs, ephemeral compute) so catalog churn = next-workload pickup is fine. Document this explicitly.
- **Not acceptable:** the broker needs a "service-binding refresh" path that re-pulls the catalog without VM restart. That's a substrate change.
Current plan defaults to the first interpretation. Pin it or change it.

**T3 — Encoding: JSON (DECIDED 2026-05-26).**
Original draft used CBOR. Switched to JSON because v1 has no genuinely binary payload, the W7 ADR-049 SDK matrix (Python `cbor2` / TS `cbor-x` / Rust `ciborium`) introduces real cross-language friction, `jq` debuggability is real over project lifetime, and the existing `GuestRequest` / `HostBoundRequest` channels already use JSON in `crates/mvm-guest/src/vsock.rs` — consistency. Future binary payloads use base64-in-JSON on the specific field; 33% overhead on one field at ~500-byte typical payloads is negligible. Trade-off acknowledged: COSE-based signing (RFC 8152) would mandate CBOR; ADR-049's signing scheme is Ed25519-on-bytes (not COSE), so JSON is fine. JCS (RFC 8785 — JSON Canonicalization Scheme) is used for the bytes-to-sign when signing JSON payloads.

**T4 — `host.secrets.v1` runs in a dedicated subprocess (DECIDED 2026-05-26).**
Resolved by §"Host-side: four-subprocess architecture" above. The general broker (port 5300, in-process) and the secrets dispatcher (port 5301, separate subprocess at uid 902 with seccomp + setpriv) share zero code paths and zero address space. A use-after-free in the general broker's dispatcher cannot reach the credential-minting code, the grant table, or the keystore policy state in the secrets subprocess. This is the production-ready isolation pattern (industry analogues: AWS STS, HashiCorp Vault, Kubernetes ServiceAccount token controllers — all out-of-process credential issuers). Cost: ~50% W1+W5 scope growth — a new crate (`mvm-secrets-dispatcher`), subprocess lifecycle in the supervisor, UDS proxy code path. Justified because (a) the user stated control-plane compromise as a security concern, (b) this gives A4 a concrete v1 consumer (see T5), (c) split-task→split-process migration later is more painful under the no-backcompat rule.

**T5 — A4 substrate ships in v1 with secrets as its first consumer (DECIDED 2026-05-26).**
Resolved by §A4 rewrite above. The "speculative substrate with no v1 consumer" criticism dissolves — the v1 consumer of the out-of-process handler substrate IS the secrets dispatcher (T4). Every line of the UDS proxy code is exercised by the security-critical secrets path on every workload start. v2 third-party addons reuse the *same* substrate when they land: same wire envelope, same handler trait, same audit flow, same subprocess pattern. The substrate's design is informed by the secrets dispatcher's real requirements, not a hypothetical addon's. This pattern of "ship the abstraction along with its first real consumer, defer hypothetical consumers to v2" is the right discipline.

**T6 — mvmd delegation is an architectural boundary, not a trust boundary.**
ADR-0023's trust model has the supervisor signing the `X-MVM-Workload-Id` header. A compromised supervisor forges arbitrary workload-ids; mvmd accepts them. The "blast radius stays single-tenant" guarantee only holds *if* the supervisor is uncompromised, in which case there's no remaining isolation to preserve (the supervisor would also release its own tenant's secrets). The delegation buys clean separation of *correctness* concerns (mvmd owns aggregation), not a new trust boundary. **Updated:** the §Cross-VM delegation prose and mvmd ADR-0023 should be explicit that this is an architectural boundary, NOT a trust boundary. The trust boundary remains "supervisor and below are trusted."

**T7 — C7 (audit sync) was a wish; now pinned to three concrete constraints.**
Resolved above in §C7 — the chain entry format must be (1) append-only canonical JSON (JCS, RFC 8785), (2) self-contained per entry, (3) expose `chain_head` via internal API. Plan 104 W2 must satisfy these contracts so the follow-up sync mechanism doesn't require rewriting the audit format.

### Out of scope here (deferred to future plans)

- `host.metrics.v1` (counter/gauge) and `host.trace.v1` (OpenTelemetry) — the host-logging follow-up plan+ in the workload-telemetry group.
- **Reaching host services from the guest** (`host.fetch.v1`, plus a future `host.endpoint.v1`) — the brokered, secure answer to the "let my workload talk to a service running on my Mac" DX. **Prior-art parallel (2026-06-04):** an external Rust-native VZ reference (the "DX reference" — named obliquely per repo policy; see [`../research/on-device-vz-sandbox-gap-analysis.md`](../research/on-device-vz-sandbox-gap-analysis.md)) solves this with a **Docker-style magic `host.*.internal` hostname mapped to the NAT gateway IP** — i.e. *raw, unmediated TCP reachability* to whatever the host happens to bind on `0.0.0.0`, with **no allowlist, no auth, no per-service binding, no audit**. We deliberately **do not clone that**: open host-NAT reachability is exactly the host-access / covert-egress hole claims 1 + 10 forbid and Plan 142 (network no-bypass) hardens against. The same DX is delivered the safe way as **binding-gated broker handlers over vsock**: `host.fetch.v1` = destination-scoped, audited HTTP; `host.endpoint.v1` (future) = an allowlisted host `host:port` forward (local DB, model server, dev server). Each is bound in the signed `ExecutionPlan.services`, destination-allowlisted, and recorded in the audit chain (claims 12/13) — controlled egress **without** flipping claim 10's default-deny off. Own plan if pursued.
- Hardware enclave integration for `host.secrets.v1` signing key (Apple Secure Enclave on macOS, TPM on Linux) — future hardening ADR.
- v2 addon detailed design — separate plan once v1 substrate is proven.
- GDPR / data-residency for cross-VM forwarded logs — the host-logging follow-up plan / ADR-060.
- Runtime-mutable bindings (supplemental signatures) — future plan if demand emerges.
- **Pre-spawn / warm-pool support — post-spawn `configure` RPC (Plan 159 WS-1 dependency, 2026-06-04).** Today each subprocess takes its signed config on stdin *at spawn* (§Subprocess lifecycle details). Plan 159's warm standby pool needs the moat spawned **before the workload is known**, then configured at claim. Add a post-spawn `configure` RPC over the existing supervisor-owned per-VM UDS carrying the **same supervisor-signed config** (allowed bindings, agent profile, session key); **accepted exactly once**, signature-verified before acceptance (preserves H-L3.6 — no downgrade); the subprocess refuses all service calls until configured. This amortizes the expensive cosign-verify + seccomp setup into the warm pool. The pool manager that drives it stays a **keyless launcher** that never sees workload plans/secrets — architectural, not trust, boundary (T6). Own work item, coordinated with Plan 159 WS-1; in the mvmd-managed case mvmd (already resident) drives it, so no new daemon there.

## Risks

- **R1 — ADR-049 SDK matrix is a lot of code.** ~10 hook points across 3 ecosystems. Split W7 per language.
- **R2 — Per-VM supervisor adds a vsock listener.** Fuzz surface (W6) + a few MB memory (negligible).
- **R3 — `host.secrets.v1` is the most security-critical code shipped on the runtime path in months.** Dedicated security review of W5 before merge; W5 includes ADR-049's hostile-guest matrix; W6 fuzz target lands same PR window.
- **R4 — Schema change to `ExecutionPlan` requires `SCHEMA_VERSION` bump 4→5.** `crates/mvm-plan/src/plan.rs:45` defines `SCHEMA_VERSION: u32 = 4` with explicit "older verifiers must fail closed on unknown schema versions." Adding `services: Vec<ServiceBinding>` is a v5 schema; old (v4) plans hard-fail at verification, not silently accept the new field as empty. This is consistent with the saved no-backcompat rule but the earlier R4 wording ("old plans verify") was misleading. Migration: any in-flight v4 plans must be re-synthesized + re-signed under v5 to keep running; per the no-backcompat rule, no shim.
- **R5 — Plan numbering race (REVISED 3x).** Three numbering collisions hit this plan mid-conversation: (1) mvm `98-vz-builder-vm.md` took Plan 98, (2) mvm `103-w6a-implementation-tracker.md` took Plan 103, (3) mvmd `51-network-policy-enforcement-rollout.md` and `0022-network-policy-enforcement-architecture.md` took mvmd Plan 51 + ADR-0022 between mvm PR open and mvmd PR open. This plan finally settles at **mvm Plan 104 / ADR-059 / Sprint 57 + mvmd Plan 52 / ADR-0023**. Sprint 55-derived work claims mvm 97 and 98; Sprint 56 claims mvm 99–102, 057, 058 and mvmd 50; Sprint 56 W6 follow-up claims mvm 103; the network-policy-enforcement initiative claims mvmd 51 + 0022. Re-verify all numbers immediately before opening any implementation PR; per saved guidance, do not renumber other sessions' work.
- **R6 — Lockstep delivery between mvm W4b and mvmd Plan 52.** Land mvmd Plan 52 W1+W2+W3 *before* opening mvm W4b. W4b PR pins required mvmd commit. mvm W1–W4a + W5 + W6 + W7 have no mvmd dep.
- **R7 — JSON encoding crates.** `serde_json` for the wire envelope (already in-tree), `serde_jcs` (or equivalent) for canonical signing bytes (RFC 8785). Existing `cargo-deny` lane catches regressions. **No CBOR libraries needed** — ciborium dropped from the dependency closure when T3 settled on JSON.
- **R8 — Cross-backend behavioral divergence.** Vsock semantics differ across libkrun, Firecracker, Apple Container, vz. Mitigation: W6 cross-backend test matrix; backend-specific shims rather than divergent behavior.
- **R9 — Sprint 56 claim 10 collision.** Sprint 56 owns "claim 10" (bytes leaving trust boundary). Plan 104's broker claims must be assigned different numbers in ADR-059 against the live ADR-002 claim list at write time.
- **R10 — W1 scope tripled by hardening fold-in.** Originally a 2-subprocess design (supervisor + secrets dispatcher); now four subprocesses (broker, secrets, host-signer, audit-signer) with cosign-verify, config-signing, cgroup/namespace isolation, resource caps, binary-hardening flags. Realistic estimate: W1 is 4–6 weeks of focused work, not 2. Split W1 into W1a (envelope + protocol + first subprocess scaffold) and W1b (remaining subprocesses + lifecycle + hardening) if a single PR becomes unreviewable.
- **R11 — W8 hardware-enclave wave depends on platform-specific code that doesn't exist in `mvm` today.** macOS SE Swift bridge + Linux TPM 2.0 integration are both first-time additions. If `tpm2-tss` C bindings prove painful or SE-Swift-bridge stability concerns emerge mid-wave, ship v1 with the **software-fallback host signer** + a loud `mvmctl doctor` downgrade row, and land W8 as a Sprint-58 follow-on. The fallback path must be implemented in W1 either way — it's the bridge during W2–W7 even before W8 ships.
- **R12 — Algorithm-identifier byte (H-L4.1) is a v1 wire commitment.** Once shipped, removing or repurposing the byte is a hard fork. Verify in W1 design review that the byte is in the *right* position in `AuthenticatedFrame` (before any length-prefixed body) so future versions can choose alternative algorithms cleanly.
- **R13 — Subprocess crash storms vs workload availability.** Three restarts per workload per subprocess = up to 12 subprocess restarts before workload pause. A subprocess hitting a deterministic crash bug (e.g., a malformed mvmd response) could pause many workloads simultaneously across the fleet. Mitigation: per-workload pause + audit-chain alert; W6 mutation testing (H-L9.2) catches most deterministic crash bugs pre-release.
- **R14 — `mvm-host-signer` subprocess is a new single-point-of-availability.** Supervisor cannot admit plans if `mvm-host-signer` is down; can't sign audit entries if `mvm-audit-signer` is down. v1 mitigation is restart-with-backoff (same as secrets dispatcher); operational consequence is "all admission and all audit blocked during signer recovery." Documented operational behavior; no code-side mitigation in v1 (m-of-n quorum is deferred per §"Tightening deliberately not folded in").
- **R15 — Cross-backend Swift listener (vz) is the riskiest single sub-task.** The existing `VsockProxy.swift` is host-as-client only — no `VZVirtioSocketListener` `shouldAcceptNewConnection` path exists. New Swift work for two ports + four subprocesses on each accepted connection. Mitigation: land an integration test on the vz backend specifically in W6 before W3 ships, so a vz regression is caught at the matrix gate.
- **R16 — Operator FIDO ceremony (W11) may not have FIDO hardware on all developer hosts.** Fallback (operator-key-on-encrypted-USB) is realistic but adds a credential-management ceremony to every contributor's workflow. Risk: developer pushback on the `--prod` gate slowing the feedback loop. Mitigation: `mvmctl up` (without `--prod`) doesn't require FIDO; the gate applies only to production-mode launches. `mvmctl up --insecure-host --no-fido` audited downgrade available.

## Non-goals (explicit)

- Streaming responses (monitoring, log tail). Envelope is request/response only in v1.
- Addon-provided handlers shipping in v1. v1 ships only the substrate (addon-proxy path implemented, no addons consumed).
- `unsafe_guest_tls_inspection` proxy-with-CA path from ADR-049. Ships separately.
- Non-HTTP secret substitution. Out of scope per ADR-049 §"Non-HTTP egress."
- Cross-VM cost aggregation across tenants. `host.cost.v1::tenant` is single-tenant.
- Audit log rotation strategy concrete triggers (size, age). Deferred to the host-logging follow-up plan / ADR-060 (when `host.audit.v1` lands). Continuity invariant *is* in scope (H-L6.2).
- **m-of-n quorum for host signer key rotation.** Operationally heavy; single-operator rotation with audit is acceptable for v1. Future plan once W11 FIDO ceremony exists.
- **Hybrid Ed25519 + Dilithium signatures (PQC).** Algorithm-identifier byte (H-L4.1) is sufficient preparation; full hybrid signing waits until CRQC pressure is real.
- **Remote attestation of workload identity** (TPM PCR-bound workload signing). Research-grade; existing signed-`ExecutionPlan` + cosigned-image sufficient.
- **Full memory-snapshot encryption** for paused workloads. Complexity in snapshot/resume; realistic threat (disk-imaging the snapshot file) mitigated by host FDE (operator's responsibility).
- **mvmd as redundant audit-chain anchor on every entry.** Latency cost too high; C7-pinned `chain_head` polling is sufficient.
- **PFS-via-broker-encryption.** Vsock channel is host-local process-to-process; no network attacker. Adding AEAD here is security theater against the actual threat. Explicitly *not* added (H-L4 design discussion).
- **Detection / alerting (G10).** Audit logs are forensics, not detection. `host.alert.v1` is reserved as a future broker service in the host-logging follow-on plan; v1 ships no alerting path.
- **Disaster recovery / key escrow (G11).** Lost host signer / TPM / audit-signer keys = workloads broken; no recovery in v1. Operator-held escrow signed under operator FIDO key is the right shape but a major operational lift — future plan once W11 lands FIDO.
- **Subprocess-restart accumulation attack (G12).** Considered and dismissed: no traffic encryption to decrypt; per-spawn keys give attacker no cryptographic leverage. Named in ADR-059 §"Considered and rejected threats" so a future reader doesn't re-litigate.
- **Supervisor split (admission verifier + IPC router as separate processes).** Deferred to v2. v1 supervisor remains the single launcher + IPC router + admission controller.
- **Workload-to-workload services (peer discovery, mesh).** Out of scope; `host.peers.v1` is future-only.
- **Runtime secret substitution / `host.secrets.v1` / managed-credential service (ADR-062).** Dropped from v1. Workloads bring their own secret material via env vars, file mounts, in-cloud IMDS, vault sidecars, etc. mvm's stance is "launch + audit the workload"; credential delivery is not in mvm's name. If the need re-emerges, a future ADR designs a fresh path rather than picking up where ADR-049 left off.
