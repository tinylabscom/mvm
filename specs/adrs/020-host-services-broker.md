# ADR-020: Host services broker over vsock

- Status: Proposed
- Date: 2026-05-26
- Owner: MVM Project
- Related: ADR-001 (microVM security posture), ADR-014 (signed audited execution plans), ADR-047 (app-deps audit pipeline), ADR-048 (workload secrets), ADR-023 (TLS substitution mechanism), ADR-019 (guest protocol versioning + readiness), ADR-058 (claim 10 — bytes leaving trust boundary), mvmd ADR 0008 (tenant-scoped authz), mvmd ADR 0023 (mvmd as cross-VM delegate, proposed)
- Sequenced by: [Plan 104 — Host Services Broker over vsock](../plans/104-host-services-broker.md)

## Context

Today, anything a microVM needs from the host arrives one of two ways:

1. **Boot-time only.** A read-only ext4 drive mounted at `/mnt/secrets` or `/mnt/config` (`mvmctl up --volume host_dir:/mnt/secrets`). ADR-048 explicitly tags this `unsafe_guest_secret_materialization` and declines to make a non-leakage claim about it.
2. **A small fixed-verb reverse channel.** `HostBoundRequest` on vsock port 53 carries `WakeInstance`, `QueryInstanceStatus`, `QueryHostTime` (`crates/mvm-guest/src/vsock.rs`). Each new verb is a code change to an enum.

There is also a **half-built secrets path**: `ExecutionPlan.secrets: Vec<SecretBinding>` exists in `crates/mvm-plan/src/plan.rs`; `KeystoreReleaser` trait stubs in `crates/mvm-supervisor/src/keystore.rs` return `NotWired` / `NotImplemented`; the `secrets:` field is hardcoded empty in synthesis. ADR-023 has committed to a vsock side-channel for secret substitution as the v1 mechanism — described in prose, stubbed in code.

What is needed is broader than secrets: a **host-side services layer** microVMs call at runtime — secrets today, then cost / time / logging / audit / monitoring as the catalog grows — with one auth model, one capability model, one audit chain, and one extension point that supports built-in *and* addon-provided services without protocol churn.

## Decision

The per-VM supervisor exposes a **host services broker** that microVMs reach over vsock. v1 ships three services:

- **`host.secrets.v1`** runs in a dedicated subprocess (`mvm-secrets-dispatcher` binary, uid 902, seccomp `standard`, setpriv `--bounding-set=-all --no-new-privs`). This is production-ready process-level isolation. Industry analogues: AWS STS, HashiCorp Vault, Kubernetes ServiceAccount token controllers — all out-of-process credential issuers.
- **`host.time.v1`** and **`host.cost.v1`** run in the in-process general broker inside the supervisor.
- **`broker.v1/list_services`** lets workloads enumerate bound services + verbs + deprecation flags at runtime.

The wire format is JSON via `serde_json`. Signed payloads use JCS (RFC 8785) for canonical bytes. Two vsock ports per VM: port 5300 for the general broker, port 5301 for the secrets dispatcher. Both use the existing `AuthenticatedFrame` (Ed25519 + session id + monotonic sequence) from day one.

Cross-VM data delegates to mvmd over its existing iroh ALPN transport (new `AgentRequest` enum variants in `crates/mvmd-agent/src/transport.rs`). The supervisor never assembles cross-tenant data itself; mvmd's tenant-scoped-authz is the authority.

The out-of-process handler substrate ships in v1 with `host.secrets.v1` as its first consumer. v2 third-party addons reuse the same substrate without protocol change.

## Architecture

### Wire shape

Two vsock listeners per VM. Both ports use 4-byte big-endian length prefix wrapped in `AuthenticatedFrame`.

```rust
#[serde(deny_unknown_fields)]
pub struct ServiceCall {
    pub service: ServiceId,
    pub verb: String,
    pub correlation_id: Ulid,
    pub payload: serde_json::Value,
}

#[serde(deny_unknown_fields)]
pub enum ServiceResponse {
    Ok { correlation_id: Ulid, payload: serde_json::Value },
    Err { correlation_id: Ulid, code: ServiceErrorCode, message: String },
}
```

`ServiceId` is reverse-DNS with explicit version segment: `host.secrets.v1`, `host.time.v1`, `host.cost.v1`. v2 services ship alongside v1 on different IDs — no silent upgrades.

### Two-process host-side architecture

**General broker** (in-process inside `mvm-supervisor`, listens on vsock 5300):

- New module `crates/mvm-supervisor/src/services/` with `broker.rs`, `registry.rs`, `handler.rs`, `host_time.rs`, `host_cost.rs`, `mvmd_client.rs`, `circuit_breaker.rs`, `quota.rs`, `secrets_proxy.rs`.
- Dispatches `HandlerRef::InProcess(Arc<dyn ServiceHandler>)` directly; forwards `HandlerRef::OutOfProcess(UdsProxy)` to the secrets subprocess.

**Secrets subprocess** (`mvm-secrets-dispatcher` binary, NEW crate, listens on vsock 5301):

- New crate `crates/mvm-secrets-dispatcher/`. Binary spawned per VM by the supervisor at admission time.
- Runs under uid 902 + seccomp `standard` + setpriv. Cannot register handlers at runtime; hosts only `host.secrets.v1`.
- Reads its config from the supervisor's stdin once at startup (host signer *public* key path, audit back-channel UDS path, agent profile, allowed bindings from `ExecutionPlan.services`), then closes stdin.
- Audit subentries flow back to the supervisor over a separate UDS for chain-signing — the subprocess never holds the signing key.
- Dies when the supervisor dies (`PR_SET_PDEATHSIG(SIGTERM)` on Linux; kqueue-monitored parent-pid watch on macOS).
- Restart-on-crash with exponential backoff (100ms, 500ms, 2s). After 3 restarts within a workload lifetime, the supervisor stops restarting, audits `secrets.subprocess.crashed_repeatedly`, and triggers a workload pause via the Plan 82 harness. The workload sees `Err(Unavailable)` for `host.secrets.v1` calls until operator review.

**Why two processes is mandatory, not optional.** The secrets subprocess's address space is fully isolated from the general broker's. A use-after-free, integer overflow, or logic bug in the general broker's schema/auth/binding/quota code cannot reach the credential-minting code, the keystore policy state, or the in-flight grant table.

### ExecutionPlan schema change

```rust
#[serde(default, deny_unknown_fields)]
pub services: Vec<ServiceBinding>,

pub struct ServiceBinding {
    pub service: ServiceId,
    #[serde(default)]
    pub policy: ServicePolicy,
    #[serde(default)]
    pub quotas: ServiceQuotas,
}
```

`SCHEMA_VERSION` bumps 4→5. Existing v4 plans hard-fail at verification — no shim, no backcompat (consistent with the project's no-backcompat-first-version rule). Existing `secrets: Vec<SecretBinding>` stays as the policy blob for `host.secrets.v1`.

### Capability gating — five sequential rules

Before any handler dispatch, a call traverses five rules **in order**. They are sequential, not isolated within a single process: for the general broker, all five run in the same supervisor task, in the same address space, sharing the same `serde_json` parser. **Process-level isolation only exists for `host.secrets.v1` calls**, which cross the UDS boundary to the secrets subprocess (gate 5 runs there in a separate address space; gates 1–4 still run in the supervisor before forwarding).

1. **Schema gate.** `serde_json` parse of the envelope with `deny_unknown_fields`; 64 KiB max frame size enforced before parse; recursion cap 8; 50ms parse timeout. Note: `deny_unknown_fields` on the envelope does not cover the dynamically-typed `payload: serde_json::Value`; the typed second-stage parse via `ServiceHandler::parse_payload` (gate 5 prerequisite) is the real payload schema gate.
2. **Authentication gate.** `AuthenticatedFrame` Ed25519 verify against the workload session key (minted at plan admission, discarded at workload stop). Monotonic-sequence replay rejection.
3. **Binding gate.** Workload's `ExecutionPlan.services` must bind this `ServiceId`. Bindings cannot be added at runtime.
4. **Profile + rate-limit + quota gate.** `AgentProfile` check; token-bucket per `(workload_id, service_id)`; in-flight cap; lifetime quota.
5. **Handler-specific policy.** Per-handler `parse_payload` with typed `deny_unknown_fields` (the real schema gate); destination-URL match for `host.secrets.v1`; mvmd tenant-scoped-authz (ADR 0008) for cross-VM verbs.

### Audit chain

Extend `EventCategory` in `crates/mvm-supervisor/src/audit_recorder.rs` with one new variant `ServiceCall`. Every dispatch — allowed or denied — emits one entry: `(service, verb, outcome, correlation_id)`. **Payload content is never logged** (ADR-019 §4 redaction invariant); per-handler audit subentries take typed `AuditFields` (no `String` payload param).

Three contracts on the chain entry format (load-bearing for the future host-logging follow-up plan's mvmd-agent sync mechanism):

1. **Append-only with stable canonical byte serialization** — entries are length-prefixed JSON canonicalized via JCS (RFC 8785) so a sync agent can hash entry bytes + `prev_hash` without re-serializing.
2. **Self-contained per entry** — each entry carries `(prev_hash, ts, category, fields, sig)` with no out-of-band state needed to verify.
3. **`chain_head` exposed** — the supervisor exposes the latest entry's hash via `AuditRecorder::current_head() -> Hash` so a future sync agent can poll/push.

### Cross-VM delegation via mvmd

Cross-VM concerns (tenant-aggregated cost, peer discovery, tenant config) belong in mvmd (per CLAUDE.md: "mvmd owns tenant isolation; mvmctl never reaches across workloads"). `MvmdClient` trait in `crates/mvm-supervisor/src/services/mvmd_client.rs`; real impl uses **mvmd-agent's iroh ALPN transport** with new typed `AgentRequest` variants — NOT raw QUIC+mTLS, NOT new HTTP routes the agent proxies. mvmd Plan 52 and mvmd ADR 0023 sequence the mvmd side.

This is an **architectural boundary, not a trust boundary** — see mvmd ADR 0023 for the full elaboration. A compromised supervisor forges arbitrary workload-ids; mvmd accepts them. The "blast radius stays single-tenant" property only holds under the uncompromised-supervisor assumption, which is itself in scope under ADR-001.

### Built-in handler split

- **No mvmd dep:** `host.time.v1`, `host.secrets.v1`, `host.cost.v1::workload` verb.
- **Mvmd-delegated:** `host.cost.v1::tenant` verb, `host.peers.v1` (future), `host.config.v1` (future).

### Extensibility surface (seven axes — full detail in Plan 104 §Extensibility design)

A1 versioned ServiceIds with parallel versions + deprecation; A2 Cargo feature flags per built-in service; A3 typed `ServicePolicy` per handler; A4 out-of-process handler substrate (v1 ships it; secrets dispatcher is the first consumer); A5 service composition with depth cap 3; A6 version negotiation at plan admission; A7 per-tenant catalogs via mvmd Plan 52.

## Security model

### New claims

ADR-001's live list runs through Claim 11. This ADR adds two new claims:

| # | Claim | Primary layer | Workstream | CI gate |
|---|---|---|---|---|
| 12 | Every host-side service the broker exposes is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited via the chain-signed log | cross-cutting (policy + audit) | Plan 104 W2 | `service_call_denied_when_unbound` + `audit_chain_contains_service_call_entries` tests; `xtask check-handler-adr-coverage` lint |
| 13 | No raw secret value crosses the broker channel; `host.secrets.v1` returns destination-bound, time-bound signed credentials only. Raw secret bytes never leave the supervisor's address space | cross-cutting (data containment) | Plan 104 W5 | `host_secrets_v1_denied_outside_allowed_destinations` + `zeroize_drop_zeros_secret_bytes` + `host_secrets_v1_signed_payload_jcs_roundtrip` + ADR-023 hostile-guest matrix |

Claim 12 is the binding-gated dispatch invariant. A tampered binding fails plan verification under Claim 8; an unbound call is refused with an audited deny.

Claim 13 is the secret-value-never-leaves invariant. `host.secrets.v1` returns destination-bound signed credentials (per ADR-023); raw secrets stay in the supervisor's keystore. The S25 placeholder-egress backstop in gvproxy/passt (Plan 104 W6 / W7) is a defense-in-depth net against SDK-bypass attacks at the L4/L7 boundary.

### Threat model

The broker is a new attack surface. Threats and mitigations (numbered per Plan 104 §Security S1–S28; only load-bearing ones repeated here):

- **S1 — JSON parser as TCB code.** `serde_json` (already in-tree, well-fuzzed). Knobs: `BROKER_MAX_FRAME_BYTES=65536`, `BROKER_MAX_DEPTH=8`, `BROKER_PARSE_TIMEOUT_MS=50`. The secrets subprocess uses its own `serde_json` instance — a parser bug exploited in the general broker does not pivot to the secrets subprocess's memory.
- **S5 — Supervisor blast radius, secrets isolated by process boundary.** The general broker (port 5300) runs in the supervisor; `host.secrets.v1` runs in the secrets subprocess with no shared address space. Subprocess crashes don't kill the supervisor; the supervisor returns `Err(Unavailable)` and restarts the subprocess (max 3 times per workload, then workload pause).
- **S10 — Out-of-process handler TCB scope.** v1 ships the substrate with `mvm-secrets-dispatcher` as its first consumer. The substrate code lives in the supervisor TCB; the dispatcher binary is a new line of TCB code — minimal, single-responsibility, dedicated security review per the no-`do_exec` discipline. v2 third-party addons reuse the same subprocess pattern.
- **S14 — Inter-call memory hygiene.** Handlers must not leak material from call N to call N+1. `zeroize::Zeroizing<…>` wrappers on any handler-internal cache; CI lint `xtask check-no-mutable-handler-state` scans handler modules for `Mutex<T> where T: !Zeroize`.
- **S22 — Audit batch durability (BLOCKING).** Batched fsync is fine; batched *enqueue* is not. The `Recorder` API takes the entry synchronously before `dispatch` returns; only the fsync is batched. Test: `audit_entry_enqueued_before_response_returned`.
- **S23 — Tenant catalog must be mvmd-signed (BLOCKING).** A compromised mvmd-agent or MITM in the iroh transport could inject a wider catalog than the tenant is entitled to. Mitigation: catalog response carries an mvmd-fleet-credential-signed envelope; the supervisor verifies against a pinned mvmd public key before trusting the payload.
- **S24 — Privileged composition can leak secrets (BLOCKING).** A handler composing `host.secrets.v1` via `ServiceCallContext::invoke` could inadvertently include the composed credential in its own outbound response. Mitigation: `xtask check-handler-composition` lint fails the build on any handler that calls `ctx.invoke("host.secrets.v1", …)` and embeds the result in its response payload. Allowlist via `#[allow(secret_passthrough)]` with mandatory review.
- **S25 — SDK integrity / placeholder egress backstop (BLOCKING).** The host-side egress proxy (gvproxy/passt) detects `mvm-secret://` token patterns in outbound HTTP bytes and drops the frame, emitting `secret.substitute.bypass_detected`. Belt-and-suspenders against a malicious deps-volume substitute SDK; Claim 11 (signed deps volume) is the primary defense.
- **S26 — First-call cold-cache timing oracle on `host.secrets.v1`.** Response latency padded to a fixed floor (default 5ms) regardless of cache state. Knob: `BROKER_SECRETS_LATENCY_FLOOR_MS=5`.
- **S28 — JSON canonical encoding for signed credential payloads.** Signed credentials use JCS (RFC 8785) for bytes-to-sign — sorted keys, no whitespace, defined number serialization, NFC Unicode.

### Surfaces that do not expand

- No new host process or persistent socket on disk in v1 beyond the per-VM secrets dispatcher subprocess and its two UDS endpoints (mode 0600, supervisor-owned). v2 third-party addons add per-addon UDS in a separate plan.
- Trust boundary unchanged from ADR-001 — supervisor was already trusted.
- Egress policy unchanged — broker is host↔guest only.
- `prod-agent-no-exec` (ADR-001 Claim 4) unchanged — no broker verb is code-execution-shaped.

## Alternatives considered

**(A) Stay with the fixed-verb `HostBoundRequest` enum.** Rejected: every new service is a code change to a guest-side enum; no auth model beyond the proxy socket; no audit; no per-workload binding. Doesn't scale to secrets + cost + logging + future telemetry.

**(B) ADR-023's TLS-terminating proxy with injected CA.** Considered as the secret-substitution alternative. The cost is significant: it **expands the host's trust boundary into the guest's trust store** — a CA the host controls is now trusted by the guest's TLS stack for *all* outbound connections, not just secret-bearing ones. (B) ships separately as the `unsafe_guest_tls_inspection` opt-in for workloads that can't be modified (vendored binaries, third-party agents).

**(B′) Vsock substitution via SDK hook — the default chosen here.** SDK hooks the HTTP client *before* TLS, asks the host for a destination-bound signed credential, injects it into the outbound request, and the guest does its own TLS to upstream. The guest's trust store is untouched. Protocol-agnostic (HTTP/1.1, HTTP/2, HTTP/3, gRPC, mTLS). Cost: per-language hook matrix (Plan 104 W7).

Plan 104 takes the strongest property of each: (B′) is the primary path; S25 adds the network-layer enforcement property from (B) as a fallback.

**(C) CBOR wire format with COSE signing.** Considered for v1. Switched to JSON via `serde_json` (Plan 104 T3 decision): no genuinely binary payload in v1; SDK matrix friction in Python/TS/Rust CBOR libraries is real; `jq` debuggability over project lifetime matters; consistency with existing `GuestRequest` / `HostBoundRequest` JSON channels. Future binary payloads use base64-in-JSON on the specific field. ADR-023's signing scheme is Ed25519-on-bytes (not COSE), so JSON-with-JCS is appropriate.

**(D) Single-process broker with all services (including secrets) in-process inside the supervisor.** Considered, rejected (Plan 104 T4 decision). Process-level isolation is the production-ready pattern for credential issuers (AWS STS, Vault, K8s SA token controllers — all out-of-process). The split-task→split-process migration later would be more painful under the no-backcompat rule. Cost: ~50% W1+W5 scope growth — a new crate, subprocess lifecycle, UDS proxy code path. Justified by (a) user-stated concern that control-plane compromise is a security risk and (b) the substrate then has a concrete v1 consumer (kills the "speculative substrate" criticism — see T5).

**(E) Defer the out-of-process handler substrate to v2 when third-party addons need it.** Considered, rejected (Plan 104 T5 decision). Coupling the substrate's first consumer (secrets dispatcher) to v1 means every line of the UDS proxy code is exercised by the security-critical secrets path on every workload start. The substrate's design is informed by real requirements, not hypothetical addon needs. v2 third-party addons reuse the substrate when they land.

## Consequences

### Positive

- **One auth model, one capability model, one audit chain** for every host-side service the workload calls — replacing the ad-hoc `HostBoundRequest` enum + the half-built `KeystoreReleaser` stubs.
- **Production-ready isolation for credential issuance** via the subprocess pattern. A logic bug in the general broker's TCB code cannot pivot into the secrets subprocess's memory.
- **Substrate proven by use, not speculation.** The out-of-process handler path is exercised by the secrets dispatcher from day one; v2 addons reuse it without protocol change.
- **Extensibility without protocol churn.** Adding a new built-in service is a single handler file + one registry line + a `ServiceBinding` entry (Plan 104 §"Manual falsifiability check"); the envelope, registry, and auth path do not change.

### Negative

- **One new line of TCB code** (the `mvm-secrets-dispatcher` binary). Mitigated by minimal single-responsibility design and dedicated security review per the no-`do_exec` discipline.
- **`SCHEMA_VERSION` bump 4→5.** Existing v4 plans hard-fail at verification; per the no-backcompat rule, no shim. Migration: re-synthesize + re-sign under v5.
- **Cross-VM calls have higher latency than in-supervisor calls** (sub-100ms target with pre-warmed iroh + agent-local TTL cache). Acceptable for the cost / catalog / future config use cases; not a fit for hot-path queries.
- **Per-backend listener work is non-trivial on vz.** The existing Swift `VsockProxy` is host-as-client only; vz needs a new `VZVirtioSocketListener` class. Substantial sub-task in Plan 104 W1.

## Migration

No backwards-compatibility path is shipped. v4 `ExecutionPlan` instances hard-fail at verification under v5. `KeystoreReleaser` / `NoopKeystoreReleaser` / `LiveKeystoreReleaser` stubs are deleted in Plan 104 W5. `HostBoundRequest::QueryHostTime` is deleted in Plan 104 W3; the only internal caller is migrated to the broker in the same commit. ADR-023's prose is updated in W5 with a one-line "Implementation: lands as `host.secrets.v1` in the broker (ADR-020, Plan 104)" — no semantic change to ADR-023.

## Out of scope

- Streaming responses (monitoring, log tail). Envelope is request/response only in v1.
- Addon-provided handlers shipping in v1. v1 ships only the substrate (the addon-proxy path is implemented and exercised by the secrets dispatcher; no third-party addons are consumed).
- `unsafe_guest_tls_inspection` proxy-with-CA path from ADR-023 — separate plan.
- Non-HTTP secret substitution — out of scope per ADR-023 §"Non-HTTP egress."
- Cross-VM cost aggregation across tenants — `host.cost.v1::tenant` is single-tenant.
- Hardware enclave integration for `host.secrets.v1` signing key (Apple Secure Enclave, TPM) — future hardening ADR.
- Runtime-mutable bindings (supplemental signatures) — future plan if demand emerges. Per Plan 104 C5, plans are immutable post-admission; a binding change requires workload restart.
- Audit chain rotation policy — deferred to the host-logging follow-up plan (number TBD) when `host.audit.v1` lands and workloads can write to the chain.


## Consolidated from ADR-061 — Host services broker — four-subprocess hardening

- **Status:** Proposed — supersedes ADR-020 (this document) §Architecture and §Security model
- **Date:** 2026-05-27
- **Owner:** MVM Project
- **Related:** [ADR-001 microvm security posture](001-microvm-security-posture.md), [ADR-014 signed audited execution plans](014-signed-audited-execution-plans.md), [ADR-014 app deps audit pipeline](014-signed-audited-execution-plans.md), [ADR-014 claim-safe sandbox parity](014-signed-audited-execution-plans.md), [ADR-023 secret substitution mechanism](023-secrets-subsystem-egress-substitution.md), [ADR-019 guest protocol versioning and readiness](019-guest-protocol-versioning-and-readiness.md), [ADR-014 claim-10 bytes leaving trust boundary](014-signed-audited-execution-plans.md), ADR-020 (this document, original text), [Plan 104 host services broker](../plans/104-host-services-broker.md), mvmd [ADR-0023 mvmd host services delegation](../../../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md)

## Context

ADR-020 (this document) shipped a **two-process design** for the host services broker: the supervisor hosts the general broker in-process (`host.time.v1`, `host.cost.v1`, `broker.v1`), and `mvm-secrets-dispatcher` runs in a separate subprocess for `host.secrets.v1`. ADR-020 records that decision and the JSON wire format, JCS-canonical signing, capability-gating, and audit-chain shapes.

Subsequent threat-modeling under the directive to make this design "as tight as practical" identified four key isolation gaps the two-process design does not address:

1. **Host signer key extraction.** The supervisor reads `~/.mvm/keys/host-signer.ed25519` to sign `ExecutionPlan`s. A supervisor UAF therefore extracts the key, which compromises *all future* plans (claim 8) across the entire host until the key is rotated.
2. **Audit chain forgery.** The supervisor holds the audit chain-signing key and is the sole writer to `~/.mvm/audit/<tenant>.jsonl`. A supervisor compromise can forge entries arbitrarily, defeating claim 8's chain-signed audit invariant.
3. **General broker bug pivots into the supervisor TCB.** A use-after-free or integer overflow in the in-process broker's JSON parser, registry, or quota logic runs in the supervisor's address space — it can pivot into admission, plan signing, or audit signing code paths.
4. **Software insider attacks.** ADR-001's "malicious host" out-of-scope clause assumes the host operator is trusted. With shell access to the host on the two-process design, an insider can read all of the above: the host signer key, the audit chain key, the audit log plaintext, and the in-flight secrets in process memory.

This ADR records the decision to pivot to a **four-subprocess design** that addresses all four gaps and narrows ADR-001's "malicious host" clause to exclude software insiders. Plan 104's "Hardening posture (Layers 1–11)" section carries the implementation specifics.

## Decision

The broker architecture moves from two processes (supervisor + secrets dispatcher) to **four discrete subprocesses**, each in its own uid + seccomp + setpriv + per-workload cgroup + PID/mount namespace. The supervisor becomes a pure launcher + admission controller + IPC router.

| Subprocess | UID | Role | Listens on |
| --- | --- | --- | --- |
| `mvm-broker` | 903 | `host.time.v1`, `host.cost.v1`, `broker.v1` | vsock 5300 + per-VM UDS |
| `mvm-secrets-dispatcher` | 902 | `host.secrets.v1` only | vsock 5301 + per-VM UDS |
| `mvm-host-signer` | 904 | Sole holder of host signer key; signs plans + signed credentials via UDS RPC | per-VM UDS only |
| `mvm-audit-signer` | 905 | Sole writer to `~/.mvm/audit/<tenant>.jsonl`; sole holder of audit chain-signing key | per-VM UDS only |

Each subprocess is cosign-verified at spawn with TOCTOU-resistant mmap-then-`fexecve`. Each receives a release-key-signed JSON config envelope on stdin and refuses to start unless the signature verifies. Each has its own per-spawn ephemeral keypair and signs every response it produces; the supervisor verifies before relaying. The full hardening matrix is documented in [Plan 104 §Hardening posture (Layers 1–11)](../plans/104-host-services-broker.md#hardening-posture-layers-111).

Additional new decisions in this hardening:

- **Algorithm-identifier byte** in `AuthenticatedFrame` (`0x01=Ed25519`, `0x02=ECDSA-P256` reserved for the macOS SE host-signer path in Plan 104 W8). Lets us swap algorithm later without a hard fork.
- **Hardware-enclave host signer** in W8 (Apple Secure Enclave on macOS; TPM 2.0 on Linux via `tpm2-tss`). Software fallback retained with a loud `mvmctl doctor` downgrade row; TOFU honesty for non-enclave hosts.
- **TPM monotonic counter for rotation rollback resistance.** Each `mvmctl host-key rotate` increments the counter; the value embeds in admission audit entries.
- **Per-call ephemeral session-key rotation** (`BROKER_SESSION_REKEY_CALLS=1000`, `BROKER_SESSION_REKEY_MS=60000`).
- **Audit-log encryption at rest** — per-tenant ChaCha20-Poly1305 key derived from a TPM/SE-bound master.
- **Anti-rollback chain-head persistence** — `chain_head` written to a second location on every entry.
- **Supervisor-assigned correlation IDs** (rewrites or rejects workload-supplied IDs to prevent cross-workload forensic-trail confusion).
- **`O_APPEND`-only audit FD + dir-immutable** (`chattr +a` on Linux, `UF_APPEND` on macOS).
- **Tenant-level secret call quotas** (mvmd-enforced cap; in addition to per-workload quotas).
- **mvmd identity pinning** in `~/.mvm/keys/mvmd-pubkey`; admission refuses without a pin.
- **Composition width cap** (`BROKER_COMPOSITION_WIDTH=5`).
- **TLS-1.3-only + single suite** (ChaCha20-Poly1305-SHA256, X25519) to mvmd.
- **Operator FIDO touch on `mvmctl up --prod`** — stub in Plan 104 W1; full implementation in W11.
- **Sigstore/Rekor transparency log per subprocess release**; in-toto attestations alongside SLSA; per-binary reproducibility-double-build lane.
- **`cargo-mutants` mutation testing** lane targeting the four subprocess crates + supervisor services module.
- **`mvmctl doctor` refuses admission on weak hosts** (KASLR, KPTI, SMEP/SMAP, Spectre-v2, KSM, THP, LSM, kernel hardening sysctls; macOS SIP+AMFI+kext). `--insecure-host` audits + warns.

## What this supersedes from ADR-020

| ADR-020 section | Status under ADR-061 |
| --- | --- |
| §Architecture (two-process design) | **Superseded.** Replaced by the four-subprocess design above. The narrative in ADR-020 still applies as the *original* design; readers should treat ADR-061 as the current architectural source of truth. |
| §Security model | **Extended.** ADR-020's threat model assumed the supervisor was a single trust boundary; ADR-061 splits it into four subprocesses and adds software insider attacks to the in-scope set (see §Threat model below). |
| §Decision (high-level) | **Refined.** The high-level "we ship a broker" decision stands. The architectural specifics under it are superseded. |

## What remains from ADR-020 unchanged

| ADR-020 section | Status |
| --- | --- |
| §Wire format (JSON; `serde_json` envelopes; `deny_unknown_fields`) | Unchanged. |
| §JCS canonical signing (RFC 8785; `serde_jcs`) | Unchanged. |
| §Capability gating (five rules: schema, auth, binding, profile + quota, handler policy) | Unchanged in structure; gates 1–4 still run in the supervisor before forwarding to the appropriate subprocess. |
| §Audit chain (one new `EventCategory::ServiceCall`; chain-signed JSONL; payload bytes never logged) | Unchanged in shape; mechanism moves to `mvm-audit-signer` per Layer 1. |
| §Cross-VM via mvmd (iroh ALPN; new `AgentRequest` variants; mvmd-side Plan 52 + ADR-0023) | Unchanged. |
| §ExecutionPlan schema bump 4→5 (`services: Vec<ServiceBinding>`; no shim) | Unchanged. |
| §Comparison of SDK-hook vsock vs TLS-terminating proxy (ADR-023 alternatives) | Unchanged. |
| Claims 12 + 13 numbering | Unchanged. ADR-061 carries the implementation details under which Claim 13's "supervisor's address space" reads through as a strict tightening (raw secrets are now in `mvm-secrets-dispatcher`'s + `mvm-host-signer`'s subprocess address spaces — both subsets of the supervisor's previous responsibility). |

## Implementation choices

Pinned now so they don't drift:

| Concern | Crate / mechanism | Why |
| --- | --- | --- |
| Signing | `ed25519-dalek` v2.x | RustCrypto, constant-time verified |
| Canonical JSON | `serde_jcs` (pin exact version; CI runs RFC 8785 conformance corpus on every PR) | Required for cross-implementation signature verification |
| AEAD for audit-at-rest | `chacha20poly1305` (RustCrypto, audited) | Audit logs at rest under Plan 104 §H-L5.4 |
| TPM (Linux) | `tpm2-tss` (Intel) | Linux host-signer key isolation under H-L2.1 |
| Secure Enclave (macOS) | Swift bridge to `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` (P-256) | macOS host-signer key isolation under H-L2.1 |
| Constant-time comparisons | `subtle::ConstantTimeEq` | H-L4.5; CI grep lint enforces |
| Seccomp filters | `seccompiler` | Per-arch (x86_64 + aarch64) deny-lists under H-L3.3 |
| FIDO (W11) | `webauthn-authenticator-rs` | Operator FIDO ceremony under Plan 104 §H-L11.6 |

All crates are present in `deny.toml` with advisory + license enforcement.

## Deployment modes

Threats and mitigations apply differently across deployment shapes; ADR-061 inherits ADR-020's framing and adds the insider-threat distinction:

| Mode | Description | Threats in scope | Notes |
| --- | --- | --- | --- |
| **single-dev** | A developer running `mvmctl` on their laptop | Hostile guest workload; hostile network for mvmd path | Insider threat NOT in scope (developer is the operator) |
| **CI** | A CI runner executing `mvmctl up` from a PR or branch | Above + hostile-PR insider (PR author cannot be trusted with prod credentials) | `mvmctl up --prod` gated by the FIDO ceremony (W11); CI auto-runs are `--no-prod` |
| **fleet (multi-tenant via mvmd)** | mvmd-orchestrated workloads across many hosts | Above + hostile mvmd-agent (Plan 104 §S15), hostile multi-tenant (§S4), hostile network for mvmd transport, **hostile insider with host shell** (newly in scope per §Threat model below) | Full hardening stack including W8 hardware enclave |

`mvmctl doctor` surfaces which mode the current host is operating in.

## Dependency CVE surface

The broker's isolation rests on vsock + the underlying VMM + kernel paths. Each is a CVE surface that requires a response. Doctor refuses admission on known-affected versions; the affected-version list ships in `mvmctl` and is refreshed per release.

| Dependency | Surface | Doctor check |
| --- | --- | --- |
| Linux kernel `vhost-vsock` | Guest-to-host channel | Refuse admission on known-vulnerable kernel versions |
| Firecracker `virtio-vsock` | Linux runtime path | Refuse admission on known-vulnerable Firecracker versions |
| libkrun `virtio-vsock` | macOS runtime path | Refuse admission on known-vulnerable libkrun versions |
| cloud-hypervisor `virtio-vsock` | Builder VM path on macOS | Refuse admission on known-vulnerable cloud-hypervisor versions |
| Apple `vz` virtio sockets | macOS 26+ Apple Silicon runtime + builder | Refuse admission on macOS versions with known Apple-vz CVEs |
| gvproxy / passt | Userspace virtio-net gateway (egress secret backstop in Plan 104 §S25) | Refuse admission on known-affected gateway versions |
| `ed25519-dalek`, `serde_json`, `serde_jcs`, `chacha20poly1305`, `tpm2-tss` | Crypto + parsing | `cargo deny` advisory + license gate on every PR |

A vsock CVE = emergency host upgrade required. Response posture documented in `SECURITY.md`'s CVE response runbook (PR-i).

## Considered and rejected threats

Named here so future readers don't re-litigate:

- **Subprocess-restart accumulation attack.** Concern: attacker induces 3 restarts to harvest ephemeral subprocess response keys. **Dismissed:** no traffic encryption to decrypt; per-spawn keys give the attacker no cryptographic leverage; 3 keys per workload is far below cryptanalytic accumulation threshold.
- **Workload-set correlation IDs as a forensic-trail attack.** **Mitigated** (Plan 104 §H-L4.6 / G4) by supervisor-assigned correlation IDs at frame ingress; workload-supplied IDs are rewritten or rejected.
- **PFS-via-broker-encryption.** Considered adding AEAD on the broker channel for forward secrecy. **Dismissed:** vsock is a host-local process-to-process channel; there is no network attacker against whom PFS would help. Adding AEAD here is security theater against the actual threat (memory-resident-key extraction).

## Threat model

ADR-001's "malicious host" out-of-scope clause is **narrowed**, not removed.

**Physical attacks remain out of scope:** cold-boot DRAM extraction, DMA via Thunderbolt/PCIe, hardware tampering (chip-off, side-channel power analysis), unauthorized firmware flashing.

**Software insider attacks are newly in scope** thanks to Layer 1 + 2 + 5 hardening:

- **Host signer key extraction by shell-on-host attacker** — defeated by H-L1.1 (key never loaded into the supervisor) + H-L2.1 (key never extractable from HW enclave on enclave-equipped hosts).
- **Audit chain forgery by shell-on-host attacker** — defeated by H-L1.2 (chain-signing key isolated to `mvm-audit-signer`) + H-L5.1 (`O_APPEND`-only FD) + H-L5.2 (anti-rollback chain-head persistence).
- **Audit log content extraction by shell-on-host attacker** — defeated by H-L5.4 (per-tenant ChaCha20-Poly1305 at rest, key derived from TPM/SE master).
- **Secret extraction from process memory by shell-on-host attacker** — defeated by H-L1.4 (per-workload cgroup + PID/mount namespace) + H-L3.9 (`PR_SET_DUMPABLE=0` / `PT_DENY_ATTACH` + mlock) + H-L3.11 (anti-debug startup check refuses to run under ptrace).

On **non-enclave hosts** (no Apple SE, no Linux TPM), the host signer is **trust-on-first-use (TOFU)**: whatever's on disk after first run is "the" key. `mvmctl doctor` surfaces this as a security-claim downgrade. Honest naming, not a hidden flaw.

## Consequences

**Positive:**

- TCB minimization: a supervisor UAF no longer extracts host signer keys, audit signing keys, or in-flight credentials.
- Threat-model expansion: software insider attacks newly in scope.
- Extensibility unchanged from ADR-020: built-in handlers and v2 addon handlers share one substrate.
- Observability unchanged: every call audited; operator actions audited; `broker.v1/list_services` exposes the runtime catalog.
- Falsifiability: a fourth service `host.dev.echo.v1` can land in one handler file in `mvm-broker` without touching envelope, registry, or auth — verified at Plan 104 W6.

**Negative:**

- Scope: roughly 3–4 sprints of work where the original ADR-020 / Plan 104 v1 was 1.
- Operational surface: four new subprocess binaries per VM (was 1 under ADR-020); new doctor checks; new release-pipeline lanes (cosign per binary, Sigstore, in-toto, reproducibility-per-binary).
- Single points of availability: `mvm-host-signer` and `mvm-audit-signer` are now load-bearing for admission and audit respectively; restart-with-backoff is the v1 mitigation, with m-of-n quorum deferred.
- Cross-backend complexity: the vz (Apple Silicon) backend needs a new `VZVirtioSocketListener` Swift class — substantial sub-task.
- Hardware-enclave dependency (W8): macOS SE + Linux TPM 2.0 integration is first-time work in `mvm`; software fallback retained but flagged as a downgrade.

## Non-goals

(Inherits ADR-020's non-goals; lists only the *additions* this hardening makes explicit so they don't quietly become assumed-covered.)

- **m-of-n quorum for host signer key rotation.** Operationally heavy. Future plan once W11 FIDO ceremony exists.
- **Hybrid Ed25519 + Dilithium signatures (PQC).** The algorithm-identifier byte (above) is sufficient preparation; full hybrid signing waits until CRQC pressure is real.
- **Remote attestation of workload identity** (TPM PCR-bound workload signing). Research-grade; existing signed-`ExecutionPlan` + cosigned-image sufficient.
- **Full memory-snapshot encryption** for paused workloads. Realistic threat (disk-imaging the snapshot file) mitigated by host FDE (operator's responsibility).
- **Detection / alerting** (Plan 104 §G10). Audit logs are forensics, not detection. `host.alert.v1` reserved as a future broker service in the host-logging follow-on plan.
- **Disaster recovery / key escrow** (Plan 104 §G11). Future plan once W11 lands FIDO.
- **Supervisor split** (admission verifier + IPC router as separate processes). v1 supervisor remains the single launcher + IPC router + admission controller. Deferred to v2.

## Migration from ADR-020's two-process design

Per the project's no-backcompat rule: there is no shim, no migration path, no transitional period. ADR-020's two-process design has not yet been implemented (Plan 104 v1 is the implementation plan; nothing was built yet). Implementation begins directly under ADR-061's four-subprocess design. Plan 104 W1 scaffolds all four subprocesses from day one.

## See also

- [Plan 104 — host services broker](../plans/104-host-services-broker.md) §Hardening posture (Layers 1–11) for the per-subprocess hardening matrix and the build sequence W1–W11.
- ADR-020 — host services broker (this document, original text) for the JSON wire format, JCS signing, capability gating, audit chain, and cross-VM delegation decisions that ADR-061 inherits unchanged.
- [ADR-001 §"Security claims"](001-microvm-security-posture.md) for Claims 12 + 13 (pending merge from `worktree-adr-002-claims-12-13`).
- [ADR-023 — secret substitution mechanism](023-secrets-subsystem-egress-substitution.md) for the `host.secrets.v1` substitution flow that lands inside `mvm-secrets-dispatcher`.
- [mvmd ADR-0023 — mvmd host services delegation](../../../mvmd/specs/adrs/0023-mvmd-host-services-delegation.md) for the cross-VM trust model.


## Consolidated from ADR-062 — Host services broker — drop `host.secrets.v1`, add `host.audit.v1`

- **Status:** Proposed — supersedes [ADR-023](023-secrets-subsystem-egress-substitution.md) in full, supersedes parts of ADR-020 §"Architecture" and ADR-020 §"Consolidated from ADR-061" §"Decision" (subprocess count + secrets-specific reasoning)
- **Date:** 2026-05-28
- **Owner:** MVM Project
- **Related:** [ADR-001 microvm security posture](001-microvm-security-posture.md), [ADR-023 secret substitution mechanism](023-secrets-subsystem-egress-substitution.md) (superseded), ADR-020 (this document), ADR-020 §"Consolidated from ADR-061", [Plan 104 host services broker](../plans/104-host-services-broker.md), [threat model 02 host services broker](../threat-models/02-host-services-broker.md)

> **Consolidation note:** an earlier draft of this section proposed itself (then-ADR-062) as the canonical host-services-broker ADR, consolidating the original secret-substitution ADR, ADR-020, and ADR-061 — that merge was never carried out (those remained standalone files). The ADR-wide consolidation pass instead folded ADR-062 into ADR-020 (this document, the host-services-broker canonical), alongside ADR-061, ADR-084, ADR-089, and ADR-090; the original secret-substitution ADR was separately folded into ADR-023 (the secrets-substitution canonical). Per ADR-022 §3 the broker / host-signer / audit-signer / supervisor remain four separate processes built from the one `mvm-hostd` crate.

## Context

[ADR-023](023-secrets-subsystem-egress-substitution.md) committed mvm to a vsock side-channel for runtime secret substitution. ADR-020 (this document) generalised that into the host services broker with `host.secrets.v1` as the forcing function. ADR-020 §"Consolidated from ADR-061" hardened the design with a four-subprocess architecture, where the dedicated `mvm-secrets-dispatcher` subprocess was the primary justification for the L1 TCB-minimization split.

Subsequent project-direction review (2026-05-28) decided to **drop runtime secret substitution as an mvm responsibility** in v1. Reasoning:

- The `host.secrets.v1` design pulls credential issuance into the host's trust boundary; the alternative ("workloads bring their own secret material") is materially simpler, and the security claims of mvm's broker are not load-bearing for whether *external* secret material is available to workloads.
- ADR-023's SDK-matrix cost (Python `requests`/`httpx`/`aiohttp`, TypeScript `fetch`/`axios`, Rust `reqwest`/`hyper`/`tonic` hook libraries) is substantial and the per-language hook surface is ongoing maintenance.
- The hostile-guest threat surface (raw socket bypass, library bypass, placeholder egress, S25 backstop) is large and growing.
- Workloads typically already have credential delivery mechanisms (env vars, file mounts, in-cloud IMDS, vault sidecars). Adding a fourth one in mvm's name is feature creep.

The hardening infrastructure that ADR-061 built around the secrets dispatcher (cosign-verified subprocesses, signed config envelopes, per-spawn ephemeral keys, isolated key holders) is still load-bearing for the *other* host-side responsibilities: signing `ExecutionPlan`s (Claim 8), writing chain-signed audit logs (Claim 8 audit chain), and the future host-services we *do* want (time, cost, audit-from-workload).

Separately, project-direction review wants **workloads to emit their own audit entries** as a first-class capability. Originally scoped to the host-logging follow-on plan; pulling into the main Plan 104 now keeps the audit infrastructure built in W1b useful from day one.

## Decision

**Drop `host.secrets.v1` and `mvm-secrets-dispatcher` from Plan 104 v1.** Delete the crate, delete the supervisor's `secrets_proxy.rs`, remove the secrets references from Plan 104 / ADR-023 / ADR-020 / ADR-061 / threat-model 02 / ADR-001 Claim 13.

**Add `host.audit.v1` as a workload-callable service in `mvm-broker`.** Verbs `emit` (one entry) + `emit_batch` (≤100 entries, ≤4 KiB each). Workload-emitted entries flow through `mvm-broker` → supervisor's `AuditSignerProxy` → `mvm-audit-signer`, chain-signed with a new `EventCategory::WorkloadAudit` variant so the chain verifier can distinguish workload-asserted from system-asserted entries.

**Keep all the subprocess hardening infrastructure** that ADR-061 built. The architecture becomes **3 subprocesses** (down from 4):

| Subprocess | UID | Role | Listens on |
| --- | --- | --- | --- |
| `mvm-broker` | 903 | `host.time.v1`, `host.cost.v1`, `host.audit.v1` (new), `broker.v1` | vsock 5300 + per-VM UDS |
| `mvm-host-signer` | 904 | Sole holder of host signer key; signs `ExecutionPlan`s via UDS RPC | per-VM UDS only |
| `mvm-audit-signer` | 905 | Sole writer to `~/.mvm/audit/<tenant>.jsonl`; sole holder of audit chain-signing key | per-VM UDS only |

The `mvm-secrets-dispatcher` subprocess (uid 902) is removed. The vsock listener on port 5301 (which was the secrets dispatcher's port) is removed too; only port 5300 is bound per VM.

## What this supersedes

| ADR / artifact | Status under ADR-062 |
| --- | --- |
| ADR-023 (entire) | **Superseded.** The vsock-substitution-vs-TLS-proxy comparison stays as historical context but the design itself is not being implemented. ADR-023's "Implementation: lands as `host.secrets.v1` in the host services broker" line is now false. |
| ADR-020 §"Architecture" (two-process design) | **Already superseded by ADR-061**; further narrowed to three subprocesses here. |
| ADR-061 §"Decision" (four-subprocess table) | **Superseded** by the three-subprocess table above. The reasoning for splitting `mvm-secrets-dispatcher` (credential-minting threat surface) is no longer applicable. The reasoning for the other three subprocesses (key isolation, audit isolation) **remains valid and is the basis for keeping them**. |
| ADR-061 §"Decision" — additional Layer-1 reasoning | **Preserved.** Host-signer isolation (H-L1.1) still load-bearing for Claim 8. Audit-signer isolation (H-L1.2) still load-bearing for chain integrity. General broker isolation (H-L1.3) still load-bearing for parser-bug containment. |
| ADR-061 §"Threat model" — software insider clause | **Preserved with edits.** Software-insider attacks on the host signer key and audit chain key are still in scope. The "secrets in process memory" threat goes away — there are no secrets to extract. |
| ADR-001 Claim 13 (no raw secret over broker) | **Rewritten** (see §"Security claims" below). |

## What remains unchanged from ADR-020 / ADR-061

- Wire format: JSON via `serde_json` for envelopes; JCS (RFC 8785) via `serde_jcs` for signed payloads.
- Algorithm-identifier byte in `AuthenticatedFrame` (§H-L4.1).
- Pre-spawn binary integrity check (§H-L3.1 — cosign verify; lands via #483).
- Signed config envelope (§H-L3.6 — wraps `SubprocessConfig` bytes; lands via #486).
- Per-spawn ephemeral subprocess response signing (§H-L4.2).
- Capability gating (five rules: schema, auth, binding, profile + quota, handler policy).
- Audit chain shape: JCS-canonical entries, `O_APPEND`-only FD, dir-immutable, anti-rollback chain-head persistence.
- Cross-VM via mvmd (iroh ALPN; mvmd Plan 52 + ADR-0023).
- `ExecutionPlan.services` schema bump 4 → 5 (`services: Vec<ServiceBinding>`).
- Hardware-enclave host signer (W8 — Apple SE + Linux TPM 2.0).
- Per-workload cgroup + namespace isolation (§H-L1.4).
- All §S* threats that aren't secrets-specific.

## What goes away

- `crates/mvm-secrets-dispatcher/` (entire crate)
- `crates/mvm-supervisor/src/services/secrets_proxy.rs`
- Plan 104 W5 (secrets dispatcher wiring)
- Plan 104 W7 (ADR-023 SDK matrix — Python/TS/Rust hook libraries)
- §H-L4.3 per-call session-key rotation (was secrets-specific timing-oracle defense)
- §S22 (audit batch durability for secrets) — replaced by generic audit-durability discussion
- §S24 (privileged composition leaks secrets) — no secrets to leak
- §S25 (SDK integrity / placeholder egress backstop) — no placeholders to bypass
- §S26 (cold-cache timing oracle on `host.secrets.v1`) — no service to oracle against
- §S27 (signed-plan revocation when host signer rotated for cause) — keep for plan signing context; rewrite to drop secrets framing
- §S28 (JCS for signed credentials) — keep but reframe: JCS is for *audit-entry* bytes-to-sign + future signed payloads, not for credentials specifically

## `host.audit.v1` service shape

New handler in `mvm-broker` (uid 903) implementing `ServiceHandler`:

| Verb | Verb-payload | Returns |
| --- | --- | --- |
| `emit` | One typed audit entry (category + fields) | `chain_head` after append |
| `emit_batch` | Vector of up to `BROKER_AUDIT_BATCH_MAX = 100` entries, total ≤ `BROKER_AUDIT_BATCH_BYTES = 256 KiB` | `chain_head` after final entry; per-entry status array |

**Per-record cap:** 4 KiB per entry (`BROKER_AUDIT_RECORD_BYTES = 4096`).
**Rate limit:** token-bucket with `BROKER_AUDIT_TOKENS_PER_SEC = 20` per workload (vs the broker-wide rate limit).
**Audit durability:** `PerCall` — the chain entry must be fsync'd before the response returns.
**EventCategory:** new `EventCategory::WorkloadAudit` variant in `mvm-audit-signer`'s allow-list, distinct from `ServiceCall` and `Admission` so the verifier can compute workload-asserted vs system-asserted entry rates separately.

The handler forwards each entry to the supervisor's `AuditSignerProxy::append_entry` with the `WorkloadAudit` category prefix. The audit-signer's existing chain-drift detection (Plan 104 §H-L5.1+H-L5.2) handles all the integrity invariants.

**Workload trust boundary:** entries are *workload-asserted* — the verifier records "workload X claimed this happened" semantics, not "supervisor observed this happened". Tooling that consumes the chain (`mvmctl audit verify`, future SIEM connectors) should display the category alongside the entry so operators can tell the source.

## Implementation choices unchanged from ADR-061

- Same Cargo dep pinning (`ed25519-dalek` v2.x, `serde_jcs`, `chacha20poly1305`, `tpm2-tss`, `subtle`).
- Same `subtle::ConstantTimeEq` discipline for security-byte comparisons.
- Same per-arch (x86_64 + aarch64) `seccompiler` deny-lists.
- Same `webauthn-authenticator-rs` for the W11 operator FIDO ceremony.

## Security claims

ADR-001's claim 12 stays (binding-gated service dispatch). **Claim 13 is rewritten** to apply to workload-emitted audit entries:

> **Claim 13 (rewritten).** Every workload-emitted audit entry (via `host.audit.v1`) is chain-signed by `mvm-audit-signer` under the `WorkloadAudit` category, distinguishable from supervisor-emitted entries in the audit chain. An entry whose bytes are tampered with after signing fails `mvmctl audit verify`; an entry claiming a workload id the caller doesn't own is refused at admission.

Two new tests verify the claim: `workload_audit_entries_chain_signed_with_workload_audit_category` + `workload_audit_entry_workload_id_mismatch_refused`.

The ADR-001 framework-references row for Claim 13 is rewritten too — drops the credential-exfiltration MITRE references; adds T1078 (Valid Accounts — unauthorized audit attribution) under `D3FEND: Authentication`.

## Consequences

**Positive:**

- Smaller v1 scope. Three subprocesses, not four. No SDK-matrix maintenance burden. No per-language hook library to fuzz.
- `host.audit.v1` becomes available from day one — workloads have a first-class audit emission path on the same chain as system events.
- Threat surface reduced: no hostile-guest matrix for SDK bypass, no placeholder-egress backstop in gvproxy/passt, no cold-cache timing oracle defense.
- All the W1a–W1b.2b.3 hardening (subprocess scaffolds, UDS proxies, spawn lifecycle, binary integrity check, signed config envelope) is preserved — none of that work is wasted.
- Single forcing function (audit) is simpler to reason about than two competing ones (audit + secrets).

**Negative:**

- ADR-023's substantial design work is now historical — superseded but not deleted (kept for future reference if the question of mvm-managed credentials comes up again).
- Operators who *want* a managed-credential service have to look elsewhere. mvm's stance becomes: "bring your own secret material; mvm's job is to launch and audit the workload."
- The W1b.1 `mvm-secrets-dispatcher` crate (PR #480, already merged) gets deleted as dead code under the no-backcompat rule. Mechanical work but visible in git history as scaffold-then-removal.
- Claim 13 changes meaning between this rewrite and any external references to its prior form (none known in the wild as of 2026-05-28; project-internal references will be updated in the same PR sequence).

## Non-goals (additions over ADR-061)

- **No "BYOK" secret-delivery path** in mvm's name. Workloads use their own credential pipelines.
- **No drop-in `host.secrets.v2`** placeholder. If a future ADR brings secrets back, it gets a fresh design rather than picking up where ADR-023 left off.
- **No backwards-compat shim** for callers expecting `host.secrets.v1`. Per the no-backcompat rule, callers either don't exist (the service was never deployed) or get a `NotBound` envelope.
- **No `host.logging.v1` in this rescope.** That stays in the host-logging follow-on plan. `host.audit.v1` is specifically the audit-chain emission path, not general structured logging.

## Migration

- Mechanical: `cargo build --workspace` no longer compiles `mvm-secrets-dispatcher`; tests no longer exercise `secrets_proxy.rs`.
- `mvmctl doctor` no longer reports the secrets dispatcher's status.
- The four-subprocess Plan 104 W1b series (PRs #480, #481, #482, #483, #486) stays merged; the secrets-specific crate is removed in a follow-on PR (PR C of the rescope sequence).
- No data migration — the secrets service was never deployed, so no live workloads depend on it.

## See also

- [Plan 104 — host services broker](../plans/104-host-services-broker.md) §"Rescope (ADR-062)" — the spec changes that land alongside this ADR
- [threat model 02 — host services broker](../threat-models/02-host-services-broker.md) §"Per-service threat walk" — `SECRET-*` tables removed; new `AUDIT-*` tables added
- [ADR-023 — secret substitution mechanism](023-secrets-subsystem-egress-substitution.md) — superseded
- ADR-020 §"Consolidated from ADR-061" — host services broker — four-subprocess hardening — partially superseded (subprocess count reduced)


## Consolidated from ADR-084 — Host services as a per-tenant daemon, not per-VM spawn

- Status: Accepted
- Date: 2026-06-16
- Owner: MVM Project
- Related: ADR-020 (host services broker over vsock — this revises its process model), ADR-023 (TLS substitution mechanism), ADR-001 (microVM security posture — claims 12/13), ADR-014 (signed audited execution plans — claim 8), mvmd Plan 52 (host-services consumer, complete)
- Sequenced by: [Plan 202 — Host services daemon](../plans/202-host-services-daemon.md)

## Context

ADR-020 specified the host-services broker as an **in-process** listener inside the per-VM supervisor, with `host.secrets.v1` split into a dedicated subprocess. The implementation that actually shipped (the E5.3b-2 spawn stack) diverged: both the broker **and** the audit-signer became **per-VM detached subprocesses**, forked from `mvmctl up` via `mvm_backend::broker_services_spawn::spawn_broker_services_if_admitted` — one `mvm-broker` and one `mvm-audit-signer` `setsid` child per admitted VM, each binding a UDS, readiness-polled, then reaped on stop.

That model has two problems we hit grounding the first live in-guest `host.audit.v1` round-trip:

1. **It is fork-per-request at the wrong granularity.** `N` VMs cost `2N` host processes plus a fork/exec/bind/poll cycle on *every* boot. mvm tolerates that for one dev VM; `mvmd`, whose entire point is density (dozens–hundreds of microVMs per host), cannot. This is the CGI-fork antipattern where a resident daemon belongs.

2. **Availability got coupled to egress.** The broker only spawns when `up` threads `tenant_id` into the launch, and `up` only does that under `MVM_GATEWAY_BRIDGE=1` (`should_thread_signed_plan`). So on a normal admitted `mvmctl up`, `host.audit.v1` is silently absent — a workload's `emit` fails with a transport error for a reason that has nothing to do with audit. The gating signal is the egress bridge, which is the wrong axis entirely.

The moat that the two-process split exists to provide is real and must survive: the broker parses **untrusted guest frames** (the fuzzed surface, claim 5) and must never share an address space with the **host signing key** (claim 13 — no raw secret crosses the broker channel). But that is an *address-space* boundary between *two roles*; it does not require a process *per VM*. Two processes total satisfy it.

`mvmd` is the production consumer of this surface (its host-services work is open), and we want the same capability locally in `mvm`. Whatever process model we pick is the one `mvmd` inherits at fleet scale — so the decision has to be made for density now, not retrofitted later.

## Decision

Host services run as a **single host-agent daemon plus a supervised signer helper, scoped per tenant**. VMs **register with** the daemon at boot and **deregister** at teardown. There is no per-VM fork.

- **Host-agent daemon (per tenant)** — the one process a user runs (`mvmctl` is a thin client to it). **Keyless.** Owns VM lifecycle, admission orchestration, and **broker dispatch**: a control socket for register/deregister, dynamic binding of each registered VM's `BROKER_PORT` socket, demultiplexing accepted connections to a `vm_id` by *which socket accepted them*, and enforcement of the admitted plan's `services` bindings (claim 12) + the per-workload rate limit, both keyed by `vm_id`. It parses untrusted guest frames but holds no signing key.
- **Signer helper (per tenant)** — the **one separate address space**. Holds *all* of the tenant's signing keys (admission plan-signing **and** audit-chain signing) and is the single writer to every per-VM workload chain (`<tenant>.<vm>.workload.jsonl`), one in-memory chain head per `vm_id`. The host agent forwards each sign request — a plan to admit, or an accepted audit entry tagged with a **server-derived** `vm_id` (never guest-supplied) — for the helper to sign/route and stamp `category: workload_audit`. The host agent never holds a key, which is why one helper suffices.

Per tenant, that is **two processes regardless of VM count** — a user's many microVMs are *registrations* in the one daemon, not processes. Per host it is `O(active tenants)`, never `O(VMs)`. The helper is a privilege-separated child supervised by the host agent (the sshd model): the user runs and manages **one daemon**; the helper is invisible to them.

VM lifecycle becomes registration:

- **start** → `ensure_daemon(tenant)` (lazy, idempotent; warm after the first VM) → `Register { vm_id, broker_listen_socket, services_bindings, workload_chain_path }`. The per-VM supervisor splices the guest's `connect_host_vsock(BROKER_PORT)` to `broker_listen_socket` exactly as today — the backend-specific path is unchanged.
- **stop** → `Deregister { vm_id }` → the daemon unbinds and drops that VM's socket; the helper flushes and closes that VM's chain head.

Registration is driven by the **admitted plan**, not by `MVM_GATEWAY_BRIDGE`. A plan that binds no host services registers nothing — same zero-process outcome as today, but for the right reason. `host.audit.v1` is implicitly available to any admitted workload (emitting to your own chain is a low-risk, broadly useful capability); the catalog services (`time`, `cost`, secrets, future addons) require an explicit `ExecutionPlan.services` binding and are dispatch-gated on it.

### mvm and mvmd are one design

`mvm` without `mvmd` is a **single tenant** running many microVMs: one host-agent daemon + one signer helper, fixed, for the whole install — its VMs are registrations, not processes. `mvmd` is the **coordinator** that replicates that unit — one (host-agent + helper) per active tenant — and adds fleet orchestration, density, and cross-VM/cross-tenant arbitration. `mvmd` does not reimplement the daemon; it conducts per-tenant instances. Local `mvm` is therefore the literal single-tenant degenerate case of the fleet design: **mvm-daemon ⊂ mvmd**. Tenant separation under `mvmd` is detailed in [Tenant boundaries](#tenant-boundaries).

### Scope: per tenant

The host agent holds no secrets, so a single host-wide agent serving every tenant would be functionally sufficient. We reject it for **defense in depth** (detailed under [Tenant boundaries](#tenant-boundaries)): a parsing bug in a daemon that eats untrusted guest input must not be a cross-tenant boundary, and each tenant's signer helper holds that tenant's keys, which must not be reachable from another tenant's traffic. One (host-agent + helper) per tenant makes the process boundary the tenant boundary — one tenant for local `mvm`, one per *active* tenant for `mvmd`, bounded by tenancy not by fan-out.

## Architecture

### Identity is server-derived

`vm_id` for every dispatched call and every signed entry comes from the socket that accepted the connection, established at `Register` time — never from a field in the guest frame. This is the same discipline the broker already applies to `correlation_id` (the supervisor reassigns a server-authoritative id at ingress). A compromised guest therefore cannot address another VM's bindings or write another VM's chain, even within one shared broker process.

### Registration control plane

The daemons listen on a per-tenant control socket under the run dir (e.g. `<run>/broker-control-<tenant>.sock`, mode 0700, host-owned). `Register`/`Deregister` are signed by the host (the same host identity that signs plans), so a guest — which has no access to the control socket — cannot register or unbind sockets. The wire `ServiceCall`/`ServiceResponse` shape on `BROKER_PORT` is unchanged from ADR-020; only the *owner* of the per-VM socket moves from a per-VM fork to the resident daemon.

### Crash and restart

A resident per-tenant daemon has a larger blast radius than a per-VM child: its crash drops host services for every VM of that tenant. Mitigations:

- The daemon is **supervised** — by `mvm` locally and by `mvmd`'s host agent in the fleet — and restarted.
- Chain integrity survives restart: each per-VM head already persists out of band (the secondary head file), so the signer rebuilds heads from disk + the live registration set rather than forking the chain. A restart re-binds sockets for the still-registered VMs from the journal.
- This is the ordinary resident-daemon bargain (nix-daemon, containerd) and is the correct trade for `O(tenants)` instead of `O(VMs)` processes.

### Where broker dispatch lives — the host agent, not the VMM

Broker dispatch folds into the **host-agent daemon** (a host-side control process), not into the per-VM supervisor. Folding it into the supervisor was rejected: the supervisor is the VMM — already the largest, most-exposed TCB — and widening it with host-service dispatch is the wrong direction. The host agent is a separate host-side daemon, so it carries dispatch without touching the VMM's TCB; it stays keyless, with the signer helper as the only key-holding address space.

## Tenant boundaries

`mvmd` separates tenants in layers, strongest first. The host-services daemon model is defense in depth on top of the VM boundary, not the primary isolation.

1. **Hypervisor + jailer, per microVM — primary.** Each workload is its own guest (Firecracker + jailer on the fleet path) with its own kernel, seccomp, cgroups, and namespaces. ADR-001 holds: one guest = one tenant's workload; multi-tenant *inside* a guest is out of scope. Two tenants' VMs are isolated because they are separate jailed VMs — full stop.
2. **Host services — separation by replication.** `mvmd` runs one (host-agent daemon + signer helper) per tenant, so there is no shared mutable host-services state across tenants: separate **process** (a parser bug or crash in one tenant's daemon can't reach another's), separate **key** (each helper holds only its tenant's signing keys — it cannot sign as another tenant, and compromising it yields nothing of another's), separate **audit** (a tenant's chains are written only by its helper, signed by its key, verified against its pubkey). Within a tenant, cross-VM is blocked by the server-derived `vm_id`; a VM reaches only its own tenant's daemon because that daemon is the only one that binds its socket.
3. **`mvmd` is the cross-tenant arbiter — and in the TCB.** It assigns VMs to tenants, scopes each tenant's network/egress policy, and arbitrates cross-VM/cross-tenant requests under tenant-scoped authz. The orchestration-layer tenant boundary is exactly as strong as `mvmd`'s authz — `mvmd`'s to harden.

Two constraints make this real:

- **Per-tenant keys are required, not optional.** The key/audit boundaries mean nothing if tenants share one host key; each tenant's helper holds that tenant's signing key(s). Local single-tenant `mvm` is the degenerate case (one key, one helper).
- **The trust root is the host.** All tenants share one host and one hypervisor; a VM escape or host compromise defeats tenant isolation (ADR-001 trusts the hypervisor and puts a malicious host out of scope). Daemon-set replication contains *host-services-layer* faults to a tenant — it does not change the trust root.

## Security model

The claim-12 (binding-gated dispatch) and claim-13 (no raw secret over the broker channel) properties are **preserved unchanged** — this ADR moves *where the two roles live*, not *what they may do*:

- Two address spaces still separate the untrusted-input parser (the keyless host-agent daemon, which does broker dispatch) from the key holder (the signer helper). `2` per tenant instead of `2N`.
- `vm_id` and `correlation_id` remain server-authoritative — a guest cannot forge cross-VM identity, and the per-tenant process boundary blocks cross-tenant reach.
- The rate limit and the 4 KiB record cap stay host-side, now keyed by `vm_id` in the daemon's per-VM state.
- The signing key path stays pinned under the host key dir (the claim-8 trust boundary); the daemon model does not relax it.

### Surfaces that do not expand

The guest-facing wire (`ServiceCall` over `AuthenticatedFrame` on `BROKER_PORT`) is byte-identical to ADR-020. The new surface is the **host-side control socket** (Register/Deregister), reachable only by the host (mode 0700, host-signed messages), never by a guest. No new guest-reachable verb, port, or frame type.

## Alternatives considered

- **Per-VM subprocess (status quo).** Correct moat, wrong granularity: `2N` processes + per-boot spawn latency. Fails mvmd density. This ADR replaces it.
- **In-process broker in the supervisor (original ADR-020).** Avoids a separate broker process but puts guest-service dispatch in the VMM's address space and is still per-VM. Rejected for TCB and granularity reasons.
- **Single host-wide broker for all tenants.** Fewest processes, but a parsing bug becomes a cross-tenant boundary and one signer would hold every tenant's key. Rejected for tenant isolation; per-tenant is the chosen middle.
- **Lazy spawn on first guest dial.** Defers the cost but reintroduces per-VM processes and adds first-call latency inside the request path. The register-at-boot daemon gets the same "only when needed" property without per-VM processes.

## Consequences

### Positive

- Host-process count drops from `O(VMs)` to `O(active tenants)`; per-VM boot no longer pays a fork/exec/bind/poll cycle.
- `host.audit.v1` becomes available on a normal admitted `up`, decoupled from the egress bridge.
- One daemon + protocol is shared by `mvm` (local) and `mvmd` (fleet) — local is a single-tenant slice of production, not a different code path.
- The moat and all claim-12/13 properties are preserved.

### Negative

- Larger crash blast radius per tenant (mitigated by supervision + persisted heads + a registration journal).
- A registration control plane is new surface to implement, supervise, and reason about (host-only, host-signed).
- Revises a process model that just shipped; the per-VM spawn stack must be migrated, not extended.

## Migration

Phased in [Plan 202](../plans/202-host-services-daemon.md). The wire protocol on `BROKER_PORT` does not change, so guests, the SDK veneer, and the in-guest probe are untouched. The change is host-side: `spawn_broker_services_if_admitted` (fork) becomes `ensure_daemon` + `register_vm`, the host-agent daemon gains a control plane with the signer as a supervised helper, and `mvmd` adopts the same per-tenant daemon by replication.

## Out of scope

- The guest-facing wire format, the service catalog, and the capability-gating rules — all unchanged from ADR-020.
- Cross-VM / cross-tenant data delegation, which remains mvmd's tenant-scoped-authz responsibility (ADR-020 §Cross-VM delegation).
- The egress gateway bridge and its L4 policy enforcement — a separate axis that this ADR deliberately stops conflating with host-service availability.


## Consolidated from ADR-089 — Builder VM resident control plane

**Status:** Proposed
**Date:** 2026-06-19
**Relates to:** [ADR-004](004-sealed-signed-builder-image.md),
[ADR-007](007-vmbackend-single-trait.md),
[ADR-004](004-sealed-signed-builder-image.md),
[ADR-004](004-sealed-signed-builder-image.md),
[ADR-014](014-signed-audited-execution-plans.md),
[Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md),
[Plan 200](../plans/200-machine-ux-dx-layer.md),
[Plan 204](../plans/204-builder-vm-resident-control-plane.md), and
ADR-020 §"Consolidated from ADR-090" (its trust-gradient and residency complement)

## Context

mvm has two different execution surfaces that are easy to confuse:

- the host-facing product surface, currently `mvmctl`;
- the Linux builder environment, which owns Nix builds/evals and Linux-only
  microVM tooling.

Plan 199 intentionally made `mvmctl` installable as a host package without
changing the guest image API. That raised a design question: should the builder
VM be a passive target launched by the host CLI, or should it be a resident
service with its own control socket that receives build/eval commands?

The product goal is a simple local UX: users install one host binary, ask it to
run/build/manage machines, and do not need host Nix for normal use. At the same
time, the trust-boundary goal is that Nix and Linux-specific work stay inside
the project builder VM, not on the macOS host and not in an unrelated VM.

Today the builder path is closer to controlled job execution: the host CLI
starts or reuses a builder VM, bind-mounts source/output directories, and runs
bounded shell/Nix jobs inside it. That is workable, but it leaves too much of the
long-term contract implicit:

- the transport is not a first-class protocol;
- shell snippets are easier to widen accidentally than typed operations;
- progress, cancellation, provenance, and cache keys are harder to make uniform;
- users and contributors can infer that host Nix is part of the runtime model.

## Decision

mvm keeps `mvmctl` as the host-facing control plane, but moves builder execution
toward a resident builder VM service exposed over a typed vsock protocol.

The target architecture is:

```text
host
  mvmctl
    validates CLI / SDK input
    performs admission and local state bookkeeping
    starts or connects to the builder VM
    sends typed BuilderRequest messages over vsock

builder VM
  mvm-builderd
    owns Nix and the builder Nix store
    owns Linux-only build/eval/syscall work
    executes allowlisted operations
    streams structured progress and returns provenance/artifacts
```

The host does not need Nix for normal use. Host Nix remains an optional
expert-facing install frontend only, for example `nix build .#mvmctl` from a
source checkout. Normal runtime and build flows use host `mvmctl` plus the
builder VM.

`mvm-builderd` is an internal execution plane, not a new user-facing CLI.
Operators and SDKs continue to use `mvmctl`; the vsock protocol is the private
transport between the host control plane and the builder execution plane.

## Protocol boundary

The long-term builder protocol is typed and allowlisted. Examples:

- `Handshake`
- `Probe`
- `FlakeCheck`
- `BuildGuestImage`
- `BuildHostTool`
- `PrefetchSource`
- `QueryStorePath`
- `CancelJob`

Each request carries explicit inputs:

- workspace/source snapshot reference;
- operation kind and schema version;
- declared environment;
- expected output kind;
- cache key or fingerprint inputs when relevant;
- admission/provenance context when the result feeds a runtime path.

Responses are structured:

- progress events;
- log chunks with redaction posture;
- final store paths or copied artifact paths;
- provenance records;
- failure category and retryability;
- resource usage when available.

Generic "run this shell command in the builder VM" is not the stable API. A raw
shell escape may exist only as a gated development/debug fallback with explicit
audit/logging and no product dependency.

## Security and trust boundary

This ADR does not weaken the existing builder boundary:

- Nix builds/evals and Linux-only microVM operations stay inside the builder VM.
- The host does not gain a normal-use Nix dependency.
- The builder service executes an allowlist of operation types, not arbitrary
  caller-provided shell.
- Source snapshots and output paths are explicit inputs/outputs, so cache keys
  and provenance stay reviewable.
- The builder service does not become a guest image dependency. MicroVM guests do
  not install `mvmctl` or `mvm-builderd`.

The host `mvmctl` remains in the TCB as the local control plane. It validates
operator intent, owns local state, and mediates builder requests. The builder VM
is the Linux execution boundary for Nix and Linux-only tooling.

## Consequences

Positive:

- Simple UX: one host binary drives the system.
- Host Nix stays optional.
- Builder jobs become explicit, cancellable, observable operations.
- Progress reporting, provenance, cache behavior, and failure categories become
  uniform.
- The implementation can retire ad hoc shell snippets gradually without changing
  user commands.

Negative:

- Requires a new daemon binary, protocol, lifecycle management, and versioning.
- The resident builder service has a wider uptime/crash-recovery surface than
  one-shot shell jobs.
- Migration must preserve existing builder behavior while replacing internals in
  slices.

## Alternatives Considered

### Require host Nix

Rejected. It makes source-based usage convenient for Nix users, but it is the
wrong default product contract. Normal users should not need to install Nix on
the host to build or run mvm workloads.

### Make the builder VM the user-facing CLI surface

Rejected. It pushes users toward thinking about the builder VM as the product.
The product surface should stay one host command. The builder VM is an internal
execution boundary.

### Keep controlled shell jobs forever

Rejected as the final state. Controlled shell jobs are useful for bootstrapping,
but they are too broad as the permanent protocol. Typed operations make the
security boundary and user-facing behavior easier to test.

### Expose a generic remote shell over vsock

Rejected as the stable API. It would be flexible, but it would blur the boundary
between product operations and arbitrary builder mutation. Debug-only escape
hatches must stay gated, logged, and out of the normal UX.

## Migration

Plan 204 owns the migration. The intended sequence is:

1. Define the builder protocol and daemon lifecycle.
2. Implement `mvm-builderd` with health/probe and one low-risk build/eval
   operation.
3. Route existing builder jobs through a compatibility adapter.
4. Move Nix flake check, guest image build, and host-tool build operations to
   typed requests.
5. Retire normal-path raw shell execution.

No user command rename is required.


## Consolidated from ADR-090 — Resident-daemon trust gradient and builder residency model

**Status:** Proposed
**Date:** 2026-06-19
**Relates to:** [ADR-001](001-microvm-security-posture.md),
[ADR-007](007-vmbackend-single-trait.md),
[ADR-004](004-sealed-signed-builder-image.md),
ADR-020 §"Consolidated from ADR-084",
[ADR-001](001-microvm-security-posture.md) (consolidated from ADR-088),
ADR-020 §"Consolidated from ADR-089",
[Plan 118](../plans/118-supervisor-standby-pool-and-live-bench.md),
[Plan 152](../plans/152-rust-native-vz-and-init-lifecycle-parity.md),
[Plan 159](../plans/159-vz-inspired-macos-dx.md),
[Plan 196](../plans/196-warm-builder-store-kernel-cache.md),
[Plan 202](../plans/202-host-services-daemon.md),
[Plan 204](../plans/204-builder-vm-resident-control-plane.md), and
[Plan 205](../plans/205-resident-builder-control-plane.md)

## Context

The local product is meant to feel instant: a user types a command and a workload
runs. Today the worst latency is the per-session builder VM bring-up — the builder
boots (or rebuilds) at the start of a session before any useful work happens. Cold
acquisition on a fresh machine is the second worst. Both are felt every working day.

The instinct to fix this is "keep the builder VM running and let it be the daemon."
That instinct is correct in shape but dangerous if taken literally, because the word
*daemon* hides three very different processes with three very different trust levels:

- a host process that holds signing keys, admits signed `ExecutionPlan`s, and writes
  the chain-signed audit log;
- the builder VM process that owns Nix and produces artifacts;
- the in-guest agent that lives inside each workload microVM.

ADR-089 already decided that builder *execution* should move to a resident service
(`mvm-builderd`) behind a typed vsock protocol (Plan 204). Two questions it left open
are the source of the present design risk:

1. Should the builder VM be always-resident, or parked and resumed on demand? These
   were treated as competing strategies with opposite cost profiles.
2. What is the trust relationship among the three daemons, and what stops "make it
   instant" pressure from pushing authority (keys, admission) into the builder VM or
   fattening the workload agent — either of which would regress ADR-001?

ADR-001 is unambiguous that the host is the trusted computing base and the guest is
not. Any redesign that improves latency by relocating authority toward the guest is a
security regression, however fast it feels. This ADR fixes the trust relationship and
the residency model together so they cannot drift apart.

## Decision

Adopt a single coherent model with two parts: a **trust gradient over three daemon
classes**, and a **residency policy** that unifies "always-resident" and
"parked-and-resumed" as two settings of one mechanism rather than two code paths.

### 1. Three daemon classes on a trust gradient

There are exactly three long-lived process classes. Authority and resident weight
**decrease monotonically** as distance from the host increases:

| Layer | Daemon | Role | Authority | Trust tier |
|---|---|---|---|---|
| Host | control daemon | host-signer keys, plan admission, audit chain, pool + VM lifecycle | full | TCB (trusted) |
| Builder VM | builder daemon (`mvm-builderd`) | owns Nix + the builder store, runs allowlisted build/eval, resident | build-only | trusted-to-build, dev-tier |
| Workload microVM | guest agent | thin vsock RPC endpoint | none | untrusted |

The governing invariant:

> No daemon may hold authority that exceeds its trust tier, and a daemon farther from
> the host may never hold authority a closer one lacks. Signing keys, plan admission,
> and the audit chain never cross the host→builder vsock line.

Concretely:

- The host control daemon stays host-side and thin. For the local single-user case it
  is effectively one daemon; under the fleet it fans out **per tenant** (ADR-084 /
  Plan 202) so each tenant key sits behind its own process boundary. Collapsing tenants
  into one global key-holding daemon is forbidden — it would regress claims 12/13.
- The builder daemon is the resident service from ADR-089. It is the *only* daemon that
  may grow to host residency for performance, because building is its whole job and it
  is dev-tier (ADR-001, consolidated from ADR-088).
- The workload guest agent stays the runt by construction: prod builds strip `do_exec`
  (claim 4) and the console (claim 15), both `dev-shell`-gated. It must never acquire
  orchestration authority or hold secrets. Fattening it is the primary smell this ADR
  exists to forbid.

### 2. Residency policy: one slider, not two strategies

Builder-VM residency is a policy over the existing standby pool (Plan 118), expressed
as `min` warm instances plus an idle timeout — not two implementations.

```text
 Parked (snapshot on disk)  ◀── idle-timeout ──  Warm (resident)
   │   resume ≈ cold boot ───────────────────────────▶  │
 min=0: no idle RAM (resume-on-demand)     min≥1: no boot latency (always-resident)
```

- `min ≥ 1` keeps a builder warm: zero per-command boot latency. This is the
  "instant" path — no VM boot, only a control round-trip to the resident daemon.
- `min = 0` parks the builder as a snapshot (Plan 159 for Vz, Plan 175 for Firecracker)
  and resumes it on demand. The resume is a full guest-memory restore, so it costs about
  what a cold boot of the same closure does — single-digit seconds (~2.3 s measured for a
  512 MiB builder, 2026-06-13). `min = 0` trades resume latency for zero idle RAM; it is
  not a sub-second path, and the earlier "<100 ms" figure conflated the control-plane
  resume signal with the memory restore. Its bar is "no slower than a cold boot of the
  same closure," not "instant."
- The idle timeout demotes warm→parked; the next command promotes parked→warm.
- Each host picks a default (for example, an Apple-silicon dev box defaults warm; CI
  defaults parked). The mechanism is identical either way.

This is the unification the user asked for: "support both" is one pool with a knob, the
same pattern proven by comparable single-library microVM tools (separate privileged
worker, snapshot cold-restore, pool with min/idle — matching Plan 152's supervisor
split and Plan 159's snapshot/fork).

### 3. Residency introduces no claim regression

- The builder VM is dev-tier (ADR-001, consolidated from ADR-088), so snapshotting and resuming it requires no
  hardened kernel or verified boot and weakens no numbered claim.
- The security-sensitive case — claim-11 application-dependency volumes — stays safe
  because the sealed volume is content-addressed and **re-verified host-side at admit
  time** (`verify_sealed_volume`), independent of how the builder booted. A resumed
  builder cannot smuggle anything past host admission.
- The host→builder transport is the typed, allowlisted `BuilderRequest` protocol
  (Plan 204), not a shell. Making the builder resident therefore *shrinks* the attack
  surface relative to today's bind-mount-and-run-shell-jobs path.

## Security and trust boundary

This ADR does not weaken any existing boundary; it pins the relationships that keep
latency work from eroding them:

- Keys, admission, and audit remain host-side in the TCB at every residency setting.
- The builder daemon never receives signing keys or admission authority.
- The workload agent stays minimal and prod-stripped; the trust gradient is testable.
- Snapshot/resume applies only to the dev-tier builder VM, never to a workload's
  security posture, which is re-verified at admit time regardless of boot path.

## Consequences

Positive:

- The fast path (builds) and the trusted path (keys/admission/audit) are *different
  daemons*, so performance work and security stop trading against each other.
- "Always-on" vs "resume-on-demand" becomes a one-line policy, not a fork.
- The trust gradient becomes an explicit, lintable invariant rather than folklore.

Negative:

- A resident builder daemon has a wider uptime/crash-recovery surface than one-shot
  jobs (owned by Plan 204 / Plan 205).
- Snapshot freshness/invalidation must be tied to the builder fingerprint (Plan 195) so
  a stale parked builder is never resumed for changed inputs.
- The residency default per host is a support surface (RAM vs latency) that must be
  documented and overridable.

## Alternatives Considered

### Collapse the host control plane into the builder VM

Rejected. It is the literal reading of "let the daemon be the builder VM," but it moves
signing keys and admission into a Linux guest, directly inverting ADR-001. The builder
daemon may be resident; it may not be trusted with keys.

### One global host daemon holding every tenant's keys

Rejected. It looks like "a single host daemon," but it regresses the claim-12/13 moat
that ADR-084 / Plan 202 built. The model is one *logical* control plane with per-tenant
process isolation when multi-tenant; locally that already presents as a single daemon.

### Two separate modes for resident vs resume

Rejected. Divergent lifecycles drift and double the test surface. The standby-pool
`min`/idle knob expresses both with one mechanism.

### Keep the one-shot builder and only make boot faster

Rejected as the end state. It leaves the per-session boot (the top pain) in the hot
path. Residency removes the boot from the steady state instead of shortening it.

## Migration

Plan 205 owns execution and sits as the umbrella over Plans 118/152/159/196/202/204.
The sequence: codify the trust-gradient invariant and its structural test; add the
residency policy over the standby pool; make `mvm-builderd` resident across `mvmctl`
invocations (consuming Plan 204's protocol, not reimplementing it); wire snapshot
park/resume into the parked state; add the cold-acquisition snapshot-bake; document
"what runs where." No user command rename is required.

## Threat-model delta (residency landed)

The residency policy (Plan 205 WS-B) and parked-standby demotion (WS-D) are in the tree. This
section records why neither changes the trust boundary or weakens an ADR-001 claim:

- **Keys, admission, and audit stay host-side at every residency setting.** Residency only
  changes how warm the standby pool is kept and whether an idle standby is parked or reaped.
  The host control plane — signing keys, plan admission, the chain-signed audit log — is
  untouched. No claim 8 / 12 / 13 surface moves.
- **A parked standby is still admitted from content-addressed inputs.** A standby is a
  kernel + supervisor saved state carrying no workload; the workload is attached at claim time
  from the admitted, signed `ExecutionPlan` (claim 8) only after a compatibility check on
  `kernel_sha256` + image digest (`StandbyCompat`). A parked standby cannot be claimed for an
  incompatible image, and how long it sat parked changes nothing the admission path verifies.
- **Demotion is gated by the dev-tier saved-state shape (`is_saved_state()`, pid 0).** Parking
  applies only to a backend whose standby is already a captured saved state (the macOS managed
  backend); the live-process backend reaps to cold. No production workload's posture is
  snapshotted or resumed — the workload rootfs is dm-verity sealed (claim 3) and re-verified
  independent of the standby it was claimed from.
- **No new guest-reachable surface.** Residency is host-side pool bookkeeping (the reaper and
  the selection predicate). The guest wire is unchanged and the workload agent gains nothing.

Net: residency changes the builder/standby *lifecycle*, not the trust gradient. Claims 1–15
are unaffected, and `check-trust-gradient` continues to machine-check the gradient on every PR.

## Trust gradient ledger (consolidated from specs/claims/trust-gradient.md)

<!-- trust-gradient:begin -->
---
claim: trust-gradient
status: Shipped
gated_phrases: []
exempt_paths: []
---

# Trust gradient ledger

Machine-checked by `xtask check-trust-gradient`. Authority and resident weight
decrease monotonically host → builder → workload. No daemon may hold authority
below its tier; `signing-key`, `plan-admission`, and `audit-writer` never exist
below the host. All three daemon tiers are covered: the builder row joined once the
`mvm-builderd` binary existed.

| Tier | Layer | Daemon | Forbidden authorities | Witnesses |
| --- | --- | --- | --- | --- |
| 2 | host | control-daemon | (none — holds all authority) | fn:per_tenant_daemon_paths_are_isolated |
| 1 | builder | mvm-builderd | signing-key, plan-admission, audit-writer | ci:builderd-no-authority |
| 0 | workload | guest-agent | signing-key, plan-admission, audit-writer, do-exec, console | ci:prod-agent-no-authority, ci:prod-agent-runentry-contract, ci:prod-agent-no-console |
<!-- trust-gradient:end -->
