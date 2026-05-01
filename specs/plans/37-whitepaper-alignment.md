# MVM Whitepaper Implementation Plan — Section by Section

## Context

The V2 whitepaper (`specs/docs/whitepaper.md`) describes a target architecture; the prior gap analysis showed that `mvm` (the runtime/CLI half) has solid local-isolation primitives but is missing the load-bearing AI-native pieces: a typed `ExecutionPlan`, a real Zone B supervisor, L7 egress + PII redaction, tool-call mediation, attestation-gated key release, signed policy bundles, runtime artifact capture, and audit-binding to plan version. This plan walks the whitepaper section by section. For each section it states the **target invariant**, what's done, what to build, what to scaffold (stub now / fill later), and a verification handle. Items explicitly belonging to `mvmd` (fleet, releases, host lifecycle, placement, distribution) get a thin `mvm`-side scaffold (types, hooks, no orchestration logic) so that mvmd can land later without reshaping `mvm`.

The plan is sequenced for leverage: §3.3 (ExecutionPlan) and §7B (supervisor) are the unblockers; §15 (egress + PII) is the differentiator; §10 / §22 / §14 / §21 / §11 hang off those. Effort labels: **XS** ≤ ½ day · **S** 1–2 days · **M** 3–5 days · **L** > 1 sprint.

## Conventions used below

- New crate: `mvm-plan` for plan types, `mvm-policy` for policy bundles, `mvm-supervisor` for the Zone B daemon. Existing `mvm-security` keeps signing/verify primitives.
- **Scaffold** = land the type, the trait, the wire format, and a `Noop`/`Stub` impl that returns a typed error or pass-through. Real impl follows in a focused PR.
- File paths use the workspace layout: `crates/<crate>/src/...`.
- Every new public type gets `#[serde(deny_unknown_fields)]` and a serde-roundtrip test.

---

## §1 — The AI-Native Infrastructure Problem
**Target invariant:** runtime constrains what model-mediated workloads can access, execute, emit, persist.
- **Build:** nothing directly. This section is the framing the rest pays off.
- **Verify:** §15, §16, §22 invariant tests collectively prove this.

## §2 — AI-Native Threat Surfaces
**Target invariant:** every named surface (prompt-injection control flow, tool abuse, dynamic runtimes, model I/O as egress, supply chain) has a control in §15/§10/§7.
- **Build:** §2 is the threat model; map it into `specs/adrs/003-ai-native-threat-model.md` so each threat cites its enforcing section. **S**.
- **Scaffold:** none.
- **Verify:** ADR cross-references each `§N` control.

## §3 — System Overview

### §3.1 MVM Runtime Layer
**Target invariant:** `VmBackend` trait carries the execution contract; native backends include Firecracker, MicrovmNix, Apple Container; Lima/Incus/containerd are pluggable adapters.
- **Done:** `crates/mvm-runtime/src/vm/backend.rs` `AnyBackend` enum.
- **Build:** open the `VmBackend` trait for out-of-tree adapters (move dispatch into a registry `BackendRegistry::register(name, factory)`); ship a `LimaBackend` wrapper around the existing Lima dev-VM machinery to honor the §3.1 wording. **M**.
- **Scaffold:** `IncusBackend` and `ContainerdBackend` empty crates with `unimplemented!()` and a clear "compatibility tier" comment so the trait surface is exercised.
- **Verify:** `cargo test -p mvm-runtime backend::registry::roundtrip`; `mvmctl image fetch --backend lima` works.

### §3.2 mvmd Orchestration Layer (out of scope for `mvm`)
- **Scaffold only:** in `mvm-core` add `pub mod mvmd_iface { /* signed control-plane wire types */ }` so mvmd can depend on `mvm-core` without reshaping it. **S**.

### §3.3 Decorated Execution Plans — **CORNERSTONE**
**Target invariant:** every workload runs from a signed, typed `ExecutionPlan`; ad-hoc args are rejected outside dev mode.
- **Build:** new crate `mvm-plan` with:
  ```rust
  pub struct ExecutionPlan {
      pub plan_id: PlanId,                 // ULID
      pub plan_version: u32,
      pub tenant: TenantId,
      pub workload: WorkloadId,
      pub runtime_profile: RuntimeProfileRef,
      pub image: SignedImageRef,           // digest + cosign sig
      pub resources: Resources,            // cpus, mem, disk, timeouts
      pub network_policy: PolicyRef,
      pub fs_policy: FsPolicyRef,
      pub secrets: Vec<SecretBinding>,
      pub egress_policy: PolicyRef,        // L7 + PII rules
      pub tool_policy: PolicyRef,
      pub artifact_policy: ArtifactPolicy,
      pub audit_labels: BTreeMap<String,String>,
      pub key_rotation: KeyRotationSpec,
      pub attestation: AttestationRequirement,
      pub release_pin: Option<ReleasePin>,
      pub post_run: PostRunLifecycle,
  }
  ```
  Plus `SignedExecutionPlan = SignedEnvelope<ExecutionPlan>` reusing `mvm-security` Ed25519. `mvmctl run` keeps a `--dev` shortcut that synthesizes a local-only plan; everything else requires a signed plan via `--plan path/to/plan.signed.json` or stdin. **M**.
- **Scaffold:** all `*Ref`/`*Spec` types live in `mvm-plan` even when their resolvers (e.g. `PolicyResolver`) are `Noop` returning `Ok(Default)`.
- **Verify:** serde roundtrip; unsigned-plan rejection test; `mvmctl plan validate` CLI; integration test boots VM from a signed plan against a fixture key.

---

## §4 — Reference Architecture
**Target invariant:** the diagram is the code's organizing seam — orchestrator → plan → host pool → backend → sandbox → policy egress.
- **Build:** wire the `ExecutionPlan` from §3.3 through `mvmctl up`/`run` so the call graph mirrors the diagram (Plan → BackendSelector → Supervisor::launch → Sandbox → EgressProxy). **S** once §3.3, §7, §15 land.
- **Verify:** new doctest `crates/mvm-plan/examples/lifecycle.rs` runs the diagram end-to-end on the dev backend.

---

## §5 — What MVM Enforces
**Target invariant:** the table is a rubric; each row maps to a runtime check.
- **Build:** create `crates/mvm-runtime/src/enforce.rs` with one function per row (`enforce_image`, `enforce_plan`, `enforce_runtime`, `enforce_tenant`, `enforce_egress`, `enforce_keys`, `enforce_artifacts`, `enforce_audit`). Each is invoked from `Supervisor::launch` in declared order. **S** scaffold; **M** to fill.
- **Verify:** `cargo test -p mvm-runtime enforce::table_complete` asserts all 8 rows are wired.

---

## §6 — Security Invariants
**Target invariant:** 8 invariants (no raw exec, no unsigned identity, no ambient creds, no bypass egress, no unscoped tenant state, no silent release mutation, no unmanaged host, no unaudited control mutation) are CI-enforced, not aspirational.
- **Done:** ADR-002's 7 claims (W1–W5).
- **Build:** extend `.github/workflows/security.yml` with one job per invariant where missing — specifically:
  - `no-raw-exec`: build mvmctl with feature `prod` and assert `cmd_run_raw` is gated by `cfg(feature = "dev")`. **S**.
  - `no-bypass-egress`: spawn a fixture VM, attempt direct outbound socket, expect blocked. **M** (depends on §15).
  - `no-unaudited-mutation`: integration test that every state-changing CLI verb emits an `AuditEntry`. **S**.
- **Verify:** all 8 jobs green on PR.

---

## §7 — Trust Zones

### §7A — Bootstrap & Key Entry
**Target invariant:** a measured init verifies image, performs attestation handoff, unseals the minimum key set, hands off to Zone B.
- **Done:** `nix/lib/minimal-init/default.nix` (mounts, virtiofs, setpriv, post-restore signals); W3 dm-verity (rootfs integrity + roothash on cmdline).
- **Build:**
  - Add `measure-and-handoff` step to minimal-init that: reads kernel cmdline `mvm.measurement=<sha256>`, writes it to `/run/mvm/measurement`, and refuses to start Zone B if absent. **S**.
  - Initial key exchange: write a `boot_token` (per-boot ephemeral key) to a tmpfs path readable only by the supervisor uid. **S**.
- **Scaffold:** `attestation_handoff` calls `NoopAttestationProvider::collect_evidence` and stashes it for §14.
- **Verify:** `tests/init_measurement.rs` boots a fixture VM and asserts `/run/mvm/measurement` exists and matches.

### §7B — Runtime Supervisor & Policy Plane — **CORNERSTONE**
**Target invariant:** a single trusted host-side process owns egress proxy, tool gate, key release, audit signing, artifact capture. Tenant code never runs in Zone B.
- **Build:** new crate `mvm-supervisor` shipping a `mvm-supervisor` daemon binary. Owns:
  - `EgressProxy` (§15)
  - `ToolGate` (§2.2/§15) wired to vsock RPC
  - `KeystoreReleaser` (§12.2)
  - `AuditSigner` (§22)
  - `ArtifactCollector` (§21)
  - Plan execution state machine (`Pending → Verified → Launched → Running → Stopping → Stopped`)
  - systemd unit + launchd plist (Linux + macOS dev-host).
  IPC: vsock to guest, Unix domain socket to `mvmctl`. **L** (this is the single biggest piece — but every sub-component is independently scaffolded below).
- **Scaffold:** start by lifting existing `mvm-hostd` into `mvm-supervisor`; sub-components import from `mvm-runtime/src/security/*` rather than rewriting.
- **Verify:** `mvmctl supervisor status` shows owner of each policy slot; integration test asserts a workload cannot reach the host network when supervisor is offline (fail-closed).

### §7C — Tenant Workload Sandbox
**Target invariant:** sandbox only has vsock to supervisor; no raw network, no host-fs beyond declared shares.
- **Done:** Firecracker microVM, seccomp standard, setpriv no-new-privs, ro-bind nsswitch, dm-verity rootfs.
- **Build:** lock down vsock host-side allowlist to *only* the ports defined in `mvm_guest::vsock` constants and the supervisor port. Reject other ports at the host vsock proxy. **S** — partly W1.3 already.
- **Verify:** `tests/vsock_port_allowlist.rs` opens an out-of-range port from inside the VM, expects EACCES at the host proxy.

---

## §8 — Control vs Sandbox Data Plane Separation
**Target invariant:** control commands and sandbox traffic share vsock as a transport but are architecturally distinct channels; tenant cannot mutate control state via data plane.
- **Build:**
  - Split vsock ports into two named ranges in code: `CONTROL_PORTS` (52, 53) and `DATA_PORTS` (10000+, 20000+). Document in `crates/mvm-guest/src/vsock.rs` doc-comment. **XS**.
  - Add a `PlaneId::{Control,Data}` enum on every `AuthenticatedFrame`; supervisor refuses control verbs received over data plane. **S**.
- **Verify:** fuzz target `vsock_plane_confusion` (extend existing fuzz) tries to cross planes; expect rejection.

---

## §9 — Runtime Backend Model
**Target invariant:** one workload contract across backends; backend-specific isolation/attestation tiers recorded in plan.
- **Build:** `BackendCapabilities { isolation_tier: u8, supports_attestation: bool, supports_snapshot: bool, supports_vsock: bool }` returned by `VmBackend::capabilities()`. `Supervisor::launch` checks plan `attestation` requirement against caps and refuses incompatible launches. **S**.
- **Verify:** unit test refuses TDX-required plan on Apple Container backend.

---

## §10 — Signed Images and Policy Bundles
**Target invariant:** every executable artifact (image, kernel, policy bundle) is signed and verified at admission.
- **Done:** dev image + builder image cosign manifest (plan 36 PR-C.1/C.2).
- **Build:**
  - Sign **catalog entries**: extend `crates/mvm-core/src/catalog.rs` `CatalogEntry` with `signature: CosignSignature` and verify in `mvmctl image fetch`. **S**.
  - Sign **kernel** as a separate artifact in the manifest (today it's hashed only). **S**.
  - **PolicyBundle** type + signing (new crate `mvm-policy`):
    ```rust
    pub struct PolicyBundle {
        pub bundle_id: PolicyId,
        pub bundle_version: u32,
        pub network: NetworkPolicy,
        pub egress: EgressPolicy,         // §15 rules
        pub pii: PiiPolicy,                // §15.1 rules
        pub tool: ToolPolicy,              // §2.2 allowlist
        pub artifact: ArtifactPolicy,
        pub keys: KeyPolicy,
        pub audit: AuditPolicy,
        pub tenant_overlays: BTreeMap<TenantId, TenantOverlay>,
    }
    ```
  - Sign with same Ed25519 / cosign primitives. `mvmctl policy sign|verify|inspect`. **M**.
  - **Revocation list** wiring: today scaffolded but unused; add periodic refresh via `mvm-supervisor` (fetch URL configurable, cache 1h, fail-open with audit warning if unreachable for >24h). **S**.
- **Scaffold:** `PolicyBundle` lives in `mvm-policy` even when sub-policies are minimal (e.g. `PiiPolicy::Disabled`); shape ships before substance.
- **Verify:** golden-bundle test; tampered-bundle rejection; `mvmctl policy inspect` shows decoded fields.

---

## §11 — Release Safety and Runtime Change Management
**Target invariant:** runtime changes (image, profile, policy, keys, artifacts, trust tier) are coordinated and rollback-capable.
- **mvmd-side:** staged rollout, canary, host draining, workload migration, load-aware distribution.
- **mvm-side build:**
  - `ReleasePin` type in plan: `{release_id, image_digest, policy_digest, runtime_profile_digest}`. Supervisor refuses to launch a plan whose live policy/image diverges from pin. **S**.
  - Two-slot rollback for policy bundles: supervisor keeps `current` and `previous`; `mvmctl policy rollback` flips. **S**.
- **Scaffold:** `ReleasePromotion` wire-types under `mvm_core::mvmd_iface` so mvmd can drive promotions later.
- **Verify:** test plan with mismatched pin is rejected; rollback flips back to previous policy and emits audit.

---

## §12 — Key Management and Rotation

### §12.1 Control-Layer Keys (mvmd)
- **Scaffold only:** define `ControlKey { kid, role, expiry }` in `mvm_core::mvmd_iface`. **XS**.

### §12.2 Workload Secrets — **MVM-OWNED**
**Target invariant:** secret released only to the run authorized by plan + (optionally) attestation; rotated on restart; revocable on stop.
- **Done:** `EnvKeyProvider`, `FileKeyProvider`, AES-256-XTS volume encryption, snapshot crypto, Zeroizing buffers.
- **Build:**
  - `KeystoreReleaser` (lives in `mvm-supervisor`) takes `(Plan, AttestationReport)` → `Vec<SecretGrant>`; refuses if attestation requirement unmet. **M**.
  - **Per-run grant**: every grant has `grant_id`, `secret_ref`, `release_at`, `expires_at`; supervisor revokes on plan stop/fail. **S**.
  - **Rotation on restart**: `KeyRotationSpec::OnRestart` causes supervisor to mint fresh credentials and inject via vsock secret-channel, rather than reuse. **S**.
- **Verify:** test that stopping a plan revokes outstanding grants; restart with `OnRestart` produces different `grant_id`.

### §12.3 Audit and Key Events
- **Build:** `AuditAction::SecretGranted | SecretRevoked | RotationOccurred` with `grant_id`, `key_version`, `policy_version`, `attestation_evidence_hash`. Wired into §22 audit signing. **S**.
- **Verify:** golden audit fixture covers every key-event action.

---

## §13 — Control Plane Compromise Model
- **mvmd-side:** mostly. `mvm`-side scaffolds:
  - `mvmctl quarantine <workload>` — supervisor freezes a running workload (pause Firecracker vCPU + drain egress). **S**.
  - `mvmctl host revoke` (local: marks host ineligible, drops admission keys). **S**.
- **Verify:** quarantined workload cannot egress and cannot make tool calls; audit records the transition.

---

## §14 — Attestation and Confidential Runtime Support
**Target invariant:** key release gated on attestation report when plan requires; SEV-SNP/TDX/TPM2 are pluggable providers.
- **Done:** `AttestationProvider` trait + `NoopAttestationProvider`.
- **Build:**
  - **Wire the gate now** (with Noop): `KeystoreReleaser::release` calls `provider.collect_evidence()` and `verifier.verify(report, plan.attestation)`; on failure emits `AttestationFailed` audit and refuses release. **S**.
  - `AttestationRequirement` in `ExecutionPlan`: `None | Measured { measurement: [u8;32] } | Confidential { vendor: Vendor, min_tcb: TcbLevel }`. **XS**.
  - **TPM2 provider** (Linux hosts with `/dev/tpm0`): real impl, smallest of the three. **M**.
- **Scaffold:** `SevSnpProvider`, `TdxProvider` crates with `fn collect_evidence` returning `AttestationError::Unsupported` until hardware is available.
- **Verify:** plan with `Confidential` requirement on Noop-only host is refused; TPM2-required plan succeeds on TPM2 host.

---

## §15 — Unbypassable Egress, PII, Exploit Controls — **CORNERSTONE / DIFFERENTIATOR**
**Target invariant:** all outbound from the sandbox passes through a host-side mediator the workload cannot bypass.
- **Done:** L3 iptables presets in `crates/mvm-core/src/policy/network_policy.rs`; L7 stub in `egress_proxy.rs`.
- **Build (plan 34 expanded):**
  - **Network plumbing**: sandbox has no default route; only route is to TAP IP of supervisor. Supervisor runs an L7 proxy (mitmdump-style or in-process Rust hyper proxy) on that IP. **M**.
  - **Egress decisions** (`EgressPolicy`): destination allow/deny, protocol normalization (HTTP/1.1 → HTTP/2 unification for inspection), TLS SNI + Host header inspection (CONNECT proxying with SNI lookup), DNS pinning (resolve once at admission, refuse mid-flight DNS changes). **M**.
  - **Request inspection hooks**: `RequestInspector` trait — order: SecretsScanner → SsrfGuard → InjectionGuard → AiProviderRouter → PiiRedactor (§15.1) → DestinationPolicy. Each returns `Inspect::{Allow, Transform(req'), Block(reason), Quarantine}`. **M**.
  - **Response inspection** (where policy requires it): same trait shape on the response side; default off for cost. **S**.
  - **Audit**: every decision (allow/transform/block/quarantine) emits an audit entry with destination, policy_version, action, reason. **S**.

### §15.1 AI-Provider PII Redaction — **DIFFERENTIATOR**
**Target invariant:** when plan declares an AI-provider call, request bodies are inspected and PII redacted/masked/tokenized/blocked/quarantined per `PiiPolicy` before forwarding.
- **Build:**
  - **AiProviderRouter**: pattern-matches on host (api.openai.com, api.anthropic.com, …) → marks request as `Provider(p)`; otherwise normal egress. **S**.
  - **PiiRedactor**: regex + dictionary detector for PERSON, EMAIL, PHONE, ACCOUNT_ID, IP, US_SSN, CREDIT_CARD; ships a v0 with conservative regexes and a clear extension trait `Detector`. **M**.
  - **Actions**: `Redact("[PERSON_1]")`, `Mask(shape-preserving)`, `Tokenize(reversible via supervisor-held key)`, `Block`, `Quarantine(disk path + audit)`. **M**.
  - **Reversible tokenization**: HMAC(secret, span) → token; supervisor stores reverse map per `plan_id`, expires with plan. Used for authorized post-processing paths. **M**.
- **Verify:** golden-prompt fixtures (`tests/pii_redaction/cases/*.json`) covering each detector × each action; assert §15.1's exact whitepaper example produces the redacted form shown.

- **Scaffold:** start with **detect-only mode** (`PiiPolicy::DetectOnly` emits audit but doesn't transform) so this can ship safely before transform actions are tuned.

---

## §16 — Multi-Tenant Isolation

### §16.1 Compute
- **Done:** per-VM cgroups, Firecracker resource caps.
- **Build:** plan-driven `Resources` enforcement at admission (refuse oversubscribed plans). **XS**.

### §16.2 Network
- **Build:** **per-tenant network namespace** on the host (`netns mvm-tenant-<tid>`); supervisor TAP devices bound to tenant netns; cross-tenant traffic dropped at netns boundary. **M**.

### §16.3 Storage
- **Done:** per-tenant directories, snapshot path-traversal guard.
- **Build:** **encryption-at-rest per tenant**: tenant DEK derived from supervisor master key + `tenant_id`; volumes/snapshots encrypted with per-tenant DEK. **M**.

### §16.4 Secrets
- Covered by §12.2.

### §16.5 Audit
- **Build:** per-tenant audit stream `~/.local/state/mvm/audit/<tenant_id>.jsonl`; supervisor fans out by `audit_entry.tenant`. **S**.
- **Verify:** fixture with two tenants → two streams, no cross-leaks.

---

## §17 — Host Lifecycle and Infrastructure Handling (mvmd)

### §17.1 Wake/Sleep
- **mvm-side:** snapshot suspend/restore exists for Firecracker (KVM-only — vsock snapshot fails on macOS/QEMU; documented).
- **Build:** `mvmctl wake|sleep` thin verbs that drive `Supervisor::suspend / resume` for a single workload (orchestration decisions live in mvmd). **S**.
- **Scaffold:** `HostInventory` wire-types in `mvm_core::mvmd_iface` (registration, capacity, draining) — empty impls.

---

## §18 — Policy Lifecycle

### §18.1 Emergency Deny Rules
**Target invariant:** signed policy updates can land hot without a release.
- **Build:**
  - `mvmctl policy apply <signed-bundle>`: supervisor verifies, two-slot swap (current/previous), emits audit. **S** once §10 PolicyBundle exists.
  - `EmergencyDenyRule { destinations[], tools[], workload_classes[], expires_at }` as a typed sub-policy that supersedes normal allow rules. **S**.
- **Verify:** apply test bundle that denies `evil.com`; ensure live workload's egress to that host fails immediately.

---

## §19 — Data Classification and Residency
**Target invariant:** plan declares data class; supervisor refuses launch if host's trust tier doesn't satisfy.
- **Build:** `DataClass::{Public, Private, Confidential, Regulated}` field on plan; `HostTrustTier` value reported by `mvmctl security status`; admission check. **S**.
- **Scaffold:** routing decisions across hosts are mvmd's job; `mvm` only enforces locally.
- **Verify:** plan with `Regulated` class refused on `Public` host.

---

## §20 — Unified Edge and Hosted Execution
**Target invariant:** same plan format runs locally, edge, hosted; backend differs, contract doesn't.
- **Build:** validate by running the §3.3 fixture plan on every backend in CI (matrix over Firecracker, Apple Container, MicrovmNix). **S** harness.
- **Verify:** `tests/cross_backend_plan.rs` matrix.

---

## §21 — Artifact Lifecycle
**Target invariant:** workload outputs are governed (retention, expiry, encryption, access, audit) — not stdout-then-destroy.
- **Done:** build-revision symlinks (`crates/mvm-runtime/src/vm/pool/artifacts.rs`).
- **Build:**
  - **Capture path**: virtiofs mount `/artifacts` inside guest, owned by supervisor on host. Or vsock channel `ARTIFACT_PORT = 54` for streaming. Pick virtiofs (simpler). **M**.
  - **`ArtifactPolicy`** in plan: `{retention: Duration, expiry: SystemTime, encryption: EncryptionSpec, signing: bool, access: AccessControl}`. **S**.
  - **`ArtifactCollector`** in supervisor: on workload exit, seal `/artifacts/*` per policy → encrypted store at `~/.local/share/mvm/artifacts/<plan_id>/`; emit `ArtifactCaptured` audit. **M**.
  - **`mvmctl artifact list|fetch|expire`**. **S**.
- **Verify:** test plan writes `/artifacts/report.txt`; on stop, file appears encrypted in store; fetch decrypts; expire removes.

---

## §22 — Runtime Observability and Audit
**Target invariant:** audit answers who/which-tenant/which-image/which-release/which-policy/which-host/what-keys/what-egress/what-artifacts/lifecycle, signed and tamper-evident.
- **Done:** `LocalAuditLog` JSONL with rotation; `AuditAction` enum.
- **Build:**
  - **Bind audit to plan**: every `AuditEntry` gets `plan_id`, `plan_version`, `policy_version`, `image_measurement`, `release_pin` (when present). **S**.
  - **Sign audit chain**: each line includes `prev_hash` + Ed25519 signature with supervisor's audit key; `mvmctl audit verify` walks the chain. **M**.
  - **Per-tenant streams** (§16.5).
  - **Export interface**: `mvmctl audit export --since <ts> --tenant <tid>` writes a signed bundle (NDJSON + manifest). **S**.
- **Verify:** mutate one line → verify fails; full chain on golden fixture verifies.

---

## §23 — Failure and Recovery
**Target invariant:** every named failure has a typed recovery action and an audit trail.
- **Build:**
  - `RecoveryAction` enum in supervisor matching whitepaper's table rows (workload crash, host crash, mvmd restart, release fail, key rotation fail, policy distribution fail, artifact upload fail, attestation fail, stuck sleep/wake, overload). **S** scaffold.
  - For each: a state-machine transition + audit event. Many are mvmd's job; `mvm`-side implements the local subset (workload crash, artifact upload fail, attestation fail, stuck sleep/wake). **M**.
- **Verify:** chaos test forces each local failure; assert recovery + audit.

---

## §24 — Threat-to-Control Mapping
- **Build:** generate `specs/threat-control-matrix.md` from a structured source (e.g. `crates/mvm-core/threats.toml`) and assert in CI that every row in §24 has a corresponding control with a citation. **S**.
- **Verify:** CI doc-gen check.

---

## §25 — Integration Surface
**Target invariant:** `mvm` exposes CLI, local API, SDK hook, backend adapter, image/policy registry, secret manager, artifact handoff, audit export, policy authoring, host registration hook.
- **Done:** CLI is strong.
- **Build:**
  - **Local HTTP API** (`mvm-supervisor` listens on Unix socket): `POST /plans`, `GET /workloads`, `GET /audit`, `POST /artifacts/:id/fetch`. Mirrors CLI verbs. **M**.
  - **Rust SDK crate `mvm-sdk`**: thin async client of the above for workflow engines. **S**.
  - **Policy authoring**: `mvmctl policy new|sign|inspect|apply` (covered in §10/§18). **S**.
  - **Secret manager bridge**: `SecretProvider` trait with `EnvProvider`, `FileProvider` (have); `VaultProvider`, `AwsSmProvider`, `GcpSmProvider` scaffold crates. **M** scaffold; real impls follow demand.
  - **Artifact handoff**: covered §21.
  - **Audit export**: covered §22.
- **Verify:** `mvmctl plan submit` and `curl --unix-socket` paths produce identical workload state.

---

## §26 — Operating Modes
- **Build:** `OperatingMode::{LocalDevelopment, HostedStandard, HostedConfidential, EdgePrivate, BuildArtifact, WorkflowRuntime}` on host config; supervisor refuses plans whose attestation/data-class requirements exceed mode capabilities. **S**.
- **Verify:** matrix test.

---

## §27 — Workload Lifecycle
- **Build:** the lifecycle steps map 1:1 onto supervisor states from §7B. Add a `mvmctl workload trace <plan_id>` that prints the full transition history from audit. **S**.
- **Verify:** lifecycle integration test asserts every step appears in the trace.

---

## §28 — How MVM Differs from Common Alternatives
- No code — but ensure containerd backend (§3.1) ships with a clear "compatibility tier, weaker isolation, not for tenant code" warning so the §28 prose holds. **XS**.

## §29 — Where MVM Fits
- No code. **0**.

## Conclusion
- No code. The conclusion's ten-verb refrain ("Run / Isolate / Enforce / Rotate / Govern / Audit / Release / Sleep / Wake / Manage") becomes the column header of the §5 enforcement table once everything above lands.

---

## Sequencing — wave plan

Each wave assumes prior waves merged. Effort sums are per wave.

### Wave 0 — Documentation truth fixes (XS, **prereq**)
- Soften §3.1 backend list, §14 hardware claims, §15.1 PII as design intent until built.
- Update CLAUDE.md / MEMORY.md: W3 dm-verity is **shipped**.
- File: `specs/docs/whitepaper.md`, `CLAUDE.md`, `~/.claude/projects/.../memory/`.

### Wave 1 — Foundation (S+M, **unblocks everything**)
1. `mvm-plan` crate + `ExecutionPlan` + signed envelope (§3.3).
2. `mvm-policy` crate + `PolicyBundle` + signing (§10, §18).
3. Lift `mvm-hostd` → `mvm-supervisor` skeleton (§7B).
4. `Supervisor::launch(plan)` happy path on Firecracker backend.
5. Audit binds to plan/policy/image (§22 partial).

### Wave 2 — Differentiator (M, **the AI-native value prop**)
6. L7 egress proxy in supervisor (§15).
7. Inspector chain: SecretsScanner, SsrfGuard, InjectionGuard, DestinationPolicy.
8. AiProviderRouter + PiiRedactor (detect-only first, then transforms) (§15.1).
9. Tool-call vsock RPC + ToolGate wired (§2.2).

### Wave 3 — Identity & artifact closure (M)
10. Attestation key-release gate with TPM2 provider (§14, §12.2).
11. Per-run secret grants + revoke-on-stop (§12.2).
12. Audit chain signing + per-tenant streams + export (§22).
13. Artifact capture path (virtiofs `/artifacts` + ArtifactCollector) (§21).

### Wave 4 — Multi-tenant + release (M)
14. Per-tenant netns (§16.2), per-tenant DEK (§16.3).
15. ReleasePin admission + two-slot policy rollback (§11, §18.1).
16. DataClass admission gate (§19).

### Wave 5 — Surface & ergonomics (S+M)
17. Local HTTP API on supervisor Unix socket (§25).
18. `mvm-sdk` crate (§25).
19. Cross-backend CI matrix on the §3.3 fixture plan (§20).
20. Threat-control matrix CI generator (§24).

### Wave 6 — Confidential & adapters (L, optional)
21. SEV-SNP, TDX provider real impls (§14).
22. Lima/Incus/containerd adapters (§3.1).
23. Vault / AWS SM / GCP SM secret providers (§25).

---

## Critical files (target paths)

- `crates/mvm-plan/src/lib.rs` — `ExecutionPlan`, `SignedExecutionPlan`, `*Ref`/`*Spec` types.
- `crates/mvm-policy/src/lib.rs` — `PolicyBundle`, `EgressPolicy`, `PiiPolicy`, `ToolPolicy`, `ArtifactPolicy`, `KeyPolicy`, `AuditPolicy`, `EmergencyDenyRule`.
- `crates/mvm-supervisor/src/main.rs`, `crates/mvm-supervisor/src/{egress, tool_gate, keystore, audit, artifact, state}.rs`.
- `crates/mvm-runtime/src/vm/backend.rs` — open `BackendRegistry`.
- `crates/mvm-runtime/src/security/attestation.rs` — gate caller; new `tpm2.rs`, `sev_snp.rs`, `tdx.rs` modules.
- `crates/mvm-core/src/mvmd_iface.rs` — wire types for orchestration boundary.
- `crates/mvm-core/src/policy/audit.rs` — extend `AuditEntry`, add chain-signing.
- `crates/mvm-cli/src/commands.rs` — new verbs: `plan`, `policy`, `supervisor`, `artifact`, `quarantine`, `wake`, `sleep`.
- `crates/mvm-sdk/src/lib.rs` — Rust client for the supervisor HTTP API.
- `nix/lib/minimal-init/default.nix` — measurement read + boot_token write.
- `.github/workflows/security.yml` — invariant jobs from §6.
- `specs/threat-control-matrix.md` (generated) and `crates/mvm-core/threats.toml` (source).

---

## Verification appendix

End-to-end checks (run after each wave):

```bash
# Wave 1
cargo test -p mvm-plan        # roundtrip + signature
cargo test -p mvm-policy      # roundtrip + signature
cargo test -p mvm-supervisor  # state machine
mvmctl plan validate fixtures/plan.signed.json
mvmctl up --plan fixtures/plan.signed.json   # boots, audit shows plan_id

# Wave 2
mvmctl up --plan fixtures/agent-plan.signed.json
# inside guest:
curl -s https://api.openai.com/v1/test       # must traverse proxy
mvmctl audit tail --since 5m | grep PiiRedacted

# Wave 3
mvmctl audit verify                          # chain signature ok
mvmctl artifact list --plan <plan_id>        # captured outputs
# stop plan; assert grants revoked:
mvmctl audit tail | grep SecretRevoked

# Wave 4
# launch plan with DataClass=Regulated on host without confidential tier:
mvmctl up --plan fixtures/regulated-plan.signed.json   # rejected with audit
mvmctl policy apply fixtures/emergency-deny.signed.json
# assert running workload's egress to denied destination immediately fails

# Wave 5
curl --unix-socket /run/mvm/supervisor.sock http://x/workloads
cargo test -p mvm-sdk
cargo test --test cross_backend_plan        # matrix
```

CI gates added across waves:

- `no-raw-exec`, `no-bypass-egress`, `no-unaudited-mutation` (§6)
- `policy-bundle-signed-roundtrip` (§10)
- `pii-golden-cases` (§15.1)
- `audit-chain-verifies` (§22)
- `threat-control-matrix-complete` (§24)
- `cross-backend-plan-matrix` (§20)

---

## What this plan **does not** build

- mvmd: fleet placement, releases/canary/rollout, host registration, cross-host wake/sleep, policy distribution, control-layer key rotation.
- Hardware-attested vendor trust roots beyond TPM2 in the first pass.
- A vendor-specific PII detector beyond regex/dictionary v0.
- Workflow-engine specific SDKs beyond the generic `mvm-sdk`.

These are intentional out-of-scope items; the plan provides typed scaffolds (`mvm_core::mvmd_iface`, `AttestationProvider` registry, `SecretProvider` registry) so they can land without reshaping `mvm`.

---

## Addendum A — ADR-004: PII redaction lives in `mvm`, not `mvmd`

When this plan executes, create `specs/adrs/004-pii-redaction-in-mvm.md` with the content below. (Cannot create it now — plan mode permits only the plan file.)

### File to create: `specs/adrs/004-pii-redaction-in-mvm.md`

```markdown
# ADR-004: PII Redaction Lives in `mvm`, Not `mvmd`

- Status: Accepted
- Date: 2026-04-30
- Deciders: Ari + future contributors
- Related: whitepaper §8, §13, §15, §15.1, §18, §19; ADR-002 (microvm security posture)

## Context

The whitepaper §15.1 describes inspecting and redacting PII in
AI-provider requests *before* they leave the system. That
inspection must happen somewhere. Two natural homes exist in the
two-tier architecture:

1. `mvm` — the per-host runtime that owns the L7 egress proxy
   between the sandbox and the network.
2. `mvmd` — the orchestrator that authors and distributes policy
   bundles, manages tenants, and aggregates audit.

This ADR records the decision and rationale for placing the
redaction *engine* in `mvm` (the supervisor's L7 proxy chain),
while keeping policy *authoring*, *signing*, *distribution*, and
*fleet aggregation* in `mvmd`.

## Decision

The PII redaction engine, the detector chain (PERSON, EMAIL,
PHONE, ACCOUNT_ID, IP, US_SSN, CREDIT_CARD, plus extensible
`Detector` trait), and the action pipeline (redact / mask /
tokenize / block / quarantine) live in `mvm` —
specifically in `mvm-supervisor`'s L7 egress proxy inspector
chain (`PiiRedactor`, see plan §15.1 / Wave 2).

`mvm-policy::PiiPolicy` is the bundle shape. Bundles are signed
artifacts. They may be authored anywhere — by `mvmd`, by hand
via `mvmctl policy new|sign`, or by other tooling.

`mvmd` owns:
- Policy bundle authoring workflows
- Signing and key custody for policy authors
- Distribution to hosts
- Pinning policy versions to plans
- Fleet-aggregated reporting on redaction events
- Emergency-deny rule promotion

`mvmd` never sees a request body in plaintext.

## Rationale

1. **Trust boundary.** The boundary between sandbox and the wider
   network is the host. The host runs `mvm`. That is the only
   place a request body is in plaintext on infrastructure we
   trust.

2. **Whitepaper §8 plane separation.** Putting redaction in
   `mvmd` would force every tenant request to traverse the
   control plane, collapsing the data-plane / control-plane
   distinction the whitepaper depends on.

3. **Whitepaper §13 control-plane compromise model.** A
   compromised orchestrator must not gain visibility into tenant
   prompts. With redaction in `mvm`, an `mvmd` compromise
   exposes policies and audit metadata, but not request bodies.

4. **Whitepaper §15 unbypassability.** "The workload cannot
   route around policy." This holds only if the policy engine
   sits on the host's only network exit. `mvmd` is not on that
   exit and cannot be made to be without sacrificing latency,
   residency, and blast-radius properties.

5. **Whitepaper §19 residency.** Sensitive workloads may be
   pinned to a host or region. Redaction must run before the
   request crosses any boundary that residency policy forbids.
   That places it on the originating host.

6. **Latency.** A regex/dictionary inspection in-process is
   single-digit milliseconds. A round-trip to a remote
   orchestrator is tens to hundreds, per AI call. The `mvm`-local
   placement preserves the user-facing latency budget for
   interactive agents.

7. **Failure independence.** When `mvmd` is unreachable, hosts
   must continue to enforce the most recently signed policy
   bundle they hold. Redaction is part of that enforcement;
   it cannot be allowed to lapse during a control-plane outage.

## Consequences

Positive:

- Tenant request bodies stay on the originating host through
  the redaction step.
- Latency cost is local-process, not network.
- Hosts continue to enforce redaction during `mvmd` outages.
- An `mvmd` compromise does not yield bulk tenant prompt access.
- Policy authoring is decoupled from the engine; multiple
  authoring workflows (mvmd, hand, third-party) all converge on
  the same signed bundle format.

Negative:

- Detector improvements ship as `mvm` releases, not as
  orchestrator pushes. Mitigated by signed `PolicyBundle`
  updates that can ship new *rules* without code changes;
  `Detector` impls are still in code.
- Cross-fleet aggregation of redaction telemetry requires audit
  shipping from each host to mvmd; mvmd cannot inspect from the
  request path.
- A poorly-tuned `PiiRedactor` blocks or mutates legitimate
  traffic on a per-host basis. Mitigated by `PiiPolicy::DetectOnly`
  shadow mode and per-policy rollback (§18).

## Operational Invariants

- **Fail-closed.** Detector panic, malformed policy, missing
  bundle digest → request **blocked**, not forwarded raw. Audit
  emits `PiiInspectionFailed` with reason.
- **Detect-only first.** New detectors and new actions roll out
  through `PiiPolicy::DetectOnly` for an explicit shadow window
  before transforms are enabled.
- **Reversible tokenization keys never leave the host.** The
  HMAC key for `Action::Tokenize` is supervisor-resident,
  per-plan, expires with the plan. mvmd never sees it.
- **Response-side inspection is symmetric.** AI-provider
  responses are inspected on the same chain (model-output
  redaction, indirect-prompt-injection guards on tool results).
  See ADR-005 (planned) and Addendum B in the implementation
  plan.

## Alternatives Considered

- **Redaction in `mvmd`.** Rejected: violates §8 plane
  separation, expands `mvmd` blast radius (§13), adds
  network latency, breaks residency (§19), creates a single
  point of failure for an enforcement action.
- **Redaction in the guest agent (Zone C).** Rejected: tenant
  code shares the trust boundary; a compromised workload would
  bypass the inspector. The whitepaper §15 explicitly places
  policy outside the tenant.
- **Redaction in a sidecar VM.** Considered. Equivalent in trust
  to host-side as long as the sidecar is supervisor-owned.
  Deferred — adds operational complexity without changing the
  trust story. Revisit if per-policy isolation between
  inspectors becomes necessary.

## Implementation Pointers

- Engine: `crates/mvm-supervisor/src/egress/pii.rs`
- Policy type: `crates/mvm-policy/src/pii.rs`
- Plan binding: `ExecutionPlan.egress_policy: PolicyRef`
- Test fixtures: `tests/pii_redaction/cases/*.json`
- See implementation plan §15.1, Wave 2.
```

---

## Addendum B — Other things that should live in `mvm` (not `mvmd`)

The PII question generalizes. The principle: **anything that sits on the data path between sandbox and outside world, anything that must keep enforcing during a control-plane outage, and anything that must respond in O(ms) to a single workload event belongs in `mvm`.** Below are the additions; each gets folded into the appropriate wave of the existing plan.

### B1. Response-side inspection (Wave 2, extend §15.1)
Same proxy chain, opposite direction. AI-provider responses can carry leaked tenant data echoed back, or attacker-controlled content (indirect prompt injection delivered via tool result, RAG document, or model hallucination). The supervisor's L7 proxy already sees the response stream; bolt the same inspector chain onto it.
- **Build:** mirror `RequestInspector` → `ResponseInspector` trait. Detectors: PII (symmetric with §15.1), known-malicious-pattern guard (data-URL injection, prompt-injection markers like "ignore previous instructions"), oversized-output kill (response > N MiB → block).
- **Effort:** S beyond §15.1.
- **Scaffold:** `ResponseInspector::DetectOnly` first.

### B2. Secrets/token scanner at egress (Wave 2)
Detects AWS keys, GitHub tokens, GCP service-account JSON, Slack webhooks, Stripe keys, generic high-entropy strings in outbound bodies. Different detector, same chain.
- **Build:** `SecretsScanner` inspector. Reuse trufflehog-style rules; `Action::Block` by default with audit, `Action::Mask` as opt-in.
- **Effort:** S.

### B3. DNS pinning at admission time (Wave 2, hardens §15)
Without this, a sandbox can subvert egress policy by mutating DNS mid-flight (DNS rebinding). Resolve plan-allowed destinations at admission; supervisor's resolver returns only pinned answers for the plan's lifetime.
- **Build:** supervisor-owned stub resolver bound to the per-tenant netns; refuses out-of-allowlist names, refuses post-admission TTL changes.
- **Effort:** S.

### B4. Hard-coded "must-traverse-proxy" hostname list (Wave 2, defense-in-depth for §15)
Even if `EgressPolicy` is misconfigured, common AI provider hostnames (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, …) trip a compile-time list and are forced through the inspector chain. Belt-and-suspenders.
- **Build:** const list in `mvm-supervisor`; integration test asserts presence of each hostname.
- **Effort:** XS.

### B5. Local rate limiting + connection caps (Wave 2)
Per-workload outbound rate cap and concurrent-connection cap. A runaway agent must be stoppable in milliseconds; mvmd's fleet-wide rate limit is too slow to be the only line of defense.
- **Build:** token bucket per `plan_id` in supervisor; refuses to admit a new connection past the cap; audit emits `RateLimited`.
- **Effort:** S.

### B6. Local kill switch (Wave 1, with §13 work)
`mvmctl kill <plan>` must work unconditionally even when mvmd is unreachable. No remote check, no policy validation — supervisor freezes vCPU + drains state + emits audit. Distinct from `quarantine` (paused, can resume) — `kill` is terminal.
- **Build:** existing `quarantine` plus a `Terminate` state. Wired to a SIGTERM-fast path on the Firecracker process.
- **Effort:** XS.

### B7. Audit buffering during `mvmd` outage (Wave 3, extend §22)
Supervisor must buffer audit (already on disk via JSONL) and ship it to mvmd when reachable. Never drop. Already mostly there — formalize the shipping queue + backpressure.
- **Build:** `AuditShipper` task: tail signed JSONL, push to mvmd ingest endpoint, ack-and-mark; bounded disk usage with oldest-shipped wins eviction; emits `AuditDropped` audit if the bound is hit (telemetry of last resort).
- **Effort:** S.

### B8. Local cosign verification cache (Wave 1)
Verifying cosign signatures on every plan launch is expensive; cache `(digest → verified_at, sig_bundle_hash)` in `~/.local/state/mvm/verify-cache`. Cache invalidation on revocation list change.
- **Build:** simple sled / sqlite-keyed cache; hooked into `mvm-security::image_verify`.
- **Effort:** S.

### B9. Workload identity attestation — short-lived JWTs (Wave 3, complements §14)
Supervisor mints a per-plan JWT (Ed25519, 5-min TTL, refreshable) presented in the `Authorization: Bearer ...` header to AI providers. Provider can verify against a published JWKS — local issuance gives auditable workload identity without putting `mvmd` in the request path.
- **Build:** `WorkloadIdentitySigner` in supervisor; configurable JWKS publication; `mvmctl jwks publish`. SPIFFE-shape claims (`spiffe://mvm/<tenant>/<workload>/<plan_id>`).
- **Effort:** M.

### B10. Sandbox memory scrubbing on stop (Wave 3, extends §16)
On workload stop, supervisor wipes Firecracker guest memory before releasing pages. Closes cold-boot residue and snapshot-leak paths.
- **Build:** `madvise(MADV_DONTNEED)` + zero-fill before unmap; integration test asserts memory pages are zeroed via `/proc/<pid>/pagemap` inspection.
- **Effort:** S.

### B11. Time/clock policy from host (Wave 3)
Guest TLS verification fails on broken clocks; without trusted time, `expires_at` checks on plan/grants/JWTs are also bypassable. Supervisor injects host time via vsock at boot and on resume.
- **Build:** supervisor-published time over vsock (existing `GUEST_AGENT_PORT`); guest agent sets clock at startup; refuses to start workload services until clock is set.
- **Effort:** S.

### B12. Workload crash dump capture (Wave 3, extends §23)
On workload crash, capture minimal post-mortem (Firecracker register state, last N audit entries, last N egress decisions) before destroying the VM. mvmd ingests later; the *capture* must be local because the VM is gone after `mvmd` even hears about it.
- **Build:** `CrashCollector` in supervisor; bounded retention; fetched via `mvmctl crashdump fetch <plan_id>`.
- **Effort:** S.

### B13. GPU passthrough governance (scaffold only — defer real impl)
For AI workloads with GPU access: device assignment per plan, memory zeroing between workloads, no shared-context. Doesn't ship in this plan but the *types* should exist so it slots in cleanly.
- **Scaffold:** `GpuRequirement` enum on `ExecutionPlan.resources`; supervisor refuses GPU-required plans on hosts without the device. Real isolation = future.
- **Effort:** XS scaffold; M+ real impl (out of scope).

### B14. Snapshot encryption + integrity checks at restore (Wave 3, hardens §27)
Snapshots can include in-flight secrets in memory. Already encrypted at rest (`snapshot_crypto.rs`); add: HMAC-tagged manifest, refuse-restore on tag mismatch, refuse-restore across plan-id boundary (a snapshot from plan A cannot be restored into plan B — prevents lateral move via snapshot reuse).
- **Build:** plan-id binding in snapshot manifest; verify on restore.
- **Effort:** S.

### B15. Per-plan resource zeroization on `Drop` (Wave 1, hygiene)
CI-enforce that every type holding secret material implements `Drop` with `Zeroize`. Lint + clippy custom check.
- **Build:** custom clippy lint or build.rs grep for `pub struct ... Secret` without `Zeroizing` wrapper.
- **Effort:** XS.

### B16. Local workload identity registry (Wave 1, extends §3.3)
Supervisor maintains a local registry of running plans, their digests, and their bound policies. `mvmctl ps` reads from there. Survives `mvmd` outage. (Today's `mvmctl ps` already partially does this; formalize the registry as a typed store with a stable schema.)
- **Build:** `LocalRegistry` keyed by `plan_id`; backed by sqlite; integration tests.
- **Effort:** S.

### Updated wave inventory

| Wave | Adds |
|---|---|
| 1 | B6 (kill switch), B8 (verify cache), B15 (zeroize lint), B16 (local registry) |
| 2 | B1 (response inspection), B2 (secrets scanner), B3 (DNS pinning), B4 (must-traverse list), B5 (rate/conn caps) |
| 3 | B7 (audit buffering), B9 (workload identity JWT), B10 (memory scrub), B11 (time), B12 (crashdump), B14 (snapshot integrity) |
| (deferred) | B13 (GPU governance) — scaffold only |

### B17. Egress audit completeness (Wave 2, with the L7 proxy itself)
Every request crossing the supervisor's L7 proxy emits a structured audit entry — allow / transform / block / quarantine, no exceptions, no sampling. Audit emit happens **before** forward; if the audit write fails the decision becomes `Block(AuditWriteFailed)`.

`EgressAuditEntry` schema:

```rust
struct EgressAuditEntry {
    plan_id: PlanId, plan_version: u32, policy_version: u32,
    image_measurement: [u8; 32],
    tenant: TenantId, workload: WorkloadId, host_id: HostId,
    timestamp: SystemTime, request_id: Ulid,
    direction: Direction,        // Outbound | InboundResponse | ToolCall | DnsLookup
    destination: Destination,    // hostname + port + resolved IP (post-DNS-pin)
    protocol: Protocol, method: Option<HttpMethod>, path: Option<String>,
    request_bytes: u64, user_agent_hash: [u8; 16],
    inspections: Vec<InspectionRecord>,
    decision: Decision,          // Allow | Transform | Block(reason) | Quarantine(path)
    transform_summary: Option<TransformSummary>,
    duration_ms: u32, upstream_status: Option<u16>,
    prev_hash: [u8; 32], signature: Ed25519Signature,
}
struct InspectionRecord {
    inspector: InspectorId, verdict: Verdict,
    detection_classes: Vec<DetectionClass>, detection_count: u32,
    rule_ids: Vec<RuleId>, duration_us: u32,
}
```

Invariants:
1. Audit emits before forward; write failure → block.
2. No request bodies in audit. Quarantined bodies go to encrypted store referenced by `quarantine_id`.
3. No sampling. Volume is managed via retention + compression, not drops.
4. `request_id` ULID correlates inspection records, request, response, downstream tool calls.
5. Response-side (B1) emits paired entries with same `request_id`.
6. DNS lookups (B3) audited — both pinned and refused-as-unpinned.
7. Tool-call vsock RPC audited (`Direction::ToolCall`, `tool_id`, `argument_hash`).
8. Quarantined requests get two records: egress-side `Quarantine(path)` + later quarantine-store access entry.
9. Failures emit too — connection refused, TLS handshake failure, upstream 5xx, supervisor crash mid-request.
10. Per-tenant streams (§16.5) — no cross-tenant leakage.

CI gate `audit-emits-before-forward`: integration test injects audit-write failure and asserts the request is blocked, not silently forwarded.

CLI: `mvmctl audit trace <request_id>`, `mvmctl audit egress --since <ts> --tenant <tid>`.

**Effort:** S beyond the L7 proxy itself.

### B18. Tool-call full audit (Wave 2)
Every `ToolGate` decision (allow / require-approval / block) emits the same shape with `tool_id`, `argument_hash`, decision. No tool call is unaudited. **XS** beyond B17.

### B19. Plan admission audit (Wave 1)
Every plan admission attempt audited — success and failure both — with rejection reason: signature invalid, pin mismatch, attestation failed, data-class mismatch, oversubscribed resources. Today admission failures are easy to make silent. **XS**.

### B20. Secret-grant audit completeness (Wave 3)
CI test on golden audit fixtures asserts every `SecretGranted` has a paired `SecretRevoked` or terminal plan stop. No orphans. **XS** beyond §12.3.

### B21. Configuration-change audit (Wave 1)
`mvmctl policy apply`, `mvmctl host trust set`, `mvmctl supervisor restart`, `mvmctl plan submit`, `mvmctl quarantine`, `mvmctl kill`, `mvmctl wake|sleep`, `mvmctl artifact fetch` — all emit audit. Closes §6 invariant "no unaudited control-plane mutation" on the local side. **S**.

### B22. Audit-write health metrics (Wave 3)
Supervisor exports `audit_write_failures_total`, `audit_buffer_pressure`, `audit_oldest_unshipped_age`, `audit_disk_pressure` so operators see audit degrading before it fails closed. **S**.

---

## Addendum C — Supervisor as an attack surface

The supervisor is the trusted root for egress, keys, audit, policy. We've designed *what* it does. These are *how it stays trustworthy under adversarial conditions*.

### C1. Supervisor self-attestation and update path (Wave 1)
Signed supervisor binary; measurement at boot extends §7A; `mvmctl supervisor verify` reports its own digest against a pinned set. Updates require signed bundles, two-slot atomic swap, no in-place mutation. Reuses `mvm-security` cosign primitives.
- **Build:** `mvmctl supervisor verify`, `mvmctl supervisor update <signed-bundle>`. Two-slot install at `/opt/mvm/supervisor/{current,previous}`. Hard refusal of unsigned binary with audit emission. **S**.

### C2. Supervisor↔guest channel rekeying (Wave 3)
Vsock auth uses Ed25519 (W4) but session keys today don't rotate during long-running plans. Periodic rekey (every N minutes or N MiB) bounds one-shot key compromise.
- **Build:** rekey trigger in supervisor; guest agent handles seamless transition; old key destroyed. Audit emits `SessionRekeyed`. **S**.

### C3. Anti-debug / anti-introspection on supervisor (Wave 1)
Prevent unprivileged host users from `ptrace`-ing the supervisor or reading its memory.
- **Build:** systemd unit applies `PR_SET_DUMPABLE 0`, `ProtectKernelTunables`, `NoNewPrivileges`, `SystemCallFilter`, `MemoryDenyWriteExecute`. macOS launchd plist applies equivalent (`HardenedRuntime`, no `task_for_pid`). Add ADR addendum naming "unprivileged host user" as in scope. **XS**.

### C4. Supervisor crash → fail-closed (Wave 1)
If the supervisor dies mid-plan, network must drop. Today: undefined.
- **Build:** systemd `BindsTo=mvm-supervisor.service` on TAP devices; on supervisor exit, TAP devices torn down within heartbeat window. Restart resumes from `LocalRegistry` (B16). Workload sees connection drops, no silent passthrough. Integration test kills supervisor mid-request, asserts block. **S**.

---

## Addendum D — Inbound inspection (the plan focused on outbound)

AI workloads have inbound surfaces too. The whitepaper §2.5 treats them as part of the supply chain; the plan as written doesn't cover them.

### D1. Inbound webhook / callback inspection (Wave 3)
Many agents expose webhook receivers (Slack, GitHub, Stripe). Need supervisor reverse-proxy mode where workloads register an inbound port and receive only signed/HMAC-verified traffic. Same inspector chain runs *into* the workload (auth check, oversize, malformed body, prompt-injection markers).
- **Build:** `InboundPolicy` sub-bundle in `PolicyBundle`; supervisor binds public ports per plan; per-provider HMAC verifiers (Slack/GitHub/Stripe scaffolds + generic `Bearer` mode). Each inbound request audited symmetrically with B17. **M**.

### D2. RAG document / retrieved-content inspection (Wave 3)
Workloads pull documents from external stores (S3, Drive, Notion, vector DBs). Per §2.5 these are attacker-influenced inputs. The same `ResponseInspector` chain (B1) runs on retrieved content with `Direction::Retrieved`.
- **Build:** route storage reads through proxy; tag retrieved content; inspector chain runs prompt-injection guards on retrieved bodies before they hit the workload. **S** given B1.

### D3. File-upload inspection (Wave 3)
Files entering the sandbox via virtiofs `/inbox` mount or vsock channel — magic-number checks, size limits, archive-bomb detection.
- **Build:** `FileInboundPolicy { max_size, allowed_mimes, archive_depth_limit, scan_with: Vec<Scanner> }`. Supervisor inspects on the mount path before file is visible to guest. **S**.

---

## Addendum E — Failure modes the plan silently assumed away

### E1. Detector false-positive DoS (Wave 2)
A poorly-tuned PII regex blocking every prompt is a self-inflicted outage. Need: per-detector circuit breakers (after N false-positive complaints from operators, detector drops to detect-only); shadow-mode comparison (`mvmctl audit shadow-diff`); documented escalation.
- **Build:** circuit breaker in inspector chain; `mvmctl detector status` shows tripped state; mvmctl-driven manual reset. **S**. **Ship-blocker for production rollout.**

### E2. Policy bundle conflicts (Wave 1)
Tenant overlay + base policy + emergency-deny can disagree. Need explicit precedence: deny wins over allow; more-specific overlay wins over base; emergency-deny wins over everything. CI test for the resolution table.
- **Build:** `PolicyResolver::resolve(base, overlay, emergency) -> EffectivePolicy` with deterministic precedence rules; golden-fixture CI table. **S**.

### E3. Clock skew during attestation (Wave 3)
Attestation reports have freshness windows. Without clock sync, reports are stale or accepted past their window.
- **Build:** clock-sync precondition before attestation verify; refuse if `host_time` unset or skews beyond bound (depends on B11). **XS**.

### E4. Disk-full audit failure (Wave 3)
Fail-closed (B17 + B7) blocks all egress on full disk — correct but brittle.
- **Build:** low-watermark alarm via `audit_disk_pressure` (B22); automatic compression of old shards; `mvmctl audit gc` with safety rails (refuses to delete unshipped audit). **S**.

---

## Addendum F — Tenant-facing surfaces the plan didn't surface

### F1. Egress budget / cost telemetry per plan (Wave 3)
AI provider calls cost real money. Supervisor sees every call — count tokens by parsing provider request shape; surface `mvmctl plan cost <plan_id>`; mvmd aggregates fleet-wide. The *measurement* must be local because supervisor is the only thing seeing every call.
- **Build:** per-provider request-shape parser (OpenAI, Anthropic, Google) extracts model + token count; aggregated per plan_id; surfaced via local API and CLI. **M**.

### F2. Workload health beyond liveness (Wave 3)
Today guest agent reports Ping/WorkerStatus. Add structured "stuck" detection: no egress in N minutes for an active plan; forward-progress timeouts on tool-call chains; agent-loop detection (same tool called >N times with same args).
- **Build:** supervisor watchdog scans audit stream for stuck patterns; emits `WorkloadStuck` with reason; configurable in plan. **S**.

### F3. Reproducible plan execution (Wave 5)
Same inputs → same egress decisions, same audit shape (modulo timestamps and request IDs). Property test, not feature.
- **Build:** CI gate: replay golden plans through supervisor, diff audit against expected modulo `timestamp`/`request_id`. **M**.

### F4. Tenant-visible audit subset (Wave 3)
Tenants own their audit data but mostly see nothing. Define `AuditView::Tenant` projection (their own plans, redacted destinations and rule_ids); `mvmctl audit show --as tenant <tid>`.
- **Build:** projection trait + view; mvmd later layers RBAC. **S**.

---

## Addendum G — Boundary conditions the plan was silent on

### G1. Multi-call AI provider sessions (Wave 2)
Streaming responses + tool loops break request-response audit assumptions. A single `request_id` for a streaming response that lasts minutes with interleaved tool calls.
- **Build:** `SessionAuditEntry` for long-lived streams with `chunk_index`; correlation rules for interleaved tool calls in the same session. **S**.

### G2. Retry storms (Wave 2)
A blocked request the workload retries 1000x → 1000 audit entries. Correct but expensive.
- **Build:** per-decision dedup-suppression; after N identical blocks for `(plan_id, destination, rule_id)` within window, emit `RepeatedBlock { count, first_seen, last_seen }` summary. **S**.

### G3. Cross-plan request stitching (Wave 3)
Outer agent plan A calls inner workflow plan B (same tenant). Audit links them via `parent_request_id`. Otherwise multi-step agentic flows are forensically unreconstructable.
- **Build:** `parent_request_id` field on `EgressAuditEntry` and `ExecutionPlan`; supervisor propagates through tool-call paths. **S**.

### G4. Time-travel / replay protection on signed plans (Wave 1)
Signed plans should expire and have nonces; otherwise an old signed plan is replayable indefinitely. **Latent bug in plan as written.**
- **Build:** add `valid_from`, `valid_until`, `nonce` to `ExecutionPlan`; supervisor maintains seen-nonce set per signing key (bounded LRU + `valid_until` purge). **S**.

---

## Addendum H — Explicit non-goals (so they don't drift in)

These belong elsewhere and the plan should *not* grow to include them:

- **H1. Model selection / routing decisions.** Workload code or sidecar agent layer. Supervisor sees the call, doesn't decide which provider.
- **H2. Prompt engineering / system-prompt management.** Workload responsibility. Supervisor enforces, doesn't author.
- **H3. Cost optimization (caching, batching).** Application concern. Supervisor measures (F1) but doesn't optimize.
- **H4. Federated learning / model training.** Out of scope for `mvm` entirely. Separate runtime if it ships.

---

### Updated wave inventory (with addenda C–G)

| Wave | New items beyond original waves |
|---|---|
| 1 | B6, B8, B15, B16, B19, B21, **C1, C3, C4, E2, G4** |
| 2 | B1, B2, B3, B4, B5, **B17, B18, E1, G1, G2** |
| 3 | B7, B9, B10, B11, B12, B14, B20, B22, **C2, D1, D2, D3, E3, E4, F1, F2, F4, G3** |
| 5 | **F3** |
| (deferred) | B13 |

### The four most-important additions not to miss

1. **G4 — replay protection on signed plans.** Without nonces + expiry, signed plans are forever-valid; latent bug in the plan as originally written.
2. **D2 — RAG / retrieved-content inspection.** Whitepaper §2.5 calls this out; the plan-as-written doesn't cover it. Major class of indirect prompt injection lives here.
3. **E1 — false-positive circuit breakers.** Without it, a bad detector takes the fleet down. Ship-blocker.
4. **C4 — supervisor death = fail-closed.** Without it, the integrity story has a hole.

### What remains correct to push to `mvmd`

For the avoidance of doubt, these stay on the orchestrator side:

- Cross-fleet rate-limit aggregation (the local cap is the floor; mvmd can lower it further but never raise it past local config).
- Cross-fleet PII telemetry rollups.
- Policy bundle authoring UX.
- Tenant onboarding, billing, quota allocation.
- Release promotion / canary / rollout / rollback decisions.
- Host registration, draining, capacity scheduling.
- Cross-host wake/sleep orchestration.
- Control-layer key custody and rotation.

The split stays clean: **`mvm` is the enforcement engine on the data path; `mvmd` is the policy author and fleet brain off the data path.**
