# MVM

## Secure MicroVM Infrastructure for AI-Native Workloads

**Technical Whitepaper · V2 Draft**  
**Audience:** platform engineers, security teams, AI infrastructure architects, developer-platform teams, and organizations evaluating secure execution environments for AI-native systems.

---

## Executive Summary

AI-native workloads should not run as trusted application code. They should run as isolated, signed, policy-governed execution units.

Modern AI systems execute generated code, invoke tools from model output, run Python and other dynamic runtimes, process user-provided files, and move data across model, tool, workflow, and application boundaries. In these systems, the application process is not a sufficient security boundary.

MVM is secure microVM infrastructure for running AI-native workloads inside isolated, policy-controlled execution environments. It combines a local and per-node microVM runtime with **mvmd**, the orchestration layer that manages tenants, workloads, runtime policy, images, secrets, networking, keys, audit, rolling releases, wake/sleep behavior, load distribution, and host lifecycle across a fleet.

The core claim is simple:

> MVM turns AI-native execution into governed infrastructure. Workloads run from signed artifacts, execute inside isolated runtime environments, receive scoped and rotating credentials, pass through policy-enforced egress, and are orchestrated by mvmd across hosts, releases, wake/sleep state, and audit lifecycle.

MVM supports native Firecracker execution while also supporting other VM and runtime backends, including Lima, Incus, containerd-based execution, and additional adapter-driven execution environments. Firecracker is a first-class backend, not the product boundary. The product boundary is the workload execution contract: signed images, decorated execution plans, tenant isolation, policy-enforced egress, key lifecycle, audit, governed artifacts, and mvmd orchestration.

At the infrastructure layer, MVM provides:

- Signed workload images and policy bundles
- Decorated execution plans as the contract between intent and runtime
- Tenant-scoped microVM and VM-backed execution
- Runtime backend abstraction across Firecracker and compatible execution environments
- Fleet orchestration through mvmd
- Rolling updates, staged releases, controlled rollbacks, host draining, and workload migration
- Automatic wake/sleep behavior and load-aware placement across runtime hosts
- Host lifecycle management across registration, health, capacity, draining, failure recovery, and release eligibility
- Separate control and sandbox data planes using guest-host communication such as vsock
- Inline, unbypassable policy enforcement for egress, AI-provider requests, PII, tool calls, and exploit surfaces
- Key rotation and short-lived credential flows for securing the control layer and workload execution
- Policy lifecycle management across signing, versioning, distribution, pinning, rollback, and emergency deny rules
- Data-classification and residency-aware workload placement
- Failure recovery for workloads, hosts, releases, keys, policy, artifacts, and attestation events
- Hardware-attestation integration points, including native support targets for AMD SEV-SNP and Intel TDX where available
- Audit metadata for workload execution, policy decisions, image provenance, key events, artifact handling, and lifecycle transitions

MVM is not a guardrail library, a container wrapper, or a conventional hosting layer. It is infrastructure for executing AI-native workloads with runtime isolation, orchestration, image integrity, policy enforcement, key management, and tenant boundaries treated as one system.

---

## 1. The AI-Native Infrastructure Problem

Classical web infrastructure assumes that application code is the primary trust boundary. That assumption breaks down in AI-native systems.

A modern AI application may include:

- LLM-mediated tool calls
- Python runtimes for code interpretation and analysis
- User-supplied files and documents
- Retrieval pipelines
- Vector stores
- Agent memory
- Background workflow execution
- Model-generated shell commands
- Dynamic dependency installation
- Browser automation
- Webhooks
- Long-running workers
- Artifact generation
- Model outputs forwarded to users, APIs, logs, and downstream systems

This creates a runtime surface larger than the application server itself. Prompt injection, tool abuse, dependency execution, poisoned documents, model output exfiltration, and compromised workflow steps can all influence what the system does.

The central infrastructure question is not whether a model can be made perfectly safe. It is whether the runtime constrains what any model-mediated workload is allowed to access, execute, emit, and persist.

MVM answers that question at the infrastructure layer.

---

## 2. AI-Native Threat Surfaces

AI-native workloads expand the threat model beyond normal request handling. The important surfaces are recurring properties of systems that combine models, tools, code execution, and user-controlled context.

### 2.1 Prompt Injection as Runtime Control Flow

Prompt injection turns data into instructions. A document, webpage, tool result, filename, ticket, email, or log line can influence the model’s behavior once it enters the context window.

The application cannot reliably distinguish trusted intent from hostile embedded instruction after both have been serialized into model context. The runtime therefore treats model output as potentially hostile control flow.

MVM places policy enforcement below the workload. The workload may attempt to call a tool, emit a response, or contact a destination, but the runtime determines whether that action is permitted.

### 2.2 Tool Abuse and Lateral Movement

The most valuable AI applications use tools. They read files, call APIs, query databases, open tickets, send messages, run code, and trigger workflows.

Those same capabilities create lateral-movement risk. A compromised or manipulated workload may attempt to:

- Call an unauthorized API
- Use a permitted API with malicious arguments
- Read files outside its tenant scope
- Exfiltrate data through a normal-looking tool response
- Reach another tenant’s service
- Call internal metadata endpoints
- Abuse webhooks
- Issue unexpected database or storage operations

MVM treats tool access as part of the runtime policy boundary. Workloads do not receive unconstrained network or tool access by default. Tool calls and outbound traffic are routed through policy-controlled paths.

### 2.3 Dynamic Runtimes and Code Execution

AI systems frequently need dynamic execution environments, especially Python. A Python runtime may be used for data analysis, code interpretation, notebook-style execution, workflow nodes, ML preprocessing, or agent-generated scripts.

Python is powerful precisely because it can load modules, spawn processes, read files, call native libraries, and make network requests. That makes it a poor fit for shared-process execution in multi-tenant systems.

MVM runs dynamic runtimes inside isolated workload environments. The runtime remains useful without inheriting ambient host privileges.

### 2.4 Model Inputs and Outputs as Egress

Model inputs and outputs are both egress channels.

A prompt sent to an AI provider may contain PII, secrets, customer records, private source code, internal identifiers, retrieved documents, tool results, or tenant data. A model response may carry the same classes of data back out through users, logs, webhooks, downstream APIs, or artifact stores.

Traditional egress monitoring often treats model-provider traffic and application responses as legitimate traffic. AI-native systems require policy-aware inspection on both sides of the model boundary because sensitive data can be present before the provider call and can also be reintroduced by the model response.

MVM places egress controls outside the tenant workload. The workload does not receive a bypass socket around the policy path. When policy requires it, MVM detects, redacts, masks, blocks, or quarantines PII before a request is allowed to leave for an AI provider.

### 2.5 Prompt, Policy, Model, and Image Supply Chain

AI applications ship more than code. They ship prompts, system prompts, policy bundles, model configuration, tool registries, retrieval indices, fine-tuned weights, runtime images, Python environments, and workflow definitions.

Each of these is a supply-chain artifact. Each requires provenance, signing, versioning, and clear ownership.

MVM treats images and runtime policy as signed infrastructure inputs. mvmd uses those inputs to decide what may run, where it may run, what keys it may receive, and what policy envelope applies.

---

## 3. System Overview

MVM consists of two primary roles:

1. **MVM** — the microVM runtime, local developer toolchain, image execution layer, and per-node abstraction for running isolated workloads.
2. **mvmd** — the orchestrator that turns individual workload execution into managed infrastructure across tenants, hosts, runtimes, policies, images, keys, releases, wake/sleep state, artifacts, and lifecycle.

Together, they provide a secure execution substrate for AI-native workloads.

### 3.1 MVM Runtime Layer

The MVM runtime layer runs isolated workloads on a host. It provides the primitives to build, launch, communicate with, inspect, stop, snapshot, and destroy microVM-backed execution environments.

MVM exposes a `VmBackend` trait that abstracts the underlying hypervisor or virtualization runtime. Native backends shipped today:

- **Firecracker** for production-grade microVM execution on Linux/KVM hosts
- **MicrovmNix (QEMU)** for Linux hosts where Firecracker is unavailable
- **Apple Container** (macOS 26+ on Apple Silicon) for native VZ.framework microVM execution
- **Docker** as a compatibility tier for non-sensitive development workloads

Roadmap backends consumable through the same trait include Lima (forced as a dev fallback today), Incus, and containerd-based runtimes. These are documented as planned adapters rather than shipped surfaces.

The runtime backend is an implementation detail behind the execution contract. The architectural contract is that workloads run inside explicitly managed execution environments with tenant-aware identity, policy, image provenance, keys, audit, and lifecycle control.

### 3.2 mvmd Orchestration Layer

mvmd is the orchestration layer for MVM infrastructure.

It coordinates:

- Tenant registration and isolation
- Workload submission
- Image selection and verification
- Desired workload state
- Host and runtime placement
- Rolling updates, staged releases, and controlled rollbacks
- Automatic wake/sleep behavior for idle and active workloads
- Load distribution across available hosts and runtime pools
- Host inventory, health, capacity, draining, and infrastructure lifecycle management
- Execution policy
- Key release, rotation, and revocation
- Network boundaries
- Sandbox data-plane configuration
- Artifact capture
- Snapshot and lifecycle transitions
- Runtime events
- Audit metadata
- Failure handling and reconciliation

mvmd is the control system for the fleet, not a process launcher. It receives workload intent, resolves it into a complete execution plan, and ensures the runtime converges toward that plan.

In production, mvmd turns microVM execution into infrastructure: release promotion, canary rollout, staged deployment, rollback, host draining, workload migration, automatic sleep for idle capacity, automatic wake for demand, and load-aware placement across the available host pool.

### 3.3 Decorated Execution Plans

MVM does not execute raw workload requests. mvmd executes **decorated execution plans**: signed, policy-enriched records that define identity, runtime, resources, secrets, egress, artifacts, lifecycle, and audit.

A decorated execution plan includes:

- Tenant identity
- Workload identity
- Runtime backend profile
- Image reference and signature requirements
- Resource limits
- Network policy
- Filesystem and volume policy
- Secret references
- PII and egress policy
- Tool-call policy
- Artifact retention rules
- Audit labels
- Cost and usage metadata
- Key-rotation requirements
- Attestation requirements where applicable
- Release and policy version pinning
- Post-run lifecycle behavior

Decoration is not an add-on. It is a core MVM capability.

The practical result is that workloads are not launched from ambiguous user intent. They are executed from complete, policy-aware infrastructure records.

---

## 4. Reference Architecture

```text
Developer, API, Workflow Engine, or AI Agent Platform
        |
        v
+--------------------------------------------------+
| mvmd Orchestrator                                |
| tenants, desired state, releases, wake/sleep,    |
| host management, placement, keys, policy, audit  |
+--------------------------------------------------+
        |
        v
+--------------------------------------------------+
| Decorated Execution Plan                         |
| signed image, tenant identity, runtime profile,  |
| resources, secrets, egress, artifacts, lifecycle |
+--------------------------------------------------+
        |
        v
+--------------------------------------------------+
| Runtime Host Pool                                |
| health, capacity, draining, load distribution    |
+--------------------------------------------------+
        |
        v
+--------------------------------------------------+
| MVM Runtime Backend                              |
| Firecracker / Lima / Incus / containerd / VM     |
+--------------------------------------------------+
        |
        v
+--------------------------------------------------+
| Tenant Workload Sandbox                          |
| Python / agents / tools / workflows / services   |
+--------------------------------------------------+
        |
        v
+--------------------------------------------------+
| Policy-Enforced Egress and Artifact Handling     |
| PII, exploit controls, tool policy, audit, output|
+--------------------------------------------------+
```

The architecture separates workload intent from workload execution. mvmd manages fleet state and release safety. Decorated execution plans define the policy contract. MVM runtime backends execute workloads. The policy path governs egress, tools, secrets, and artifacts outside the tenant workload.

---

## 5. What MVM Enforces

| Layer | MVM Enforcement |
|---|---|
| Image | Signing, verification, provenance, content identity, release versioning |
| Plan | Decorated execution plan with tenant, runtime, resources, policy, secrets, artifacts, and lifecycle |
| Runtime | MicroVM, VM, or backend-specific isolation through MVM adapters |
| Tenant | Compute, network, storage, secrets, policy, and audit boundaries |
| Egress | PII controls before AI-provider calls, exploit controls, destination policy, tool-call validation, response inspection, and audit |
| Keys | Scoped release, key rotation, revocation, short-lived credentials, and key-event audit |
| Fleet | mvmd placement, releases, rollback, wake/sleep, load distribution, host health, and host draining |
| Artifacts | Retention, expiration, access control, encryption policy, handoff, and audit |
| Audit | Runtime events, policy decisions, key events, lifecycle transitions, and artifact handling |

This enforcement model is the product boundary. Individual runtime backends implement execution. MVM and mvmd define the governed workload contract around that execution.

---

## 6. Security Invariants

MVM is built around security invariants that remain true across runtime backends. The backend may change. The execution contract does not.

| Invariant | Meaning |
|---|---|
| No raw workload execution | Workloads run from decorated execution plans, not ad hoc commands. |
| No unsigned runtime identity | Images, policy bundles, and release records are signed and verified before execution. |
| No ambient long-lived credentials | Secrets are scoped, rotated, revocable, and released through policy. |
| No bypass egress path | Tenant workloads cannot route around policy-enforced egress. |
| No unscoped tenant state | Compute, storage, network, secrets, artifacts, and audit are tenant-bound. |
| No silent release mutation | Releases are staged, versioned, audited, and rollback-capable. |
| No unmanaged host participation | Hosts must be registered, identified, health-checked, and capability-aware before receiving workloads. |
| No unaudited control-plane mutation | Policy, release, key, host, and workload-state changes produce audit records. |

These invariants make MVM more than a launcher. They define the minimum safety properties required for AI-native workload execution.

---

## 7. Trust Zones

MVM uses trust zones to separate responsibilities inside the execution path. The exact process layout may vary by runtime backend and deployment tier, but the trust model remains consistent.

### Zone A — Measurement, Bootstrap, and Key Entry

The bootstrap zone prepares the workload environment. It verifies image identity, participates in attestation where available, establishes the initial trust context, and obtains only the key material required for the next stage.

Responsibilities include:

- Image verification
- Measurement binding
- Attestation handoff where supported
- Initial key exchange
- Secret unsealing into the appropriate runtime scope
- Handoff to the runtime supervisor

This zone is small, deterministic, and short-lived.

### Zone B — Runtime Supervisor and Policy Plane

The runtime supervisor manages the tenant sandbox and the policy path around it.

Responsibilities include:

- Launching and monitoring workload sandboxes
- Maintaining the policy-enforced egress path
- Applying PII and exploit controls
- Managing runtime keys and short-lived credentials
- Emitting signed or tamper-evident audit events
- Coordinating artifact capture
- Handling lifecycle transitions

Zone B is trusted runtime infrastructure. Tenant code does not run here.

### Zone C — Tenant Workload Sandbox

The tenant workload sandbox is where customer code, agent code, Python runtimes, workflow nodes, tools, and application processes execute.

This zone is treated as untrusted.

The sandbox does not receive unconstrained host access. It communicates with the surrounding runtime over separate control and sandbox data planes using guest-host communication such as vsock. The policy path is outside the tenant’s control.

This structure makes policy enforcement part of the infrastructure path rather than a library call the workload may skip.

---

## 8. Control Plane and Data Plane Separation

MVM separates control responsibilities from sandbox execution traffic.

The control plane carries desired state, lifecycle commands, health, runtime metadata, key-management events, policy versions, release state, host state, and audit records.

The sandbox data plane carries workload communication between the tenant environment and the runtime services that mediate network, file, tool, and artifact access.

Both planes use guest-host communication patterns such as vsock where appropriate, but they are treated as separate data planes. This separation reduces accidental privilege blending between orchestration and tenant execution.

The control plane is responsible for:

- Declaring what should run
- Confirming what is running
- Coordinating rolling releases and rollbacks
- Managing host health and capacity
- Delivering policy versions
- Coordinating key rotation
- Recording lifecycle transitions
- Receiving runtime events

The sandbox data plane is responsible for:

- Mediated egress
- Tool-call routing
- Runtime service access
- Artifact movement
- Workload-level communication

A tenant workload cannot mutate control-plane state through the sandbox data plane.

---

## 9. Runtime Backend Model

MVM supports multiple runtime backends because secure execution must work across development, production, edge, and hosted environments.

Firecracker remains a native and important backend. It is well suited to high-density, short-lived, KVM-based microVM workloads. However, MVM’s architecture is not limited to Firecracker.

The backend model allows MVM to support:

- Production microVM execution
- Local VM development
- Host environments where Firecracker is unavailable
- Integration with existing VM and container infrastructure
- Edge or workstation execution patterns
- Runtime portability across cloud and local environments

The backend abstraction applies the same workload identity, signing, policy, audit, key, and lifecycle concepts across different execution substrates.

When a backend provides different isolation or attestation properties, mvmd records and enforces the appropriate trust tier through policy.

---

## 10. Signed Images and Policy Bundles

MVM treats the deployable workload as a signed infrastructure artifact.

A workload image identifies:

- The root filesystem or runtime environment
- Kernel or VM configuration where applicable
- Runtime profile
- Entrypoint
- Declared capabilities
- Required secrets
- Expected policy bundle
- Content hash
- Signature metadata

Policy bundles identify:

- Allowed destinations
- Disallowed destinations
- Tool-call constraints
- PII detection and redaction rules
- Exploit detection rules
- Logging and audit requirements
- Artifact retention behavior
- Key-rotation rules
- Tenant overlays

mvmd uses signed image and policy metadata to decide whether a workload may run. Unsigned or tampered artifacts are rejected by policy.

The result is a runtime chain where what runs, what policy applies, and what secrets may be released are linked to verifiable infrastructure artifacts.

---

## 11. Release Safety and Runtime Change Management

AI-native infrastructure needs release controls at the runtime layer, not only at the application layer.

A release may change the workload image, runtime profile, policy bundle, egress behavior, key requirements, artifact handling, or trust tier. Each of these changes affects security posture.

mvmd manages release safety through:

- Signed release artifacts
- Policy-version pinning
- Runtime-profile versioning
- Staged rollout
- Canary deployment
- Controlled rollback
- Host draining
- Workload migration
- Wake/sleep-aware placement
- Load-aware release distribution
- Audit of release transitions

This allows teams to promote workload versions without turning runtime changes into unmanaged host operations.

A release is not merely a new image. In MVM, a release is a coordinated change to the signed image, decorated execution plan, runtime policy, key requirements, artifact behavior, and lifecycle state.

---

## 12. Key Management and Rotation

Key rotation is a core part of the MVM security model.

AI-native systems place unusual pressure on credentials. Workloads may need API keys, model-provider tokens, database credentials, signing keys, webhook secrets, storage credentials, and short-lived access grants. Those credentials cannot become ambient, long-lived capabilities inside tenant code.

MVM uses key-management boundaries to secure both the control layer and tenant workload execution.

### 12.1 Control-Layer Keys

Control-layer keys secure mvmd coordination, host identity, workload authorization, policy distribution, signed desired state, release promotion, and audit integrity.

These keys are:

- Scoped to specific roles
- Rotated on a defined schedule
- Revoked when hosts or tenants are removed
- Bound to workload or host identity where appropriate
- Logged through audit events
- Kept separate from tenant runtime secrets

Key rotation is how the control layer remains secure over time.

### 12.2 Workload Secrets

Workload secrets are released only into the execution context authorized to use them.

MVM supports:

- Short-lived workload credentials
- Per-run secret grants
- Tenant-scoped secret references
- Policy-gated secret release
- Attestation-gated key release where supported
- Rotation on workload restart, redeploy, or policy change
- Secret revocation when a workload transitions to stopped, failed, expired, or quarantined

The workload receives the minimum credential material required for its declared execution plan.

### 12.3 Audit and Key Events

Key events are part of the audit trail.

The audit record captures:

- Which workload requested secret access
- Which tenant owned the workload
- Which policy version authorized access
- Which key version was used
- When rotation occurred
- Whether revocation succeeded
- Which host or runtime identity participated

This allows security teams to answer not only what ran, but what authority it had while running.

---

## 13. Control Plane Compromise Model

MVM assumes the control plane is security-critical. mvmd controls workload placement, release promotion, host eligibility, key release, policy versions, and lifecycle state. A compromise in this layer must be contained through signing, scoping, rotation, revocation, audit, and rollback.

MVM reduces control-plane blast radius through:

- Signed desired state for workload and release changes
- Role-scoped control-plane keys
- Short-lived credentials for host and workload operations
- Key rotation and revocation for hosts, tenants, releases, and service identities
- Policy version pinning on decorated execution plans
- Host revocation and draining
- Workload quarantine
- Release rollback
- Audit records for control-plane mutations
- Separation between control-plane state and sandbox data-plane communication

A compromised control-plane credential should not grant unlimited, silent authority. The system records what changed, which identity changed it, which policy version allowed it, which hosts accepted it, and which workloads were affected.

Control-plane recovery relies on explicit mechanisms: revoke affected keys, pin or roll back policy, quarantine impacted workloads, drain affected hosts, rotate credentials, and replay audit state against known signed records.

---

## 14. Attestation and Confidential Runtime Support

MVM models attestation as a pluggable provider in the runtime trust chain.

Attestation proves what was launched and binds runtime identity to a measured artifact. It does not replace signed images, policy bundles, key rotation, or audit. Its value is in making workload identity verifiable before sensitive keys are released.

MVM defines an `AttestationProvider` trait whose implementations may consume hardware-rooted evidence where available. **Implementation status:** today MVM ships a `NoopAttestationProvider` plus the `AttestationRequirement` admission gate; TPM2 is the next concrete provider on the roadmap. AMD SEV-SNP and Intel TDX are named as future support targets and ship as `unimplemented!()` scaffolds — plans whose `AttestationRequirement::Confidential` cannot be satisfied are refused at admission today, not silently downgraded.

The general attestation flow is:

1. A workload image is built and signed.
2. The image measurement is registered as an allowed workload identity.
3. mvmd schedules the workload on a compatible host.
4. The runtime produces an attestation report where supported.
5. The verifier checks measurement, platform identity, freshness, and policy.
6. Key material is released only if the attestation and policy checks pass.
7. Runtime credentials remain short-lived and subject to rotation.

This model supports both integrity-focused deployments and confidential-computing deployments. The policy tier determines what guarantees are required before the workload may run. Confidential-computing tiers require a future SEV-SNP or TDX provider; integrity-focused tiers are reachable today with TPM2 once shipped, and design-intent today via the noop provider.

---

## 15. Unbypassable Egress, PII, and Exploit Controls

> **Implementation status (V2 draft):** §15 and §15.1 describe the runtime policy plane's broader design intent. L3 destination allowlisting via `NetworkPreset` is shipped today. The full AI-provider policy plane remains in progress, but the first owned-path reversible-replacement slice is now real: the host substitution proxy can detect secret/PII spans on owned cleartext request headers/bodies, replace them with opaque request-scoped tokens, and restore exact token echoes on the owned response path while keeping proofs plaintext-free. The larger L7 egress proxy / provider inspection / generalized response inspection surface remains tracked as Sprint 44 / plan 37 Wave 2 (`mvm-supervisor` + `PiiRedactor`). The example in §15.1 is still the target output shape for the broader policy plane, not a current full-system trace.

MVM’s policy path prevents tenant workloads from bypassing the controls that govern outbound behavior.

The tenant sandbox does not receive a raw, unconstrained network path. Outbound activity is mediated through the runtime policy plane.

The egress layer enforces:

- Destination allow and deny policies
- Protocol normalization
- AI-provider request inspection
- Prompt and payload inspection before model calls
- Tool-call validation
- PII detection
- PII redaction, masking, blocking, or quarantining before provider egress
- Response inspection after model calls where policy requires it
- Secret and token detection
- SSRF prevention
- SQL, command, and prompt-injection pattern detection
- Suspicious destination detection
- Rate and volume anomalies
- Audit logging for allowed, transformed, and denied activity

The purpose is to ensure that every outbound path passes through policy enforcement before it reaches an AI provider, network destination, tool, webhook, or external system.

This is materially different from an SDK-level guardrail. SDKs live inside the application’s trust boundary. MVM’s egress path lives outside the tenant workload.

### 15.1 AI-Provider PII Redaction

MVM treats AI-provider calls as governed egress, not ordinary application traffic.

When a workload sends a request to an AI provider, the runtime policy plane can inspect the outbound prompt, messages, tool results, retrieved context, metadata, and attachments before the request is forwarded. If PII is detected, policy determines the action:

- **Redact** sensitive spans before forwarding the request
- **Mask** sensitive values while preserving shape
- **Tokenize** sensitive fields for reversible restoration in an authorized post-processing path
- **Block** the provider call entirely
- **Quarantine** the request for review
- **Audit** the transformation, denial, or release decision

This allows a workload to accidentally or maliciously include PII in a prompt while MVM still prevents that raw PII from reaching the AI provider when policy forbids it.

For example, a tenant workload may construct a prompt containing a customer name, email address, phone number, account identifier, and support history. Before the prompt leaves the sandbox, MVM can transform it into a redacted provider request such as:

```text
Customer [PERSON_1] at [EMAIL_1] reported an issue with account [ACCOUNT_ID_1]. Summarize the support history without exposing raw identifiers.
```

The AI provider receives the policy-approved version, not the raw tenant data. The audit trail records the provider destination, policy version, redaction action, workload identity, tenant identity, and key context without exposing unnecessary sensitive content in logs.

---

## 16. Multi-Tenant Isolation

MVM is designed for multi-tenant execution.

A tenant may represent a customer, organization, team, project, workflow owner, or agent execution scope. Tenant isolation is enforced across compute, network, storage, secrets, policy, and audit.

### 16.1 Compute Isolation

Tenant workloads execute in isolated runtime environments rather than shared application processes.

Resource limits are applied per workload or tenant, including CPU, memory, disk, process limits, and runtime timeouts where supported by the backend.

### 16.2 Network Isolation

Tenant network identity is assigned and managed by mvmd.

Tenants have separate network scopes. Cross-tenant communication is denied unless explicitly modeled through policy. Egress moves through the policy path rather than directly from workload code to the host network.

### 16.3 Storage Isolation

Tenant storage is scoped by runtime policy.

MVM separates:

- Runtime state
- Workload volumes
- Secret material
- Config data
- Snapshots
- Artifacts
- Audit records

This separation allows different retention, encryption, and cleanup policies for different classes of data.

### 16.4 Secret Isolation

Tenant secrets are not shared across tenants and are not treated as static files inside workload images.

Secret access is mediated through policy, identity, key release, rotation, and audit.

### 16.5 Audit Isolation

Audit records are scoped to the tenant and workload. Security teams can inspect workload lifecycle, policy decisions, key events, image versions, release versions, and artifact handling without relying on application logs alone.

---

## 17. Host Lifecycle and Infrastructure Handling

mvmd manages runtime hosts as part of the infrastructure control plane.

A host is not just a machine that can launch a workload. It is an identified infrastructure participant with runtime capabilities, health state, capacity, trust tier, key material, release eligibility, and audit history.

mvmd manages host lifecycle through:

- Host registration
- Host identity and trust-tier assignment
- Runtime backend capability detection
- Capacity reporting
- Health checks
- Release eligibility checks
- Workload placement
- Load distribution
- Wake/sleep pool participation
- Host draining
- Workload migration
- Failed-host reconciliation
- Host revocation
- Audit of host state transitions

This allows MVM to treat infrastructure changes as governed events. A host entering service, leaving service, failing health checks, receiving a release, draining workloads, or losing eligibility is visible to the control plane and reflected in audit records.

### 17.1 Wake/Sleep and Load Distribution

AI-native workloads are often bursty. A fleet may need warm capacity for interactive agents, sleeping capacity for infrequent tenants, and immediate scale-out for demand spikes.

mvmd manages this through:

- Automatic sleep for idle workloads or pools
- Wake-on-demand for tenant workloads
- Warm pool management
- Load-aware placement
- Capacity-aware release distribution
- Migration away from overloaded or draining hosts
- Snapshot-aware lifecycle transitions where supported

Wake/sleep is not only a cost feature. It is an infrastructure-control feature that lets mvmd preserve tenant state, reduce idle capacity, and still route demand into a governed execution path.

---

## 18. Policy Lifecycle

Policy is a first-class runtime artifact in MVM.

A policy bundle defines what a workload may access, where it may send data, which tools it may call, which PII rules apply, which exploit controls run, which artifacts are retained, which keys may be released, and which audit requirements must be satisfied.

The policy lifecycle includes:

- Authoring
- Signing
- Versioning
- Distribution
- Tenant overlays
- Release pinning
- Workload pinning
- Rollback
- Emergency deny rules
- Audit of policy changes

Policy changes affect runtime behavior. For that reason, they are treated with the same seriousness as image releases.

A decorated execution plan records the policy version that applied when the workload was admitted. This makes workload behavior explainable after the fact and prevents silent mutation of runtime constraints.

### 18.1 Emergency Deny Rules

AI-native systems need fast response when a destination, tool, model, webhook, package source, or data path becomes unsafe.

MVM supports emergency deny rules as signed policy updates. These updates can block known-bad destinations, disable risky tools, quarantine specific workload classes, or prevent release promotion until review.

Emergency controls are still governed: they are signed, versioned, distributed through the policy path, and recorded in audit.

---

## 19. Data Classification and Residency

MVM connects workload execution to data classification and residency requirements.

Different workloads handle different data classes. A prompt containing public documentation does not require the same runtime policy as a workload processing customer PII, regulated data, private source code, or tenant secrets.

MVM uses policy to determine where and how workloads may execute based on data sensitivity.

Data-aware execution can include:

- Local redaction before hosted model calls
- Routing by data classification
- Tenant policy deciding where workloads may execute
- PII-sensitive workloads requiring specific trust tiers
- Artifact retention based on data class
- Secret release based on data classification
- Audit records showing where sensitive workloads ran
- Denial of execution when the available host pool cannot satisfy the required trust tier

This allows MVM to support a unified execution model across local, edge, and hosted environments while preserving policy differences between public, private, confidential, and regulated workloads.

---

## 20. Unified Edge and Hosted Execution

MVM uses a single execution model across hosted infrastructure, developer machines, and capable edge environments.

The data path is consistent:

1. A workload is built and signed.
2. Policy is attached.
3. mvmd validates the decorated execution plan.
4. The appropriate runtime backend is selected.
5. Keys are released according to policy.
6. The workload runs in an isolated environment.
7. Egress and tool calls pass through the runtime policy path.
8. Artifacts and audit events are collected.
9. The workload is stopped, snapshotted, expired, or destroyed according to lifecycle policy.

Hosted, local, and edge execution differ in available hardware, runtime backend, attestation source, and trust tier. The control model remains the same.

This matters for AI-native applications because sensitive work may need to happen close to data. A workload can redact PII locally before sending a transformed request to a hosted model. A developer can test the same image locally before production execution. A hosted environment can require confidential-computing support before secrets are released.

MVM keeps these paths unified by making policy, signing, lifecycle, and audit part of the runtime contract rather than deployment-specific glue.

---

## 21. Artifact Lifecycle

AI-native workloads produce artifacts: generated files, reports, transformed datasets, model outputs, logs, screenshots, compiled binaries, embeddings, traces, and workflow results.

MVM treats artifacts as governed outputs.

Artifact policy defines:

- Ownership
- Retention
- Expiration
- Access control
- Encryption requirements
- Signing requirements
- Download or handoff mechanism
- Audit events
- Cleanup behavior

Artifacts are not incidental files left behind by a worker. They are outputs of a controlled execution environment.

This is important for compliance and product safety. Generated artifacts may contain sensitive data, derived customer information, or intermediate model outputs. They require the same seriousness as workload inputs.

---

## 22. Runtime Observability and Audit

MVM records infrastructure events that application logs cannot reliably provide.

A complete runtime audit trail answers:

- Who submitted the workload?
- Which tenant owned it?
- Which image ran?
- Which release version applied?
- Which policy bundle applied?
- Which runtime backend executed it?
- Which host accepted it?
- What trust tier was required?
- Which keys or secret grants were released?
- Which network policy was enforced?
- Which egress decisions were made?
- Which artifacts were produced?
- When did the workload start, stop, fail, snapshot, sleep, wake, expire, migrate, or get destroyed?

Audit records are tied to the control plane and runtime lifecycle, not only to the application process. This keeps audit useful even when tenant code is compromised, buggy, or incomplete.

---

## 23. Failure and Recovery

Infrastructure security is incomplete without failure behavior.

MVM records and responds to failure states across workloads, hosts, releases, keys, policy, artifacts, and attestation.

| Failure | MVM Recovery Behavior |
|---|---|
| Workload crash | Record failure, preserve audit context, collect available artifacts, apply retry or lifecycle policy. |
| Host crash | Mark host unhealthy, reconcile affected workloads, migrate or restart eligible workloads elsewhere. |
| mvmd restart | Rehydrate desired state, compare with observed runtime state, resume reconciliation. |
| Release failure | Stop rollout, preserve release audit, roll back or hold affected workloads by policy. |
| Key rotation failure | Deny new sensitive operations, preserve existing audit chain, retry rotation or revoke affected grants. |
| Policy distribution failure | Keep workloads pinned to known policy versions or deny admission when policy freshness is required. |
| Artifact upload failure | Preserve local artifact state where possible, retry handoff, record incomplete artifact status. |
| Failed attestation | Deny key release, prevent workload admission to the requested trust tier, record attestation failure. |
| Stuck sleep/wake transition | Reconcile runtime state, retry transition, migrate workload, or mark instance for operator review. |
| Overloaded host | Stop placing new workloads, migrate eligible workloads, wake additional capacity where available. |

Failure handling is part of the control model. mvmd continuously compares desired state against actual state and drives the system back toward a governed state.

---

## 24. Threat-to-Control Mapping

| Threat | MVM Control |
|---|---|
| Prompt injection causes tool abuse | Tool-call policy and mediated egress outside the tenant workload. |
| Prompt sent to AI provider contains PII | PII inspection, redaction, masking, tokenization, blocking, or quarantine before provider egress. |
| Model output leaks PII | PII inspection, redaction, masking, blocking, or quarantine at egress. |
| Tenant attempts cross-tenant access | Tenant-scoped compute, network, storage, secrets, artifacts, and audit. |
| Host receives tampered image | Signed image verification and content identity checks. |
| Policy changes silently alter behavior | Signed policy bundles, versioning, pinning, rollback, and audit. |
| Long-lived secret leaks | Short-lived credentials, scoped release, rotation, and revocation. |
| Bad release ships | Staged rollout, canarying, host draining, rollback, and release audit. |
| Idle workload wastes capacity | mvmd sleep orchestration and warm pool management. |
| Demand spike overloads host | Load-aware placement, wake-on-demand, and host-capacity tracking. |
| Host becomes unhealthy | Health checks, failed-host reconciliation, migration, and host revocation. |
| Control-plane credential is compromised | Role scoping, key rotation, signed desired state, audit, revocation, and rollback. |
| Sensitive workload runs in wrong location | Data-classification policy, trust-tier requirements, and placement denial. |
| Artifact contains sensitive data | Artifact retention, access control, encryption policy, expiration, and audit. |
| Attestation fails | Key release denial and workload admission failure for attestation-required tiers. |

This mapping is intentionally infrastructure-oriented. MVM does not depend on perfect model behavior. It constrains the runtime consequences of model-mediated behavior.

---

## 25. Integration Surface

MVM is designed to be integrated by platforms that need governed workload execution.

The integration surface includes:

- CLI for developers and operators
- API or gateway for workload submission and lifecycle inspection
- SDK hooks for workflow engines and agent runtimes
- Runtime backend adapters
- Image and policy registry integration
- Secret manager integration
- Artifact handoff
- Audit export
- Policy authoring and signing workflows
- Release-management integration
- Host registration and fleet-management hooks

This surface keeps MVM useful as infrastructure rather than a closed application. A workflow engine, AI-agent platform, secure builder, developer sandbox, or internal automation system can submit workloads into the same execution contract.

---

## 26. Operating Modes

MVM supports several operating modes using the same workload contract.

| Mode | Purpose |
|---|---|
| Local Development | Run the same signed workload and policy model locally with a compatible backend. |
| Hosted Standard | Run isolated signed workloads on managed hosts with tenant, policy, key, artifact, and audit controls. |
| Hosted Confidential | Require hardware attestation and confidential-computing support before sensitive key release. |
| Edge or Private | Run close to sensitive data while preserving policy, signing, lifecycle, and audit semantics. |
| Build and Artifact | Run secure builders and artifact-generation workloads inside governed execution environments. |
| Workflow Runtime | Execute workflow nodes, Python steps, tools, and agents with tenant-scoped policy and audit. |

The operating mode changes placement and trust requirements. It does not change the core execution model.

---

## 27. Workload Lifecycle

```text
Raw Workload Intent
        ↓
Decoration
        ↓
Signed Decorated Execution Plan
        ↓
mvmd Scheduling + Host Selection
        ↓
Runtime Backend Launch
        ↓
Tenant Sandbox Execution
        ↓
Policy-Enforced Egress + Artifact Capture
        ↓
Audit + Key Events
        ↓
Sleep / Wake / Snapshot / Migrate / Destroy
```

This lifecycle is the center of MVM’s infrastructure model. The workload begins as intent, becomes a signed and decorated plan, runs through a managed backend, passes through policy-controlled egress and artifact handling, and exits through an audited lifecycle transition.

---

## 28. How MVM Differs from Common Alternatives

### Containers

Containers are useful packaging and process-isolation tools, but they are not always sufficient as the primary boundary for untrusted AI-native execution. MVM uses stronger workload isolation where required and keeps runtime policy outside the tenant workload.

### Conventional VMs

Traditional VMs provide isolation but are often too heavy or operationally generic for high-density, ephemeral, policy-rich AI workloads. MVM focuses specifically on managed workload execution, signing, policy, tenant isolation, key management, release safety, and lifecycle automation.

### Guardrail Libraries

Guardrail libraries run in the application path. They can be omitted, misconfigured, downgraded, or bypassed by compromised code. MVM places policy enforcement in the runtime path outside the tenant sandbox.

### CI Runners

CI systems execute jobs, but they are usually organized around build pipelines rather than long-lived secure execution infrastructure for agents, tools, workflows, and hosted AI services. MVM provides a reusable runtime layer for broader AI-native execution.

### Ad Hoc Sandboxes

Ad hoc sandboxes often solve one dimension of the problem: process isolation, network filtering, logging, or dependency control. MVM treats isolation, orchestration, releases, policy, secrets, images, audit, and artifacts as one system.

---

## 29. Where MVM Fits

MVM is a strong fit when a platform needs to run workloads that are powerful, dynamic, tenant-scoped, or partially untrusted.

Typical examples include:

- AI-agent execution environments
- Python code interpreters
- Secure workflow runners
- Multi-tenant build systems
- Data transformation jobs
- Tool-using LLM applications
- Artifact generation systems
- Hosted developer environments
- Edge or local privacy-preserving AI workflows
- Internal automation platforms

The need is strongest when workloads can access sensitive files, credentials, user data, private APIs, or model-mediated tools.

The decision point is simple:

> If a workload is powerful enough to be useful, it is powerful enough to require a real runtime boundary.

MVM provides that boundary as infrastructure.

---

## Conclusion

AI-native infrastructure needs to treat execution as a security boundary, not merely as an application feature.

The systems being built now do more than respond to requests. They interpret user intent, run code, call tools, process files, generate artifacts, and move data between models, APIs, runtimes, and users. That makes the runtime itself one of the most important parts of the security architecture.

MVM provides the runtime boundary AI-native systems need: signed workloads, decorated execution plans, isolated tenants, AI-provider PII redaction, policy-enforced egress, rotating keys, governed artifacts, policy lifecycle, host lifecycle, failure recovery, and mvmd-managed fleet operations.

MVM runs isolated execution environments across multiple runtime backends. mvmd orchestrates tenants, policies, images, secrets, keys, lifecycle, releases, wake/sleep behavior, host management, load distribution, failure recovery, and audit across the fleet. The runtime enforces egress, PII, exploit, and tool-call controls in a path the tenant workload cannot bypass. Signed images and policy bundles define what may run. Key rotation and scoped secret release protect the control layer over time. Policy lifecycle prevents silent runtime mutation. Host lifecycle management keeps infrastructure participation explicit. Attestation support strengthens the trust chain where compatible hardware is available.

The result is a runtime architecture built for the way AI-native systems actually behave: dynamic, tool-using, data-moving, code-executing, and multi-tenant.

MVM exists so teams can run those workloads without treating the application process as the final line of defense.

**Run the workload. Isolate the tenant. Enforce the policy. Rotate the keys. Govern the artifacts. Audit the execution. Release safely. Sleep idle capacity. Wake on demand. Manage the fleet.**
