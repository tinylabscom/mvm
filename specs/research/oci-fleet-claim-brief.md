# OCI and Homepage Claim Readiness

**Full competitive claim audit for mvm / mvmd — August 4, 2026**

## Executive conclusion

Yes: OCI is a first-class concept in the fleet control plane.

No: we should not yet describe OCI as a fully first-class fleet workload source unless we can demonstrate the complete production path from an OCI image reference to a booted, managed microVM on a worker.

The distinction is important:

> We have first-class OCI vocabulary, API objects, registry controls, and a real local OCI runtime path. The remaining gap is proving that the fleet can ingest, materialize, schedule, boot, reconcile, and operate an OCI image end to end.

This document audits the complete product claim surface on the supplied reference homepage, not only its headline. It covers the claims about workload portability, local execution, cloud, customer-owned infrastructure, startup, SDKs, enterprise operations, networking, credentials, operating systems, open source, and availability.

Source analyzed: the supplied homepage, captured August 4, 2026.

## Claim-by-claim audit

The statuses below are intentionally tiered. “Local” means the single-host `mvm` runtime. “Fleet” means the multi-node `mvmd` product. “Cloud” means a live managed service that we operate and support for customers.

| Reference claim | Our current position | What is missing to make the claim strongly and publicly |
|---|---|---|
| **“A computer for anything, anywhere.”** | **Partial.** We support OCI images, Nix flakes, and decorated functions on macOS and Linux, with a broad fleet control plane. | Prove the supported workload envelope, Windows story, customer-owned deployment, fleet production, and managed cloud. Replace “anything/anywhere” with an explicit compatibility matrix until those are real. |
| **Actual microVMs.** | **Strong locally; substantial in fleet.** The runtime uses real hypervisors: HVF, libkrun, and Firecracker. | Complete a fleet production proof that the selected worker backend is always an approved hardware-isolated backend and that fallback tiers cannot silently carry production workloads. |
| **A kernel per sandbox / one workload, one microVM.** | **Strong locally; fleet claim gated.** Each local machine boots its own Linux kernel. | Run the claim through the multi-node scheduler, warm-pool, restore, replacement, and failure paths. Publish backend-specific evidence and explicitly exclude shared-kernel dev tiers. |
| **Run generated code, third-party software, or your own apps.** | **Strong locally; partial in fleet.** Local OCI, Nix, function, agent, browser, and code-execution paths exist. | Demonstrate the same three workload classes through fleet creation, placement, execution, logs, teardown, tenant isolation, and retries. |
| **Local execution.** | **Shipped.** One-host CLI, SDK, and runtime flows exist on macOS and Linux. | Improve installation and first-run proof, publish supported host/backend combinations, and measure cold start and readiness rather than relying on broad “fast” language. |
| **Execution in a managed cloud.** | **Not shipped as a public product claim.** Remote/fleet APIs and cloud-provider provisioning surfaces exist; a supported managed service is not established by the repository. | Operate the service: onboarding, regions, reliability targets, support, billing, data handling, incident response, and a real cloud OCI-to-microVM path. |
| **Execution on the customer’s own infrastructure.** | **Architecture and control-plane support exist; production claim is not closed.** Local runtime and fleet components are self-hostable in principle. | Ship a documented BYOC install, private registry/artifact mirror path, upgrade/rollback process, external-endpoint inventory, air-gapped test profile, and support boundary. |
| **The workload moves while the security boundary stays the same.** | **Partially true.** The client facade has local and remote targets, and the runtime has backend contracts. | Prove artifact portability across local, worker, and customer-owned backends, with identical admission, kernel, filesystem, network, credential, audit, and lifecycle semantics. |
| **Same OCI-image workflow as ordinary container tooling, but with a hardware boundary.** | **Local: shipped. Fleet: incomplete.** Local OCI pull/unpack/materialize/boot is real; fleet OCI import is currently only partially wired. | Finish OCI streaming/pull, conversion, immutable digest resolution, policy enforcement, artifact distribution, worker boot, and negative-path tests. |
| **One command to run the first sandbox.** | **Strong locally.** `mvmctl machine run --image ...` is a real path and the smoke test covers it. | Make the one-command flow work against a production-shaped remote fleet and document authentication, image policy, readiness, and error behavior. |
| **Node, Python, CLI, Claude Code, Codex Skills, and related developer surfaces.** | **Strong on CLI/Python/TypeScript/Rust; partial on integrations.** We have CLI, Python, TypeScript, Rust, MCP, and SDK surfaces. | Provide tested first-party integrations for the named agent workflows, consistent install commands, and parity tests across local and remote targets. |
| **A real microVM in milliseconds.** | **Preview.** Local snapshot/warm paths are benchmarked; fleet start SLOs are unpublished. | Publish p50/p95/p99/max for cold boot, warm claim, snapshot restore, and create-to-exec, split by backend, image size, memory, node type, and readiness signal. Do not use an unqualified “milliseconds” claim until this report exists. |
| **No daemon, no root, no account for local use.** | **Mostly true locally, but needs a contract.** The local client is designed to run without a persistent daemon or account; host prerequisites still vary by backend. | Add a supported-host test matrix proving non-root operation, no account/network requirement for local mode, and clear behavior when `/dev/kvm`, Hypervisor.framework, or libkrun prerequisites are absent. |
| **Rogue code damages its sandbox host, not the developer’s computer.** | **Strong security objective locally.** Hardware isolation, admission, dm-verity, vsock, default-deny egress, and CI-enforced claims exist. | Publish a threat-model-backed escape test report, clarify host-trust assumptions, and prove the same guarantees on every production fleet backend. |
| **The same SDK runs locally and in the provider’s cloud; switching is configuration, not a rewrite.** | **Partial.** The client facade has `LocalBackend` and a remote gateway backend, and `mvmd` has SDK surfaces. | Establish a single versioned lifecycle contract, run conformance tests against local and live remote backends, and close create/start/exec/files/logs/snapshot/fork/stop/destroy parity. |
| **Cloud organizations, SSO, audit logs, quotas, and invoicing.** | **Substantial control-plane coverage; managed-service proof incomplete.** Tenants/organizations, RBAC, audit, quotas, SSO, metering, and billing-related code exist. | Finish production integration and operational evidence: real IdP flows, usage accuracy, invoice correctness, tenant isolation, retention, support procedures, and a live service using them. |
| **Private beta with access by request.** | **Not a substitute for a product claim.** We can offer an evaluation, but a private beta still needs a functioning managed path. | Decide whether we are selling cloud access now. If yes, publish limits, regions, SLA posture, data handling, pricing, and the exact supported workload path. |
| **The same runtime inside a customer VPC or on customer metal.** | **Partial.** Apache 2.0 runtime and self-hosted components are real. | Package and validate the deployment, including private networking, registry access, artifact distribution, upgrades, observability, credentials, and supportability without public internet dependencies. |
| **Inspectable security model; reproducible benchmarks; run locally before putting it in a fleet.** | **A major strength, but not packaged as a competitive proof.** We have public security docs, CI-enforced claims, local runtime code, and benchmark documentation. | Publish a single security portal with threat model, backend matrix, escape tests, benchmark methodology/results, signed release artifacts, and fleet claim evidence. This can become a stronger differentiator than the reference claim. |
| **macOS, Linux, and Windows (WHP, preview).** | **macOS/Linux are supported; Windows is not a shipped native target.** WSL2 is an architectural possibility, not the same as native Windows/WHP support. | Either build and test a Windows/WHP backend, or state clearly that Windows is not supported and avoid “anywhere” language. |
| **Rust, TypeScript/Node, Python, Go, and CLI; MCP workflows.** | **Strong but not identical.** Rust, TypeScript/Node, Python, CLI, and MCP exist. Go is not established as a supported SDK surface. | Add a maintained Go SDK or narrow the claim. Publish versioned SDK compatibility and local/remote parity. |
| **Public internet by default; private, host-local, link-local, and metadata destinations blocked.** | **Different and arguably stronger locally.** Local workloads default to deny-all egress, with explicit host allowlists and host-controlled vsock egress. Fleet networking has bridges, VPCs, and firewall policy, but the full claim matrix is still gated. | Decide on one public default across tiers, implement and test the exact destination classes, publish DNS anti-rebinding and metadata protections, and make the policy explainable and auditable. |
| **Egress can be allowlisted or disabled entirely.** | **Strong locally; fleet Preview/Planned by claim.** `--allow-host`, default-deny policy, host proxying, and audit exist locally. | Carry the exact policy into fleet scheduling and every backend; prove denied traffic fails before leaving the node and allowed traffic is audited. |
| **The cloud cannot lift non-public destination blocking, even for the customer.** | **Not established.** This is a managed-service policy promise. | Implement an immutable provider-side control that customers cannot override, test it against privileged tenant roles and backend escape paths, and document the exception model. |
| **Credentials are destination-bound; workloads see placeholders; host substitutes real values only on approved outbound requests.** | **A local strength; fleet non-leakage claim is not shipped.** Local vsock substitution and secret references exist. The fleet claim matrix explicitly keeps “secrets do not enter guests by default” Planned. | Finish provider abstraction, destination-bound grants, TTL/revocation, cross-node revoke, redaction, and end-to-end tests showing secrets absent from responses, logs, audit detail, errors, and cache keys. |
| **Approved destinations still receive the real credential and can misuse it.** | **We should make this warning part of our own security posture.** Our docs already distinguish secret substitution from a guarantee that a destination is trustworthy. | Publish the same explicit residual-risk warning, scope allowlists, support rotation/revocation, and provide audit evidence for every release. |
| **Open source under Apache 2.0.** | **Shipped.** The repository is Apache 2.0 and the runtime is available as source. | Make the open-source boundary precise: what is open, what is hosted-only, release cadence, signed artifacts, and what BYOC support includes. |
| **Local runtime is free; cloud has private-beta pricing.** | **Not currently a complete commercial claim.** Local source/runtime economics are clear; a live managed service and pricing contract are not established here. | Decide the business model, publish local-vs-cloud boundaries, meter usage correctly, issue invoices, and document support and retention. |
| **Teams already build with it / external credibility.** | **No equivalent public proof should be implied.** Repository functionality is not customer evidence. | Earn this with named design partners, permissioned case studies, public benchmarks, production references, or a transparent evaluation program. |
| **Coding agents, code interpreters, browser agents, multi-tenant workloads, agent evaluations, and regulated workloads.** | **Mixed.** Local documentation and examples cover agent/code/browser patterns; `mvmd` has multi-tenancy, MCP, functions, audit, and policy surfaces. Regulated-workload readiness is not a single shipped product contract. | Create one end-to-end acceptance scenario for each use case, then publish the exact isolation, data, network, credential, residency, audit, and retention guarantees that apply. |
| **Accelerator backing and “all systems operational” presentation.** | **Not a technical parity target.** We should use our own company facts and operational evidence, not mirror another company’s credibility or status language. | Maintain a real status page, incident history, release health, and independent customer proof if we want equivalent confidence signals. |

## The strongest gap is a product contract, not a feature checkbox

The homepage is strong because it presents one coherent contract:

```text
same workload
  → local runtime
  → managed cloud
  → customer-owned infrastructure

same boundary
  → one kernel per sandbox
  → consistent network policy
  → consistent credential handling
  → consistent lifecycle and SDK
```

Our repository has most of the individual ingredients, and in several areas our local security model is more explicit: signed execution plans, chain-signed audit records, dm-verity, default-deny egress, vsock-only host communication, no raw secret value crossing into the guest, and structured PII handling on owned egress paths.

The missing piece is cross-tier parity. A strong homepage claim requires the same guarantee to survive the transition from local host to fleet worker to customer-owned deployment or managed cloud. The work is therefore less about adding another API object and more about proving one portable, immutable workload contract.

## Readiness by layer

| Layer | Status | What that means |
|---|---|---|
| Local OCI runtime | **Shipped** | `mvmctl run --image` pulls and unpacks an OCI image, injects the mvm runtime, materializes a filesystem, applies admission, boots a microVM, and exercises the guest over vsock. |
| Fleet API and data model | **Substantial / first-class** | Pools and sandboxes have image fields. OCI imports, artifacts, repositories, tags, signing policies, pull policies, promotions, scans, and webhooks are represented in the control plane. |
| OCI ingestion for fleet use | **Partial** | The fleet has an OCI import record and lifecycle vocabulary, but the import route currently creates the record and returns `202 Accepted`; the actual image streaming and conversion path is not complete. |
| OCI-to-worker execution | **Not proven end to end** | The worker desired-state model can pull pre-built registry artifacts, but that is not the same as resolving an arbitrary OCI reference, converting it into a bootable artifact, and booting it as a fleet sandbox. |
| Supply-chain enforcement at runtime | **Substantial but incomplete** | Registry policies and signing concepts exist. We still need proof that those policies are enforced on the exact artifact selected and booted by a worker. |
| Managed-cloud claim | **Separate gap** | OCI support does not by itself establish that a production managed cloud is available. That requires a live, supported service with documented limits, reliability, and onboarding. |

## What is already first-class

### 1. OCI is part of the fleet domain model

The fleet API treats `image` as a property of pools and sandboxes, not as an incidental local-runtime flag. A sandbox creation request accepts an image, and the resulting sandbox record retains it.

Evidence:

- `mvmd/crates/mvmd-gateway/src/state.rs`: `PoolRecord.image`, `CreatePoolRequest.image`, `SandboxRecord.image`, and `CreateSandboxRequest.image`.
- `mvmd/crates/mvmd-gateway/src/routes/sandbox.rs`: sandbox creation accepts an image and carries it through tenant, pool, and instance creation.

### 2. OCI imports and artifacts are modeled explicitly

The control plane has an `OciImportRecord` with statuses such as `uploading`, `converting`, `succeeded`, and `failed`. Artifacts can record that they came from an OCI import and retain an artifact revision.

That is more than a marketing placeholder: it is the beginning of a real image-to-artifact pipeline.

Evidence:

- `mvmd/crates/mvmd-gateway/src/state.rs`: `OciImportRecord` and `ArtifactRecord`.
- `mvmd/crates/mvmd-gateway/src/routes/oci.rs`: OCI import creation and status transitions.

### 3. Registry and supply-chain controls are broad

The registry surface includes repository and tag management, scans, signing policies, pull policies, promotions, and webhooks. This gives us a strong control-plane foundation for treating OCI images as governed fleet inputs rather than anonymous blobs.

Evidence:

- `mvmd/crates/mvmd-gateway/src/routes/registry.rs`.
- `mvmd/crates/mvmd-gateway/tests/suites/e2e_sprint112.rs`.

### 4. The local OCI path is real

The local runtime already demonstrates the technically important part: an OCI image can become a running workload inside an isolated microVM.

The live smoke test covers OCI pull and unpack, runtime injection, filesystem materialization, admission, boot, and guest command execution over vsock.

Evidence:

- `tests/oci_image_runner_smoke.rs`.
- `README.md`: OCI image execution, provenance, auditability, and production refusal of mutable image tags.

## What is still missing or needs proof

### 1. Complete the real OCI ingestion path

The current OCI route explicitly says that image streaming is a subsequent production implementation. To close this gap, implement and test:

- authenticated image upload or registry pull;
- OCI manifest, config, and layer retrieval;
- digest calculation and immutable identity;
- signature and attestation verification;
- unpacking and conversion into the filesystem/artifact format expected by the microVM runtime;
- durable status transitions, retries, cancellation, idempotency, and failure diagnostics;
- retention and garbage collection for intermediate layers and completed artifacts.

The import record should not be considered `succeeded` until the resulting artifact is actually bootable or has passed the artifact validation required by the worker.

### 2. Connect the artifact to worker scheduling and boot

The fleet needs a deterministic handoff:

```text
OCI reference
  → immutable digest
  → verified import
  → bootable fleet artifact
  → worker placement
  → Firecracker launch
  → guest readiness
  → reconciled sandbox status
```

The critical proof is not that the API stores an image string. It is that a worker can resolve that string to the correct immutable artifact, boot it, report readiness, and recover from failure.

### 3. Bind policy to the artifact that actually boots

Registry policy is valuable only if it participates in admission and execution. The worker path should enforce, at minimum:

- mutable-tag refusal for production workloads;
- digest pinning or an equivalent immutable resolution step;
- signature and provenance requirements;
- tenant and repository authorization;
- pull-policy semantics;
- artifact freshness and revocation behavior;
- audit records linking tenant, image reference, resolved digest, artifact revision, worker, and sandbox.

The policy decision must be made against the resolved image and artifact, not only against the original user-provided string.

### 4. Build public evidence before making the broad claim

The claim needs a repeatable acceptance test, not just API coverage. Add a production-shaped test that:

1. creates or selects an OCI image by digest;
2. imports or pulls it through the fleet API;
3. waits for conversion and artifact readiness;
4. creates a sandbox or pool from that image;
5. schedules it onto a worker;
6. confirms the microVM boots and executes a guest command;
7. verifies status, logs, audit information, and teardown;
8. exercises rejected signatures, unauthorized images, failed conversion, worker loss, and retry behavior.

Until this exists, the safest public wording should distinguish “OCI support in the fleet control plane” from “run any OCI image across the fleet.”

## What we can claim today

### Safe, accurate wording

> Run OCI images as isolated microVM workloads locally, with fleet APIs for pools, sandboxes, image imports, artifacts, and registry policy.

Or, more concise:

> Run OCI images inside hardware-isolated microVMs locally. Manage fleet sandboxes, artifacts, and image policy through the control plane.

These statements match the implementation while avoiding an unsupported promise that every OCI image is already deployable through the production fleet path.

### Wording to reserve for the completed end-to-end path

Once the ingestion, worker, policy, and acceptance gates are green, we can say:

> Run OCI images across a fleet of hardware-isolated microVMs. Each sandbox gets its own Linux kernel. Deploy locally, on your own infrastructure, or in our managed cloud where available.

The “in our managed cloud” portion should remain conditional until the managed service is live and supportable. It is an availability claim, not merely an architecture claim.

## Recommended implementation sequence

- [ ] **Define the canonical image contract.** Make digest, platform, entrypoint, environment, filesystem expectations, and artifact revision explicit. Decide which OCI image classes are supported first and document exclusions.
  - [ ] Pin the image identity to an immutable digest.
  - [ ] Define supported architectures, manifests, entrypoints, filesystem behavior, and resource limits.
  - [ ] Specify the artifact revision and compatibility contract consumed by workers.

- [ ] **Finish import and conversion.** Implement real upload or registry pull, verification, unpacking, conversion, durable state, retries, and cleanup. Make conversion output a validated, addressable artifact.
  - [ ] Implement authenticated registry pull or upload and layer streaming.
  - [ ] Verify signatures, attestations, manifests, and digests before conversion.
  - [ ] Add idempotency, retry, cancellation, failure diagnostics, retention, and garbage collection.
  - [ ] Mark an import `succeeded` only after artifact validation proves it is bootable.

- [ ] **Wire artifacts into reconciliation.** Have the scheduler resolve the requested image to an approved artifact, place it on a worker, launch the microVM, and report readiness and failure states.
  - [ ] Add artifact distribution and tenant-isolated worker caches.
  - [ ] Reconcile image digest, artifact revision, worker placement, and guest readiness.
  - [ ] Recover correctly from worker loss, conversion failure, placement failure, and retry.

- [ ] **Enforce policy at execution time.** Apply authorization, digest pinning, signature/provenance checks, pull policy, and audit linkage immediately before artifact selection and boot.
  - [ ] Reject mutable tags when the tenant or production policy requires a digest.
  - [ ] Fail closed for unauthorized registries, repositories, signatures, and tenants.
  - [ ] Link tenant, image reference, resolved digest, artifact revision, worker, and sandbox in the audit record.
  - [ ] Prove private registry credentials never appear in API responses, logs, audit detail, errors, or cache keys.

- [ ] **Prove portable security semantics.** Carry the local isolation, network, credential, filesystem, admission, and audit contract across every production worker backend.
  - [ ] Test one-kernel-per-sandbox and hardware-boundary claims through placement, warm pools, restore, replacement, and teardown.
  - [ ] Test deny-first egress, destination policy, DNS anti-rebinding, metadata blocking, and audit behavior.
  - [ ] Test destination-bound secret substitution, expiry, revocation, cross-node revoke, and redaction.
  - [ ] Publish host-trust assumptions and backend-specific exclusions.

- [ ] **Close developer-surface parity.** Make local and remote lifecycle behavior interchangeable through the CLI, Python, TypeScript, Rust, Go if supported, and MCP surfaces.
  - [ ] Run shared conformance tests for create/start/exec/files/logs/snapshot/fork/stop/destroy.
  - [ ] Publish supported SDK versions and first-party agent workflow integrations.
  - [ ] Provide one-command local and remote quickstarts with the same workload contract.

- [ ] **Ship the end-to-end gate and update docs.** Add the multi-step fleet test, negative security cases, operational metrics, runbooks, and public documentation. Then change the feature-status language from planned/partial to supported with explicit limits.
  - [ ] Create or select an OCI image by digest.
  - [ ] Import or pull it through the fleet API.
  - [ ] Wait for conversion and artifact readiness.
  - [ ] Create a sandbox or pool from that image.
  - [ ] Schedule it onto a worker and confirm guest execution.
  - [ ] Verify status, logs, audit information, teardown, and retry behavior.
  - [ ] Run rejected-signature, unauthorized-image, failed-conversion, and worker-loss cases.

## Homepage parity launch checklist

These are the public-proof gates for using strong homepage language. Leave a box unchecked until the evidence is real and repeatable.

- [ ] **Local:** publish the supported macOS/Linux backend matrix and a one-command first-run path.
- [ ] **Isolation:** publish a backend-by-backend report proving one workload per hardware-isolated microVM and one Linux kernel per sandbox.
- [ ] **Speed:** publish cold-start, warm-claim, restore, and create-to-exec p50/p95/p99/max numbers with methodology.
- [ ] **Portability:** run the same immutable workload contract locally, on a fleet worker, and in customer-owned infrastructure.
- [ ] **OCI fleet:** pass the OCI reference → digest → verified artifact → placement → boot → readiness → teardown gate.
- [ ] **Managed cloud:** operate a supported service with regions, limits, reliability, support, data handling, pricing, and incident response.
- [ ] **Customer perimeter:** ship a documented VPC/metal deployment, private registry path, upgrades, rollback, and offline/air-gapped self-test.
- [ ] **Enterprise:** validate organizations, SSO, RBAC, quotas, audit, metering, invoicing, retention, and tenant isolation in production-shaped tests.
- [ ] **Networking:** publish and enforce default behavior, allowlists, destination classes, DNS policy, metadata protection, and immutable managed-cloud restrictions.
- [ ] **Credentials:** ship provider abstraction, destination-bound substitution, TTLs, revocation, cross-node revoke, redaction, and non-leakage tests.
- [ ] **Developer experience:** publish CLI, SDK, MCP, and agent workflow parity with versioned compatibility guarantees.
- [ ] **Platform:** either ship native Windows/WHP support or narrow the public platform claim to the backends we actually support.
- [ ] **Proof:** publish threat model, benchmark reports, signed releases, status page, customer evidence, and the exact boundary between open-source runtime and hosted services.

## Decision

We should correct the earlier characterization:

- **OCI is first-class in the fleet control plane.** The API and data model are not the main gap.
- **OCI is first-class in the local runtime.** The local image-to-microVM path is real and tested.
- **OCI is not yet fully proven as an end-to-end fleet execution path.** The missing work is the production ingestion/conversion pipeline, worker boot integration, runtime policy enforcement, and public acceptance evidence.

So the answer to “can we use the same broad homepage language?” is:

> We can confidently claim actual microVMs, a kernel per sandbox, local OCI workloads, generated code, third-party software, and self-hosted execution where the documented runtime path applies. We should not yet claim unrestricted OCI fleet execution or “in our cloud” until those two separate production gates are closed.

## Repository evidence reviewed

- `README.md`
- `tests/oci_image_runner_smoke.rs`
- `crates/mvm-core/src/domain/agent.rs`
- `mvmd/crates/mvmd-gateway/src/state.rs`
- `mvmd/crates/mvmd-gateway/src/routes/sandbox.rs`
- `mvmd/crates/mvmd-gateway/src/routes/oci.rs`
- `mvmd/crates/mvmd-gateway/src/routes/registry.rs`
- `mvmd/crates/mvmd-gateway/tests/suites/e2e_sprint25.rs`
- `mvmd/crates/mvmd-gateway/tests/suites/e2e_sprint112.rs`
- `mvmd/docs/feature-status.md`
