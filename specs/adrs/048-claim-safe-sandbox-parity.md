# ADR 048: Claim-safe sandbox parity roadmap

- Status: Proposed
- Date: 2026-05-14
- Owner: MVM Project
- Related: ADR-004 (egress policy), ADR-031 (cross-platform strategy), ADR-041 (signed audited execution plans), ADR-047 (app dependency audit pipeline), mvmd ADR-0020 (OCI images as microVM workloads)

## Context

The earlier external sandbox runtime's public positioning has sharpened the product bar for local and fleet-managed code sandboxes (external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`):

- sub-100ms cold start
- embedded, no-root, no-daemon SDK-owned runtime
- cross-platform native operation
- arbitrary OCI image input
- secrets that do not enter the guest
- programmable DNS/TLS-aware network policy
- extensible filesystem backends
- snapshot/fork/restore workflows
- in-perimeter and air-gapped deployment

`mvm` already has stronger operator/security primitives in several areas: Nix-built rootfs artifacts, signed plans, audit chains, dm-verity posture, Firecracker as the Tier-1 backend, vsock-only guest communication, and multi-backend architecture. The gap is that several developer-facing claims are not yet defensible as shipped behavior.

This ADR records the claims we want to make and the runtime primitives `mvm` must own before those claims are allowed in public docs, landing pages, or release notes.

## Decision

`mvm` will pursue claim-safe parity for seven claims, but each claim is gated by implementation and tests. Marketing language must use the claim status taxonomy below until the gate is green.

### Claim status taxonomy

| Status | Meaning |
|---|---|
| Shipped | Implemented, documented, tested, and wired through at least one production-capable backend. |
| Preview | Implemented behind an explicit flag or limited backend matrix; docs must name limitations. |
| Planned | ADR/plan exists; not available to users. |
| Not claimed | Deliberately absent or rejected. |

### The seven target claims

1. **Claims hygiene:** public docs clearly distinguish Shipped, Preview, Planned, and Not claimed.
2. **OCI ingest:** users can run digest-pinned OCI images in microVMs without Docker as the runtime.
3. **Programmable network policy:** deny-by-default egress with DNS pinning, SNI/Host enforcement, metadata endpoint protection, and audit.
4. **Secrets do not enter guests by default:** workloads receive opaque placeholders; real secret values are released only by trusted host-side policy for approved destinations, and only on host-mediated outbound surfaces. Guest HTTPS CONNECT egress is not a request-time substitution path.
5. **SDK-owned lifecycle:** Python/TypeScript/Rust SDKs can create, exec, inspect, snapshot, and stop sandboxes with cleanup bound to the parent process.
6. **Measured cold-start story:** published latency numbers are produced by a reproducible harness and split by fresh boot, guest-agent-ready, snapshot restore, and warm-pool claim.
7. **Extensible filesystem backends:** local, encrypted, object-store-backed, and in-memory filesystem substrates share one contract and state which backends are mountable versus API-only.

## Runtime Ownership

`mvm` owns the local primitives:

- OCI distribution, verification, unpacking, whiteout handling, rootfs materialization, template registration, and launch.
- Local egress enforcement surfaces: L3 rules, DNS pinning resolver, L7 proxy, SNI/Host policy, and audit emission.
- Host-side secret placeholder registry, policy-bound substitution, grant revocation, and redaction at all boundaries.
- SDK process-owned lifecycle over local `mvm` primitives.
- Performance harnesses and budgets for local backends.
- Storage and filesystem backend contracts.

`mvmd` owns fleet/product policy:

- Tenant image policy, registry allow rules, cache isolation, route exposure, and API admission.
- Fleet egress policy, tenant DNS policy, quota, and audit aggregation.
- Tenant secret providers, per-tenant grant policy, and cross-node revocation.
- Warm pools, placement, wake-on-demand, public API, generated SDKs, and web console claims.

If a primitive is missing in `mvm`, `mvmd` must not implement a parallel runtime path. The primitive is added to `mvm` first, then consumed by `mvmd`.

## Claim Gates

### OCI ingest

Public claim allowed only when:

- `mvmctl image pull <ref>` resolves an immutable digest and records requested ref plus launched digest.
- Production profile rejects mutable tags unless an explicit local/dev policy allows them.
- Layer unpacking handles whiteouts, symlinks, hardlinks, ownership, permissions, entrypoint, env, workdir, and exposed ports.
- Rootfs artifacts are tenant/cache scoped correctly.
- Tests cover digest pinning, mutable-tag rejection, private registry auth, whiteout behavior, and secret/cache non-leakage.

### Programmable network policy

Public claim allowed only when:

- `deny` is a first-class default policy.
- DNS answers for allowed names are pinned for the workload lifetime.
- HTTP Host and HTTPS SNI are verified against policy.
- Direct metadata endpoint access is blocked by default.
- Policy decisions emit audit records for allow, deny, DNS pin, DNS reject, and proxy failure.
- Integration tests prove DNS rebinding, raw-IP bypass, wrong-SNI, and metadata access are blocked.

### Secret non-leakage

Public claim allowed only when:

- Default SDK/CLI secret flow gives the guest only an opaque placeholder or a scoped, non-reusable grant.
- Real secret values never appear in guest env, guest files, guest argv, logs, audit detail, plan JSON, cache keys, route labels, error messages, or panic output.
- Substitution is bound to destination policy and transport identity.
- Grant revocation runs on stop, crash, timeout, and parent-process death.
- Tests cover hostile guest exfiltration attempts, destination mismatch, redirect chains, wrong SNI, plaintext HTTP, audit redaction, and crash cleanup.

### SDK lifecycle

Public claim allowed only when:

- Python, TypeScript, and Rust SDKs expose the same core lifecycle surface.
- SDK-created sandboxes are owned by the SDK process unless explicitly detached.
- Parent death triggers sandbox cleanup or documented lease expiry.
- The lifecycle surface works without importing or executing untrusted user code during static compilation.
- Tests cover create, exec, filesystem read/write/list, logs, snapshot, stop, parent cleanup, and error redaction.

### Cold-start

Public claim allowed only when:

- The harness records host, backend, kernel/rootfs digest, CPU model, memory, vCPU count, storage mode, and readiness signal.
- Numbers are published as p50/p95/p99/max and identify the readiness boundary.
- Fresh boot, guest-agent-ready boot, snapshot restore, and warm-pool claim are reported separately.
- CI enforces regression budgets for representative artifacts.

### Filesystem backends

Public claim allowed only when:

- The `VolumeBackend`/filesystem contract has conformance tests reused by every backend.
- Docs distinguish mountable backends from API-only backends.
- Encrypted backends encrypt content and names where promised.
- Object-store backends define consistency, rename, partial-write, and health semantics.
- Tests cover path traversal, symlink escape, concurrent writes, large files, deletion, rename, and audit.

## Consequences

### Positive

- The project can make stronger developer-facing claims without weakening the existing operator/security story.
- `mvmd` can expose product capabilities without forking runtime behavior.
- Docs gain a safe vocabulary for features that are planned but not yet shipped.

### Negative

- OCI ingest and secret substitution increase attack surface and test burden.
- The SDK lifecycle surface forces `mvm` to become more than a CLI.
- Secret substitution requires a trusted egress path; it cannot be bolted onto unrestricted networking.

## Non-goals

- Docker or a Docker daemon as the production runtime.
- Kubernetes or Compose compatibility.
- Claiming sub-100ms cold boot before measured data supports it.
- Claiming "secrets cannot leak" for legacy env/file injection flows.
- Bypassing signed plans, audit, or verified artifact checks for developer ergonomics.

## Implementation Plan

Tracked in [`specs/plans/74-claim-safe-sandbox-parity.md`](../plans/74-claim-safe-sandbox-parity.md).
