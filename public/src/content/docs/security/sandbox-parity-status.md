---
title: Sandbox parity status
description: Which sandbox-parity claims mvm makes today, and which are Preview, Planned, or deliberately Not claimed. Backed by ADR-048 and the cargo xtask check-doc-claims lint.
---

mvm makes seven sandbox-parity claims relative to the earlier external sandbox
runtime's published positioning. Each claim has a defined gate
([ADR-048](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/048-claim-safe-sandbox-parity.md))
and a current status. Public docs and release notes use the language
in this table — anything stronger is enforced by the
`cargo xtask check-doc-claims` lint in CI.

## Status taxonomy

| Status         | Meaning                                                                                                                |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Shipped**    | Implemented, documented, tested, and wired through at least one production-capable backend.                            |
| **Preview**    | Implemented behind an explicit flag or limited backend matrix; docs must name limitations.                             |
| **Planned**    | ADR/plan exists; not available to users.                                                                               |
| **Not claimed**| Deliberately absent or rejected.                                                                                       |

## Current status

The seven claim ids correspond to ADR-048
§"The seven target claims". Each row's machine marker (HTML comment
above the row) is what the docs lint reads — flipping the status
requires editing both the marker and the visible cell.

<!-- claim:claims-hygiene status:Shipped -->
<!-- claim:oci-ingest status:Planned -->
<!-- claim:network-policy status:Planned -->
<!-- claim:secret-non-leakage status:Planned -->
<!-- claim:sdk-lifecycle status:Planned -->
<!-- claim:cold-start status:Planned -->
<!-- claim:filesystem-backends status:Planned -->

| Claim id              | Description                                                                                                              | Status      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `claims-hygiene`      | Public docs clearly distinguish Shipped, Preview, Planned, and Not claimed.                                              | **Shipped** |
| `oci-ingest`          | Run digest-pinned OCI images in microVMs without Docker as the runtime.                                                  | **Planned** |
| `network-policy`      | Deny-by-default egress with DNS pinning, SNI/Host enforcement, metadata endpoint protection, and audit.                  | **Planned** |
| `secret-non-leakage`  | Workloads receive opaque secret tokens; real secret values are substituted only by trusted host-side policy.             | **Planned** |
| `sdk-lifecycle`       | Python/TypeScript/Rust SDKs create, run, inspect, snapshot, and stop sandboxes with cleanup bound to the parent process. | **Planned** |
| `cold-start`          | Latency numbers produced by a reproducible harness, split by fresh boot, guest-agent-ready, checkpoint restore, warm pool. | **Planned** |
| `filesystem-backends` | Local, encrypted, object-store, and in-memory filesystem substrates share one contract; mountable vs API-only is stated. | **Planned** |

## What each status means in practice

### `claims-hygiene` — Shipped

This page is the artifact. The companion `cargo xtask check-doc-claims`
lint runs in CI and rejects gated marketing phrases on any page that
isn't this one or the deliberate `mvmforge` migration guide.
Contributors flip a row to Shipped only when the underlying CI gate
exists.

### `oci-ingest` — Planned

Today mvm builds rootfs from a Nix flake or from a bundled template
catalog. There is no `mvmctl image pull` command, no OCI layer
unpacker, and no digest-pinned launch path. The
[round-trip OCI bridge](https://github.com/tinylabscom/mvm/blob/main/crates/mvm-backend/src/docker.rs)
loads mvm-built images into Docker; it does NOT pull upstream images.

To move to Preview: ship `mvmctl image pull` with digest
verification, layer unpack with whiteout, symlink, and hardlink
coverage, and an integration test against a hermetic local registry.

To move to Shipped: production profile rejects mutable tags, audit
events fire for resolve, fetch, cache-hit, materialize, verify,
launch, and delete; mvmd-side consumer is wired (mvmd ADR-0020
cross-repo handoff, tracked in
[mvmd#153](https://github.com/tinylabscom/mvmd/issues/153)).

Tracking work:
[Plan 74 W1](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md#w1--oci-image-ingest),
[mvm#222](https://github.com/tinylabscom/mvm/issues/222),
[mvmd#153](https://github.com/tinylabscom/mvmd/issues/153).

### `network-policy` — Planned

Today's egress enforcement is L3 allow-listing
([ADR-004](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/004-egress-policy.md)).
There is no DNS pinning resolver, no HTTPS SNI/Host policy, and the
metadata endpoint (`169.254.169.254`) is not blocked by default.

To move to Preview: ship the pinning DNS resolver and an L7 proxy
that enforces Host on HTTP and SNI on HTTPS CONNECT, with audit
events for allow, deny, dns-pin, dns-reject, and proxy-fail.

To move to Shipped: per-plan network policy flows through the
signed `ExecutionPlan`; integration tests prove DNS rebinding,
raw-IP bypass, wrong-SNI, and metadata-endpoint denial.

Tracking work:
[Plan 74 W2](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md#w2--programmable-network-policy).

### `secret-non-leakage` — Planned

Today, manually mounted secret files are still readable by the guest
that receives them. ADR-048 §"Non-goals" explicitly states mvm will
**not claim** secret non-leakage for that manual file-materialization
path. The opaque-token + host-side substitution path is Planned for
managed secret refs.

To move to Preview: ship the managed secret token type, host-side
grant registry, and L7-proxy substitution for at least one provider
end-to-end, behind a default-off feature flag.

To move to Shipped: the default flow uses opaque tokens; redaction
wrappers cover plan JSON, logs, audit, errors, cache keys, route
labels, and panic output; hostile-guest exfiltration tests run in
CI; explicit guest-visible file mounts remain manual opt-ins and are
documented as such.

Tracking work:
[Plan 74 W3](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md).

### `sdk-lifecycle` — Planned

`crates/mvm-sdk` ships today as the build-time SDK
([migration guide](/guides/mvmforge-migration/)) — it lets a user
declare a workload, emit canonical IR, and compile entrypoints
statically. There is no runtime lifecycle surface: no Python or
TypeScript `create` / run / `snapshot` / `stop` methods that own
a sandbox from a parent process.

To move to Preview: ship the Rust lifecycle API plus a Python
binding (pyo3), shared fixture suite, parent-process lease using
`PR_SET_PDEATHSIG` on Linux.

To move to Shipped: TypeScript binding via napi-rs; parent-death
cleanup works on both Linux and macOS (kqueue `NOTE_EXIT` on
macOS); static decorator compilation stays separate from the
runtime control surface (no importing user code to inspect it).

Tracking work:
[Plan 74 W4](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md#w4--sdk-owned-lifecycle).

### `cold-start` — Planned

`runtime_boot_bench` covers Apple Container serial and parallel
boots today, but mvm has no published end-to-end latency number
covering Firecracker, libkrun, checkpoint restore, and warm-pool
claim under a single methodology.
ADR-048 §"Non-goals" explicitly forbids claiming
<!-- allow(doc-claim:cold-start): explicit non-goal callout -->
sub-100ms until measured data supports it.

To move to Preview: one canonical report, one host, one backend
(e.g. macOS Apple Silicon + libkrun), p50/p95/p99/max, with
readiness boundary named on every row.

To move to Shipped: the harness runs on at least two backends; CI
budget gates have been green for at least one week;
`specs/perf/` carries a published report contributors can diff
their changes against.

Tracking work:
[Plan 74 W5](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md#w5--cold-start-measurement-and-budgets).

### `filesystem-backends` — Planned

mvm has volume primitives (virtio-fs `--add-dir`, named volumes)
and an instance-snapshot path with HMAC-sealed monotonic-epoch
replay protection. There is no shared `VolumeBackend` conformance
suite and no encrypted, object-store, or in-memory backend.

To move to Preview: conformance test scaffold runs against local
and in-memory backends; capability flags (mountable vs API-only)
land.

To move to Shipped: encrypted and object-store backends pass the
same suite; path-traversal, symlink-escape, concurrent-write, and
large-file edge cases are covered by tests; audit records emit on
attach, detach, read, write, delete, rename, snapshot, and health.

Tracking work:
[Plan 74 W6](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md#w6--extensible-filesystem-backends).

## Deliberately not claimed

ADR-048 §"Non-goals" names the postures mvm rejects:

- Docker or a Docker daemon as the production runtime.
- Kubernetes or Compose compatibility.
- Sub-100ms cold boot before measured data supports it.
- The phrase
  <!-- allow(doc-claim:secret-non-leakage): non-goal callout -->
  "secrets cannot leak" for legacy env/file injection
  flows — those flows reach the guest in plaintext today and the
  ADR forbids the claim.
- Bypassing signed plans, audit, or verified artifact checks for
  developer ergonomics.

These are policy commitments. A future PR cannot flip them by
editing this page alone — ADR-048 must be amended first.

## Reading the table programmatically

The `<!-- claim:<id> status:<word> -->` HTML comments above each
row are the machine-readable source of truth.
`cargo xtask check-doc-claims` reads them per-file: if a gated
phrase fires on a page and the same page declares `status:Shipped`
for the corresponding claim, the lint allows it. This page is also
on a short path allow-list (along with the mvmforge migration
guide) because its job is to *talk about* every gated phrase.

Inline opt-outs use the comment form
<!-- allow(doc-claim:claims-hygiene): example below is markup, not a claim -->
`<!-- allow(doc-claim:<id>): <reason> -->` on the same line or
within two lines above the phrase. The reason field is required
so audit bypasses stay visible in git blame.

## Related reading

- [ADR-048: Claim-safe sandbox parity roadmap](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/048-claim-safe-sandbox-parity.md)
- [Plan 74: workstreams W0-W6](https://github.com/tinylabscom/mvm/blob/main/specs/plans/74-claim-safe-sandbox-parity.md)
- [Plan 74 attack plan: sequencing for W1-W6](https://github.com/tinylabscom/mvm/blob/main/specs/plans/83-w1-w6-attack-plan.md)
- [Seven CI-enforced security claims](/security/ci-claims/) — the
  existing operator-facing security guarantees this page does NOT
  duplicate.
