---
title: Sandbox parity status
description: Which sandbox-parity claims mvm makes today, and which are Preview, Planned, or deliberately Not claimed. Backed by the cargo xtask check-doc-claims lint.
---

mvm makes seven sandbox-parity claims relative to the earlier external sandbox
runtime's published positioning. Each claim has a defined gate and a current
status, both of which this page owns: there is no separate sandbox-parity ADR.
Public docs and release notes use the language in this table — anything
stronger is enforced by the `cargo xtask check-doc-claims` lint in CI.

## Status taxonomy

| Status         | Meaning                                                                                                                |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Shipped**    | Implemented, documented, tested, and wired through at least one production-capable backend.                            |
| **Preview**    | Implemented behind an explicit flag or limited backend matrix; docs must name limitations.                             |
| **Planned**    | ADR/plan exists; not available to users.                                                                               |
| **Not claimed**| Deliberately absent or rejected.                                                                                       |

## Current status

The seven claim ids are defined by this table. Each row's machine
marker (HTML comment above the row) is what the docs lint reads —
flipping the status requires editing both the marker and the visible
cell.

<!-- claim:claims-hygiene status:Shipped -->
<!-- claim:oci-ingest status:Shipped -->
<!-- claim:network-policy status:Preview -->
<!-- claim:secret-non-leakage status:Planned -->
<!-- claim:sdk-lifecycle status:Planned -->
<!-- claim:cold-start status:Planned -->
<!-- claim:filesystem-backends status:Planned -->

| Claim id              | Description                                                                                                              | Status      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `claims-hygiene`      | Public docs clearly distinguish Shipped, Preview, Planned, and Not claimed.                                              | **Shipped** |
| `oci-ingest`          | Run digest-pinned OCI images in microVMs without Docker as the runtime.                                                  | **Shipped** |
| `network-policy`      | Deny-by-default egress with DNS pinning, SNI/Host enforcement, metadata endpoint protection, and audit.                  | **Preview** |
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

### `oci-ingest` — Shipped

mvm still builds rootfs from a Nix flake or from a bundled template
catalog, and OCI ingest now sits alongside that as a first-class
microVM path rather than a container fallback. `mvmctl image pull`
is a dispatched command; the allow-listed layer unpacker covers
whiteouts, symlinks, hardlinks, device nodes, xattrs, and case-fold
collisions; and `--prod` refuses a mutable, non-digest-pinned
reference before any network fetch. Each `mvmctl run --image`
admission is a signed `ExecutionPlan` that emits an OCI provenance
entry — registry, repo, supplied reference, resolved digest, layer
digests, trust policy, and cosign verdict — into the chain-signed
audit log. That is numbered security claim 14; see the
[CI-enforced security claims](/security/ci-claims/).

The remaining cross-repo work is the fleet-side consumer, which is
outside this claim: mvmd ADR-0020 handoff, tracked in
[mvmd#153](https://github.com/tinylabscom/mvmd/issues/153).

Tracking work:
[mvm#222](https://github.com/tinylabscom/mvm/issues/222),
[mvmd#153](https://github.com/tinylabscom/mvmd/issues/153).

### `network-policy` — Preview

Egress is deny-by-default and enforced at one seam
([ADR-003](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/003-hypervisor-egress-policy.md)):
the per-VM host-side network endpoint, whose `EgressGate` is the sole
decision point for numbered claim 10. Three pieces this row once
listed as missing are live. Host-allowlist DNS pins are resolved once
when the gate is built and the build fails closed on an unresolvable
host, so a later rebind cannot move an admitted destination. TLS SNI
is peeked out of the ClientHello without consuming it and routed by
policy — a bound connection goes to a rustls server, an unbound one
is spliced. And the cloud metadata endpoint (`169.254.169.254`) is
the first entry of the mandatory-deny ranges, which are checked
unconditionally ahead of every grant shape, including `Unrestricted`.

What keeps this Preview rather than Shipped: there is no check that a
CONNECT request's authority matches the SNI actually presented on the
tunnelled ClientHello, so the two can disagree. The destination
allowlist is a literal host-string match today, not a certificate-SAN
pin. Enforcement is also backend-scoped — the dev/test QEMU backend is
type-excluded from the admitted workload path and carries no egress
gate at all.

To move to Shipped: bind the CONNECT authority to the observed SNI,
and cover DNS rebinding, raw-IP bypass, wrong-SNI, and
metadata-endpoint denial with integration tests.

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

### `sdk-lifecycle` — Planned

`crates/mvm-sdk` ships as the build-time SDK
([migration guide](/guides/mvmforge-migration/)) — it lets a user
declare a workload, emit canonical IR, and compile entrypoints
statically. A runtime lifecycle surface also ships in both the Python
and TypeScript SDKs: `create` / `connect` / `exec` / files / `kill`,
plus context managers, and in live mode each shells `mvmctl machine
run` to boot and `mvmctl machine stop` to tear down.

Two parts of this row's description are genuinely absent, which is
what keeps it Planned. There is no `snapshot` method on either
surface. And cleanup is not bound to the parent process in any
enforced sense — it rests on a context manager, an `atexit` handler,
and a default 30-minute TTL that an orchestrator-side reaper
collects, none of which survive a hard parent kill.

To move to Preview: a parent-process lease the kernel enforces
(`PR_SET_PDEATHSIG` on Linux), plus a shared fixture suite across
the two SDK surfaces.

To move to Shipped: parent-death cleanup works on both Linux and
macOS (kqueue `NOTE_EXIT` on macOS); `snapshot` lands on both
surfaces; static decorator compilation stays separate from the
runtime control surface (no importing user code to inspect it).

### `cold-start` — Planned

`runtime_boot_bench` covers HVF serial and parallel
boots today, but mvm has no published end-to-end latency number
covering Firecracker, libkrun, checkpoint restore, and warm-pool
claim under a single methodology.
This page's non-goals below explicitly forbid claiming
<!-- allow(doc-claim:cold-start): explicit non-goal callout -->
sub-100ms until measured data supports it.

To move to Preview: one canonical report, one host, one backend
(e.g. macOS Apple Silicon + libkrun), p50/p95/p99/max, with
readiness boundary named on every row.

To move to Shipped: the harness runs on at least two backends; CI
budget gates have been green for at least one week;
`specs/perf/` carries a published report contributors can diff
their changes against.

### `filesystem-backends` — Planned

mvm has volume primitives (virtio-fs `--mount`, named volumes)
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

## Deliberately not claimed

These are the postures mvm rejects:

- Docker or a Docker daemon as the production runtime.
- Kubernetes or Compose compatibility.
- A round-trip OCI bridge into a container runtime. OCI ingest is a
  microVM path — pull, verify, unpack, materialize a rootfs — not a
  handoff to a shared-kernel runtime.
- Sub-100ms cold boot before measured data supports it.
- The phrase
  <!-- allow(doc-claim:secret-non-leakage): non-goal callout -->
  "secrets cannot leak" for legacy env/file injection
  flows — those flows reach the guest in plaintext today and this
  page forbids the claim.
- Bypassing signed plans, audit, or verified artifact checks for
  developer ergonomics.

These are policy commitments, and this page is where they live —
there is no separate ADR standing behind them. Flipping one is a
maintainer decision, not a docs edit, and the reasoning belongs in
the PR that does it.

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

- [CI-enforced security claims](/security/ci-claims/) — the existing
  operator-facing security guarantees this page does NOT duplicate. That
  is a separate, larger claim family from the seven sandbox-parity claims
  tracked here, and the two numberings do not correspond.
