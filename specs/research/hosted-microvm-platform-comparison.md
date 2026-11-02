# Research — a hosted microVM platform, compared at the product and trust level

Backing: preview
Validation: none — a research note read from the comparison vendor's public
documentation and from the source of this repository and its sibling
control-plane repository. Nothing here is a shipped-behavior claim.

**Date:** 2026-11-02
**Owner:** mvm
**Source:** The comparison vendor's public documentation (44 pages, plus an
LLM-oriented index and an OpenAPI document). Their stack is a local engine CLI
plus a separate hosted service with an SDK for both. On our side: this
repository (`mvm`, the host-side execution authority) and the sibling
control-plane repository at `../mvmd` (the fleet authority).

**Where it lives.** This note is attached to the tracking issue for its
findings rather than kept in the tree: `specs/` now holds only the PRD, the
README, the ADRs, and the contracts, and the repository root is allow-listed
too, so no in-tree directory fits a research note. The issue holds the
checklists; this note holds the evidence and the tables.

**Naming rule.** The comparison vendor is referred to as *the vendor* throughout.
No product, organization, package, artifact, environment-variable, or endpoint
proper name of theirs appears here, nor in any branch, commit, or PR that
carries it. Describe their surfaces by role instead. This is a handling rule
for whoever picks the file up next, not a restatement of a legal position.

The precedent this rule follows — an earlier oblique comparison of another
competitor product — was retired from `specs/` along with the rest of the
research notes and now lives in the `specs-archive-2026-11-02` tag.

## TL;DR

Their stack is a **product**: a local engine plus a hosted service that an agent
can use in minutes, with a published SDK, a local HTTP API, a console, and
metered billing. Ours is a **trust platform**: signed admission, verified boot,
hash-chained audit, enforced egress, and a cryptographically chained fleet
control plane — with a user-facing surface that has not caught up and a
control-plane repository that is a well-documented prototype rather than an
operable fleet.

The interesting axis is not feature count. It is *where authority lives*. Their
cloud is a rented service whose admission is an authenticated API call. Ours
splits authority explicitly: a fleet signs a launch permit and a plan, a host
independently refuses stale reservations, and no component can both choose and
accept. That split is real and enforced in code — and it is exactly what their
documentation never mentions.

Their clearest structural advantages over us are first-class Windows support, a
graphics path, a hosted control plane with real money rails, and a much simpler
command surface. Our clearest advantages are the trust chain, the NIC-less
egress model, launch-budget discipline, and a reproducible artifact pipeline.

## The two stacks

```text
theirs:   local engine CLI ──┬── SDK (Node/TS + Python)
                             └── hosted service (their hardware)
             portable pack artifact

ours:    mvmctl ── mvm (host-side admission, hypervisor, enforcement)
             │
             └── mvmd (fleet identity, placement, leases, metering, messaging)
                      │
                      └── nodes (enrolled hosts, each running mvm)
```

Three authority scopes in ours, and the boundary is documented and enforced
rather than implied: **mvm** remains the local admission and execution
authority (execution-plan admission, hypervisor, filesystem/network/secret
enforcement); **mvmd** owns fleet identity, placement, capacity, and messaging;
the **host** owns actual resources and may refuse work but cannot mint fleet
authority.

## 1. Product surface

| | **mvm** | **vendor** |
|---|---|---|
| Local CLI | `mvmctl` — 50 top-level commands, deep subtrees | one `machine` group (~35 verbs) plus `pack` and `serve` |
| Hosted service | none in this repository; the sibling control plane is self-hosted | first-class multi-tenant service: orgs, sub-orgs, members, scoped keys |
| Local daemon API | none — MCP over stdio only | `serve` → HTTP with a versioned prefix, OpenAPI output, warm-pool leases, SSE exec streaming, no authentication (bind to loopback) |
| SDKs | Python (`mvm` 0.15.2) and TypeScript (`@runmvm/mvm` 0.15.2) runtime SDKs **partial**; Kotlin pack-authoring source only, unpackaged; Rust `MvmClient` lifecycle client | Node/TypeScript and Python (synchronous plus an async variant), published, with jobs, port links, endpoint/fetch helpers, typed error classes |
| Install | install script, Homebrew, or a source build with a pinned toolchain | single-command script install |
| Fleet | self-hosted; `mvmctl deploy` seals locally, then ships to the control plane | hosted only |
| Machine-readable errors | error-code catalogue in the client crate | stable codes on every command (`{"error":{"code":...}}`), RFC 9457 `application/problem+json` on the hosted API, `x-request-id` on every response, guest exit-code passthrough |

## 2. Isolation, egress, credentials

| | **mvm** | **vendor** |
|---|---|---|
| Guest NIC | **never** — no routable NIC on any workload backend | default backend exposes no visible interface (loopback plus a dummy device only); a real interface appears when ports are published or a credential is bound |
| Egress | every connect, datagram, and DNS answer is decided by one gate in a per-VM host endpoint, reached over vsock; a build gate pins the single spawn site so a backend cannot grow a second path | host-side gateway on the interface-bearing backend; allow/deny hostname and CIDR lists, private-range blocking; a deny is checked before any allow |
| Default posture | deny-all, always; the network policy is **derived** from the signed grant set so the policy in force and the policy the plan was signed over cannot drift | local: off by default; hosted: the network mode defaults to **open** when omitted |
| Credentials | managed substitution — the guest receives a placeholder and the host substitutes; the manual path still ships raw bytes, and our own ledger marks that gap honestly | two explicit models: injection (plaintext in the guest, documented as such) and substitution (opaque placeholder, host-side substitution restricted to HTTPS to bound hosts, header-only unless opted into bodies, refused in URLs) |
| Host-process confinement | Landlock plus seccomp self-confinement on the secret-holding endpoint and per-VM supervisors | seccomp allowlist plus Landlock on the **VMM** process; the enforcing mode fails closed; ignored on macOS |
| Credential/network coupling | one decision: the signed grant set | credential hosts must fall under the network allow-list, so widening the network never widens a credential |

Their substitution model is the more polished one (wildcards, per-branch
resolution, a per-machine trust bundle). Ours is the more structural one (no
interface at all, policy derived from a signed artifact).

One open question on their side: their documentation ties the egress gateway to
the interface-bearing backend and says naming the default backend alongside any
policy flag is refused. The default backend's egress posture is the
least-documented part of their model and is worth verifying before we draw a
conclusion from it.

## 3. Trust and assurance — our clearest lead

| Capability | **mvm** | **vendor** |
|---|---|---|
| Admission | signed execution plan (Ed25519) over a canonical-JSON plan, admission-time signing, grant ceilings, replay protection, validity windows, optional pinned external signers | egress allow-lists only — no plan, no signature, no admission artifact |
| Audit | hash-chained Ed25519 audit log, receipts, provenance, attestations; the verifier also builds for wasm | **silent** |
| Artifact trust | signed portable archive carrying kernel, rootfs, dm-verity pair, sidecar, runtime overlay; publisher trust store; revocation feeds; a canonical-Linux-proof member; content-address determinism gates | unsigned pack and checkpoint artifacts; the manifest records platform and engine version only |
| Verified boot | dm-verity seal, pinned image-set manifests, image-reproducibility gates | **silent** |
| Policy engine | network policy, grants, budget and ceiling projection, approvals, protected paths, DNS guard and pinning, action budgets, restricted addresses | allow/deny lists and private-range blocking |
| Claim verification | **25 machine-checked claims** with typed witnesses, **45 enforced build gates**, **431 BDD scenarios**, and documentation that is compile-tested against the real crates | no claim, witness, or audit machinery anywhere in their documentation |

Their documentation is silent on: audit trail, signed artifacts, verified boot,
attestation, provenance, threat model, SBOM or CVE management, and any policy
engine beyond egress lists. Silence is not a disproof — but it means their
product cannot currently be compared on this axis, and any future comparison
should say so that way.

## 4. Platforms, GPU, artifacts, performance

| | **mvm** | **vendor** |
|---|---|---|
| Hosts | Linux x86_64 and aarch64 (Firecracker), macOS 26+ Apple Silicon (in-house HVF, no Homebrew prerequisites), QEMU and libkrun as substrate, plus a container and a wasm tier | Linux x86_64 and aarch64, macOS 11+ Apple Silicon, **native Windows x86_64** via the Windows Hypervisor Platform, WSL2 on Windows 11 |
| Windows | explicitly unsupported; the platform type says so | first-class, with branching and checkpointing, live branch requiring a frozen source, and no graphics |
| GPU | CUDA driver, CUDA runtime, and NVML **remoted over vsock**: 38/26/10 guest symbols, 33+9 host symbols, a 36-method backend trait, a deterministic stub backend for CI, per-VM endpoint selection. **No graphics path at all.** | **graphics via a paravirtualized GPU with Venus** (headless browsers, WebGL, ANGLE), plus CUDA remoting over vsock. No direct passthrough either. Their hosted service has no GPU at all. |
| Portable artifact | signed archive — kernel, rootfs, dm-verity, sidecar, runtime overlay, with the publisher trust store consulted on every launch | pack — disk only, no RAM, unsigned, two files |
| Live branching | template and slot level fork, plus lineage and time-travel (timeline, revert, rewind, advance), checkpoints (create, restore, fork, diff, verify), durable agent sessions | live copy-on-write clone of a running machine, batch fan-out with a name prefix and a parallelism bound, waiting on a workload-declared branch point; host-local, not exportable |
| Checkpoint | create, restore, fork, diff, verify | RAM plus processes into one portable file; versioned; portable across same-OS/arch hosts plus one macOS-to-arm64-Linux direction; refuses capture when host mounts, sockets, remote volumes, host secret references, or GPU state are present; incremental store with generation selection |
| Warm standby | `pool warm` — shape-matched standby claims with a published 30 ms median budget and a 300 ms hard ceiling enforced at launch | warm pools in the local API with leases and heartbeats (same word, same idea) |
| Published latency | budgets enforced in CI (prepared-cold median 200 ms, p95 250, p99 300, every boot under 300 ms; warm-claim median 30 ms), raw per-sample vectors retained, host-fingerprint comparability required, contaminated samples **refused** | **no numbers.** Only qualitative: "normally takes a few seconds", "a fraction of a second", "several times slower on a mount" |

On GPU we are at parity on the remoting concept and they own the graphics lane
outright. On performance *discipline* we lead — but our published dataset is a
single row on one host, and our own ledger still marks the cold-start benchmark
as Planned. That is the softest edge of an otherwise strong position.

## 5. The hosted-service comparison

Our hosted story is the sibling control-plane repository. The comparison below
is against their hosted service.

| | **their hosted service** | **our control plane** |
|---|---|---|
| Who runs the hardware | them | you do — self-hosted and sovereign |
| Tenancy | orgs, sub-orgs, members, invitations; per-tenant ceilings on machine count, vCPU, memory, and disk | organization → fleet → node → instance; 6 roles × 8 actions; ceilings are **budget holds in integer microunits** |
| Auth | prefixed bearer key with 9 scopes | bearer key, BLAKE3-hashed at rest, compared in constant time, role-scoped; **no expiry and no revocation path** |
| Admission | authenticated request → ceiling check → machine | authenticate → authorize → idempotent start intent → **budget hold** → hard filters → deterministic integer ranking → reservation offer → host atomic reserve → reservation receipt → signed placement lease → launch permit → boot |
| Fencing | none visible | **two generations**: a node-local resource generation (stale reservation refused) and a controller-local placement generation (fences stop and replace) |
| Cryptographic chain | none | node-signed receipt → fleet-signed lease → launch permit carrying the **fleet-signed execution plan**, bound by digest and independently re-checked by the node before launch |
| Accounting | metered execution, prepaid balance, `402`, grace period, capacity introspection | usage receipt with **sequence, previous-receipt digest, node signature**, and dimensions in vcpu-nanos, memory-byte-nanos, disk-byte-nanos, ingress and egress bytes, all checked integer arithmetic |
| Messaging | none | encrypted workload-to-workload mailboxes (X25519 + XChaCha20-Poly1305), at-least-once, FIFO, idempotency-key dedup, bounded lease/ACK/NACK with a dead-letter terminal state, assignment fencing |
| Cross-host fabric | hidden | QUIC carrier with fixed application-protocol lanes, signed per-RPC envelopes (audience, validity window, nonce, payload digest), durable replay state in the node store, quarantine-before-admission binding the membership certificate to the exact connected endpoint |
| Extras | in-service checkpoints and rollback, cache disks, port links, custom domains, detached jobs, interactive WebSocket execution, usage and capacity endpoints, API explorer | none of these |
| Public surface | a documented, versioned, explorable REST API | 13 routes; tenancy carried by the principal rather than the path; no instance-list, usage, or ledger read routes |

Their control plane wins on operability: sign-up, no cluster to run, real money
rails, hardware churn owned by them, a console, and an explorable API. Ours
wins on the chain: nothing in their flow is signed, and the entire fleet path
here is a sequence of signed, generation-fenced, replay-protected artifacts.

The decisive structural difference: a controller can choose a host but cannot
force it to accept; a host can accept or refuse but cannot mint fleet
authority. Their service has one authority, and the customer cannot audit any
part of it.

## 6. Where the vendor is ahead

1. **Time to value.** Install, create a machine, execute — three commands.
2. **A local daemon API.** Agents want HTTP; we have stdio MCP only.
3. **A shipped hosted service** with orgs, metering, and a console.
4. **Windows.**
5. **Graphics.**
6. **Error contracts** for scripting: stable codes, problem+json, request IDs,
   guest exit-code passthrough.
7. **SDK completeness** — detached jobs, port links, endpoint helpers, an async
   Python variant.
8. **Docs breadth per page** — an API reference, an explorer, a pricing page,
   and per-integration pages.

## 7. Where we are ahead

1. **The trust chain** — plan signing, verified boot, hash-chained audit, and a
   fleet path of signed permits that our competitor's documentation never
   mentions.
2. **Egress posture** — deny-all with a policy derived from a signed artifact,
   against a hosted default of open.
3. **Measurement discipline** — budgets as ceilings, CI-enforced, contaminated
   samples refused, comparability fingerprints.
4. **Reproducible supply chain** — a Nix builder VM producing signed,
   dm-verity-sealed, content-addressed artifacts.
5. **Backend breadth** and an in-house HVF with no Homebrew prerequisites.
6. **Governance** — 25 claims, 45 gates, 431 scenarios, compile-tested docs.
7. **A sovereign, self-hostable fleet authority** with an explicit authority
   split.

## 8. Open questions and gaps, with evidence

Findings, not assignments — the owner, tracker, and closure criteria belong in
an issue, not in this file.

### In the control-plane repository

Paths below are relative to the sibling control-plane repository at `../mvmd`.

| Finding | Evidence |
|---|---|
| No fault tolerance: the peer-death contract is unwired dead code, there is no heartbeat, no failover, and no re-placement; replacement is a manual API call and the conformance scenario for host loss requires an explicit replacement step. The repository's own README defers fleet HA as the next milestone. | `crates/mvmd-core/src/peer.rs`; `crates/mvmd-core/src/controller.rs`; `features/suites/s1_fleet_lifecycle/fleet_lifecycle.feature` |
| The suite that would prove the product claim does not run in CI: the live-microVM BDD target is feature-gated and the BDD recipe is not in CI, and the MVM adapter is **excluded from the workspace**, so its tests never compile or run — CI runs dependency auditing on it only. | `crates/mvmd-conformance/Cargo.toml`; `.github/workflows/ci.yml`; workspace `Cargo.toml` exclude list |
| Usage is never metered in the shipped path: settlement and receipt import exist and are idempotent, but have **no production caller**, and no transport variant carries a receipt. | `crates/mvmd-core/src/billing.rs`; `crates/mvmd-core/src/transport.rs` |
| No TLS on the HTTP API (plain listener, no TLS dependency) and **no API-key revocation or expiry** route or command. | `crates/mvmd-api/src/lib.rs`; `crates/mvmd/src/main.rs` |
| The mailbox is not reachable by a user: there is no NACK route, so redelivery is unreachable; the only producer of an assignment is the demo command; placement never assigns one; there is no guest-side path. | `crates/mvmd-api/src/lib.rs`; `crates/mvmd/src/main.rs` |
| Persistence cannot evolve: a single create-if-not-exists batch, no schema version, no alter path, so an added column breaks existing databases. No backup or restore code. No metrics endpoint. | `crates/mvmd-core/src/store.rs` |
| Operational burden: no install script, no container image, no service unit; the all-in-one command runs controller and nodes in one process over in-process IPC, and the demo path uses a no-op executor, so no microVM boots. | `crates/mvmd/src/main.rs` |
| Two API shapes are in flight. The control plane serves `/v1/instances` and friends, with tenancy carried by the principal rather than the path. The client-side remote backend in this repository — the one `mvmctl`'s remote surface speaks — expects a different sandbox- and tenant-shaped prefix. Resolve before either hardens and gains consumers. | control plane: `crates/mvmd-api/src/lib.rs` (sibling repository) · client: `crates/mvm-core/src/client/gateway.rs` (this repository) |

### Documentation defects found while comparing

These are the most damaging class of defect for a project whose pitch is that
it does not overclaim.

| File | Defect |
|---|---|
| `docs/SECURITY.md` (control-plane repository) | Lists the Noise carrier among the authenticated encrypted cross-host channels and frames quarantine around a Noise peer, while the **production carrier is the QUIC carrier** and Noise is labelled a reference carrier in code. The document never distinguishes them and never says the private-route carrier is experimental and unwired. |
| `docs/PRIOR_BLUEPRINT.md` (control-plane repository) | Lists seven "package contents" that **do not exist** in the repository. It also describes an authenticated encrypted vsock session for guest/host communication; no such transport exists in that repository. |
| `MANIFEST.sha256` (control-plane repository) | Stale — lists a file that does not exist. |
| `VALIDATION.md` (control-plane repository) | States a test count that does not match the tree. |
| `CLAUDE.md` (this repository) | Says builder auto-detect answers the HVF builder on Apple Silicon macOS and that the 13–25 tier therefore reports the macOS 26 floor as unavailable. The code and its own unit test answer the **QEMU** builder there. The same file calls that backend opt-in only, and omits a backend value the flag accepts. `crates/mvm-build/src/builder_backend_select.rs`; `crates/mvm-cli/src/commands/mod.rs` |

### In this repository

1. **A local HTTP daemon** is the biggest single product gap against agent
   frameworks.
2. **The runtime SDKs are partial.** The published surface is narrower than
   the competitor's, and the third language is unpackaged.
3. **More published latency rows.** We hold the strictest methodology in the
   comparison and one row of results.
4. **A beginner-UX pass on the command surface.** Fifty top-level commands is
   a real ergonomic deficit even though a beginner group already exists.
5. **Decide explicitly on graphics and Windows** rather than by omission.
6. **Live copy-on-write branch parity** if agent fan-out is our wedge — weighed
   against the artifact-signing story, where we are clearly ahead.

## 9. How to keep this current

- This note is research, not a tracker. The findings above point at evidence;
  the issue checklists own status, owners, and closure.
- Re-read the vendor's documentation when a new release note appears and
  update the affected tables rather than appending a new section — the tables
  are the artifact, and a second copy of them is how comparisons rot.
- Keep the naming rule. If a future revision needs to reference a specific
  vendor artifact by name, describe it by role instead and keep the rule.
- Record what changed in the revision history below.
- When a finding above is fixed in either repository, strike it and say what
  closed it, so the note does not read as a stale list of complaints.
- **Gates.** This note lives with the tracker rather than in the tree, so no
  build gate can reach it. For reference, the lints now scan
  `public/src/content/docs` and `public/src/pages` for the published docs,
  `specs/adrs` and `specs/contracts` for the decision records, and every
  tracked path under `specs/` and the repository root for layout. One of them
  reports false positives locally: the overclaim lint walks the filesystem
  rather than the tracked tree, so it picks up stale agent-sandbox copies
  under the git-ignored `.delta/`, `.qwen/`, `.claude/*`, and `.worktrees/`
  roots. Every violation it reports is in one of those copies, and a clean
  checkout is unaffected.

## Revision history

| Date | Change |
|---|---|
| 2026-11-02 | Initial note. Vendor documentation read in full (44 pages); this repository and the sibling control-plane repository inventoried at source level. |
| 2026-11-02 | Moved out of the tree to this issue after the `specs/` retirement retired `specs/research/`. Corrected two references that the retirement invalidated: the naming-rule precedent, and the lint roots. |
