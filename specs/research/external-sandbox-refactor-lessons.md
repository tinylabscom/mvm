# Research — lessons from a comparable AI-sandbox offering for the mvm refactor

**Status:** Research note; no implementation commitment
**Date:** 2026-07-22
**Owner:** mvm
**Source:** A hosted AI-agent sandbox offering from a major cloud vendor, open-sourced under Apache-2.0 in April 2026. Reviewed from its public architecture docs, quickstart, and launch write-up. Named obliquely throughout, per the house convention in `specs/adrs/001-microvm-security-posture.md` §"Appendix: Cardoso minimum-viable-policy checklist"; competitor and product proper names are deliberately omitted, including the incumbent hosted-sandbox SDK it is wire-compatible with.

## TL;DR

The referenced external offering is a KVM microVM sandbox for AI agents, built on the `rust-vmm` building blocks plus a self-developed VMM, and wire-compatible with the incumbent proprietary code-interpreter SDK. Architecturally it converges on the *same thesis mvm already holds*: hardware-isolated microVMs with a per-guest kernel, a minimal virtio device set, default-deny/allowlist egress, and host-side credential injection so secrets never enter the guest.

That convergence is the most useful finding: it independently validates several bets the mvm refactor has already placed (in-house minimal-device VMM, warm-snapshot restore, host-side secret substitution). The offering is not a security-posture peer — as documented it has no signed-and-audited admission, no verified boot, no supply-chain claim ladder, and no interactive-surface exclusion. Most of its surface (a cluster orchestrator, node scheduler, multi-node scaling) maps to mvm's *sibling fleet product*, not to mvm's single-VM CLI scope.

Worth borrowing (details below): (1) copy-on-write / dirty-page **snapshot-and-fork** as an agent-facing DX primitive; (2) a **wire-compatible client adapter** for the incumbent SDK as an adoption on-ramp; (3) a **named, first-class egress-proxy component** with a domain-allowlist UX; (4) **published density/latency SLOs**. Do not borrow: a guest-NIC eBPF network data plane, or a mutable shared store as control-plane authority — both regress mvm claims or invariants.

## What was reviewed

The offering describes itself as production infrastructure for AI agents that hosts long-running agent processes, stateful service stacks, and one-shot code execution behind one lifecycle. Documented shape:

- **Isolation:** each sandbox runs its own Linux kernel inside a KVM microVM; "no shared-kernel escape surface." The stated motivation is precisely the container multi-tenant-escape problem, traded against VM cold-start/memory cost.
- **VMM:** self-developed rather than an off-the-shelf VMM, built on `rust-vmm` + KVM, retaining only `virtio-net`/`virtio-blk`/`serial` and a trimmed guest kernel "with only the minimal feature set required for agent execution." Hypervisor is seccomp-hardened.
- **Boot/perf:** sub-60–100ms cold start via a pre-warmed pool plus CoW clone from a template sandbox (not raw VM boot speed); <5 MB overhead per instance; a claimed 2000+ concurrent sandboxes on a 96-vCPU host; P95 ~90ms under 50 concurrent creations. Vendor-published, not independently benchmarked.
- **Storage/snapshots:** a CoW engine using the kernel `FICLONE` ioctl for O(1) clones, metadata-only snapshots (shared extents, no byte copy), and incremental dirty-page memory tracking to "fork multiple exploration branches" or roll back. One secondary source describes snapshot/fork as still-maturing, which conflicts with the architecture page presenting it as shipped — treat it as early.
- **Networking:** per-sandbox TAP device; an eBPF kernel-space data plane doing SNAT/DNAT and policy without iptables; a transparent L7 egress proxy (OpenResty + Lua) enforcing a zero-trust domain allowlist on all outbound traffic.
- **Secrets:** "credential injection" — the egress layer appends `Authorization` headers on the way out so keys "never enter the sandbox, model context, or logs."
- **Control plane:** a REST gateway wire-compatible with the incumbent SDK, a cluster orchestrator, a node scheduler, a `containerd` shim-v2 bridge, a reverse proxy, and a shared in-memory store as "single source of truth" for sandbox metadata/events. Control-plane components are partly Go; the data-plane VMM/shim/egress are Rust.
- **DX:** drop-in migration by repointing the SDK's base-URL env var; a `run_code(...)`-style one-shot exec API; templates built from an OCI image via a CLI; a browser console for administration.

## Architecture at a glance

| Concern | External offering | Nearest mvm equivalent |
|---|---|---|
| Isolation boundary | KVM microVM, per-guest kernel, minimal virtio set | ADR-001 L1/L2; Firecracker (Tier 1), HVF/libkrun (Tier 2) |
| VMM provenance | Self-developed on `rust-vmm` + KVM | In-house HVF VMM (ADR-098 / Plan 214); Firecracker on Linux |
| Warm start | Pre-warmed pool + CoW clone from template | Warm-snapshot direction (ADR-025); `vm/` checkpoints |
| Snapshot/fork | `FICLONE` O(1) clone + dirty-page memory delta | `vm/` templates + checkpoints; not yet an agent-fork DX |
| Egress control | eBPF SNAT/DNAT + L7 MITM proxy, domain allowlist | Claim 10 default-deny; nftables (FC) / gateway-bridge `PlanFlowPolicy` (libkrun) / vsock gate (HVF) |
| Secret handling | Egress appends `Authorization`, secret never in guest | Claim 13 + preview claim 16 egress substitution |
| Admission/authority | Mutable shared store as source of truth | Claim 8 signed, validity-windowed `ExecutionPlan` + chain-signed audit |
| SDK model | `run_code(str)` + incumbent-SDK wire compat | Build-time decorator → Workload IR → Nix; transient `run` / exec runner |
| Platform reach | KVM x86_64 Linux only | Linux KVM **and** macOS (HVF / libkrun) |
| Scope | Cluster orchestrator + multi-node (fleet) | Single-VM CLI; fleet is the sibling product |

## (a) Ideas genuinely worth borrowing

1. **Snapshot-and-fork as an agent-facing DX primitive (highest value).** The offering packages CoW clone + dirty-page memory delta as a product capability: "roll back to any saved state or fork multiple exploration branches." mvm already has the substrate — `vm/` checkpoints and the warm-snapshot prior-art boundary in ADR-025 — but not the agent-centric *fork N branches from a warm state* story. This is squarely refactor-aligned (the overlay-only runtime and in-house-VMM work already touch the pieces). Mapping: expose fork/restore over the `VmBackend` seam, keyed on a checkpoint identity. **Hard constraint:** a forked or restored VM must not bypass admission — it must inherit or re-admit a signed `ExecutionPlan` (claim 8) and, on block+ext4 backends, keep its dm-verity binding (claim 3). A fork that silently reuses authority would be a claim-8 hole. Captured as a design guardrail, not a shortcut.

2. **A wire-compatible client adapter for the incumbent SDK.** Their entire adoption pitch is "change one URL env var, zero code changes." mvm's `mvm-client` facade already has a `GatewayBackend` seam; a thin, host-side, audited translation from the incumbent SDK's `run_code`-style ephemeral-exec calls onto mvm's transient-run path would give the same on-ramp without adopting their execution model or abandoning mvm's decorator→IR philosophy. Keep it a pure translation layer: every admitted exec still synthesizes and signs an `ExecutionPlan` and emits audit entries. This is a DX/distribution win, not an architecture change.

3. **Name the egress proxy as a first-class, observable component.** mvm *enforces* claim 10 (default-deny) and secret substitution today, but they are described as backend-internal mechanisms (nftables ruleset, gateway-bridge policy, per-VM vsock gate). The offering's "named L7 egress component + explicit domain-allowlist UX" is a packaging and observability idea: give the operator one place to read "what this workload is allowed to reach," surfaced in `mvmctl doctor` / receipts. Capability already exists; the borrow is presentation, discoverability, and a stated allowlist UX.

4. **Publish warm-start and density SLOs.** They lead with measured numbers (cold start, per-instance overhead, concurrent density, P95/P99). mvm already measures boot/perf internally; as the snapshot path matures, turning those into stated, doc-level SLOs makes performance a claimed, regression-gated property rather than folklore — consistent with how mvm already treats security properties as CI-gated claims.

5. **Convergent validation of the in-house-VMM bet (reassurance, not an action).** An independent team, optimizing for the same agent workload, also chose a self-developed minimal-device VMM on `rust-vmm`, a trimmed guest kernel, and pre-snapshot restore over an off-the-shelf VMM. That is exactly the mvm refactor's HVF direction (ADR-098 / Plan 214) and the minimal L2 device set. Worth citing when the in-house-VMM cost is questioned. The shared `rust-vmm` crate base (a community crate set, not a competitor product) is also a candidate to share rather than reimplement, subject to ADR-002 dependency review.

## (b) Where mvm already does something equivalent or stronger

Do not read the offering as exposing gaps in mvm; on the security axis mvm is broader. As documented, the offering asserts *isolation + egress* and little else. mvm's fifteen CI-gated claims cover strictly more:

| mvm property | Claim | External offering as documented |
|---|---|---|
| Signed, validity-windowed, replay-gated admission | 8 | None; authority is a mutable shared store |
| Chain-signed audit log with drift detection | 8, 12 | None stated |
| Verified boot (dm-verity rootfs, panic-on-tamper) | 3 | None; "trimmed kernel" is not rootfs integrity |
| Content-addressed, key-id-pinned signed bundles | 9 | None stated |
| Sealed dep volumes: SBOM + CVE + attestation | 11 | None stated |
| OCI image provenance in the audit chain | 14 | None stated |
| Dep audit + reproducible double-build | 6, 7 | None stated |
| No `do_exec` in prod agent; no interactive console | 4, 15 | Opposite by design — arbitrary agent code, long-running processes, admin console |
| Secret is destination-bound, time-bound, zeroized, never in audit | 13, 16 | "Credential injection" is directionally identical but thinner as described (header append; no stated destination/time binding, zeroization, or audit-no-value guarantee) |
| Cross-platform (macOS HVF/libkrun + Linux) | — | KVM x86_64 Linux only |
| Rust boundary discipline + wasm-clean audit verifier | — | Control plane partly Go; no equivalent verifier surface |

Two structural points:

- **Scope mismatch.** The offering is a multi-tenant fleet system (cluster orchestrator, node scheduler, multi-node). mvm scopes multi-tenant guests *out* at the mvm layer; that trust boundary lives in the sibling fleet product. So most of the offering's control plane compares to the sibling, and any cross-tenant lessons belong to that product's own claim catalog, not to mvm's.
- **Auditability model.** The offering runs *real guest networking* — a per-sandbox TAP with an eBPF SNAT/DNAT data plane and an L7 MITM egress proxy. mvm's HVF path is deliberately vsock-only with no guest NIC, precisely so the vsock seam remains the single auditable egress-and-substitution chokepoint. Their model is legitimate but is the thing mvm's vsock-only invariant intentionally rejects.

## What mvm should NOT adopt

- **A guest-NIC eBPF network data plane.** It conflicts with the vsock-only auditable-data-plane invariant. Matching their model would reintroduce a guest network interface and move enforcement off the vsock seam, regressing the audit/substitution story that claims 10/13/16 rest on. Considered and rejected, same spirit as ADR-001's serial-console rejection.
- **A mutable shared store as control-plane authority.** mvm's trust root is the signed `ExecutionPlan` plus the chain-signed audit log. Introducing a mutable store as "single source of truth" for lifecycle/authority would undercut claim 8. A cache is fine; an authority is not.
- **`containerd` shim / OCI-runtime integration on the runtime path.** mvm's posture is explicitly no container runtime on the runtime path (ADR-001 tier matrix: there is no Tier 3). The offering's shim-v2 bridge buys ecosystem reach at a cost mvm has already declined. mvm consumes OCI *images* (claim 14) without adopting an OCI *runtime*; keep that line.

## (c) Prioritized recommendation

**Adopt the DX/performance ideas that are already refactor-aligned; hold every security claim fixed.** The offering is a useful mirror of where the industry is converging on agent-sandbox *ergonomics*, and a poor mirror of mvm's *assurance* posture. Borrow from the first, not the second.

- **P0 — Snapshot-and-fork DX, admission-safe.** Elevate warm checkpoints to a first-class fork/restore capability over the `VmBackend` seam, with the invariant that a forked/restored VM re-admits or inherits a bound signed plan and keeps its verified-boot binding. Highest leverage, already in the refactor's path, and the guardrail is the whole point. Sequence as a small design spike against ADR-025 + the checkpoint code before committing.
- **P1 — Incumbent-SDK wire-compat adapter behind `mvm-client`.** A thin, audited translation of `run_code`-style calls onto the transient-run path. Adoption on-ramp with no change to the IR model; every call still signs a plan and audits.
- **P1 — Publish warm-start + density SLOs** as the snapshot path lands, turning measured perf into stated, gated properties.
- **P2 — First-class, observable egress-allowlist surface** in `doctor`/receipts. Presentation over an existing capability.
- **Reject** the guest-NIC eBPF data plane, the mutable-store authority, and the container-runtime shim, for the reasons above.

No dependency, wire contract, or claim changes are implied by this note. Any adoption starts as an additive, reversible spike, mirroring the pilot discipline in `specs/research/uor-addr-integration-assessment.md`.

## Sources

Public materials from the vendor's open-source project, cited obliquely to honor the naming rule (URLs and repository identifiers embed the product/vendor name and are therefore omitted):

- Vendor architecture overview (public documentation) — component roster, VMM/storage/networking design, security-layer summary.
- Vendor product introduction and quickstart (public documentation) — performance figures, execution model, SDK env-var setup, template CLI, admin console.
- Vendor launch write-up (public blog) — motivation, container-vs-VM trade-off framing, self-developed-VMM rationale, SDK example.
- Third-party technical explainer (independent blog) — isolation summary, unshipped/early-feature caveats, and the note that vendor metrics lack independent benchmarking.
- `specs/adrs/001-microvm-security-posture.md` — mvm's threat model, tier matrix, and the fifteen-claim ledger used for the contrast above.
