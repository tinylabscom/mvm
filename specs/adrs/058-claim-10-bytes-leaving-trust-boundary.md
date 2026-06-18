# ADR-058 — Claim 10: bytes leaving the trust boundary are encrypted, attested, and audited

**Status:** Proposed
**Sprint:** 56 (W2, W3, W4)
**Plan:** [Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md)

## Context

ADR-002 §"Out of scope" today carves out *a malicious host* — "mvmctl trusts the host with the hypervisor and private build keys." That carve-out is correct as stated, but the current implementation is too permissive: it grants the host more capability than the threat model requires.

Specifically:

- **RW tenant volumes are plaintext.** `mvmctl volume create` produces an AES-256-GCM archive (`crates/mvm-security/src/secret_store.rs`) that protects the volume's host-side file at rest *when locked*. But once a volume is opened and mounted into a guest, the backing storage on the host is decrypted ext4 / virtiofs. A host process with read access to the volume directory can read every byte the workload is writing or reading.
- **Gateway flows are not in the audit chain.** `crates/mvm-core/src/policy/audit.rs` (`LocalAuditKind` enum) has plan/admission events and Stage 0 boot events, but no flow events. gvproxy (macOS) and passt (Linux) handle all guest network I/O at the host level; neither emits attested flow metadata. A compromised host can route, log, or exfil any traffic with no record landing in the chain.
- **App-deps volumes have integrity, not confidentiality.** dm-verity-sealed deps volumes (claim 9, [Plan 73](../plans/73-app-deps-audit-pipeline.md) / [ADR-047](047-app-deps-audit-pipeline.md)) prove "what's on disk hasn't been tampered with." They don't hide what's on disk. Different property.

Result: a host whose userland (not kernel — that's a different threat tier) has been compromised can read tenant data and silently exfil network traffic, and nothing in the audit chain notices.

## Threat model

This ADR narrows ADR-002's "out of scope: a malicious host" carve-out. The new posture:

- **Still trusted:** the hypervisor binary, the host kernel, the host signer's private key. Compromise of any of these defeats mvmctl's isolation by definition; out of scope here as in ADR-002.
- **No longer trusted (this ADR):** the host userland's *passive* read access. A user-space process on the host should not be able to (a) read tenant volume bytes at rest, or (b) exfil tenant network traffic, *without that fact being attested in the audit chain.*

Adversary capability assumed: read access to host filesystem and host network namespace. Not assumed: kernel module load, hypervisor hijack, signer key exfiltration (those are ADR-002's still-out-of-scope tier).

**Adjacent surface — not addressed here, named so readers don't expect it:** inbound TLS termination is mvmd's concern, not mvm's. mvmd manages tenant certs at its multi-tenant edge and is the natural place to terminate inbound TLS. Workload-level TLS (the user's own HTTPS listener inside the microVM) stays encrypted end-to-end. This ADR's threat model is *outbound exfil from the workload*, not *inbound eavesdrop or auth* — different threat model, different ADR if/when it gets one.


## Decision

Add claim 10 to ADR-002's CI-enforced security claims, in three legs.

### Leg 1 — Volume confidentiality

Every RW tenant volume is dm-crypt / LUKS-2 inside the guest. The host's view of the volume backing store is ciphertext at all times, even while the workload is running.

Key delivery: the signed `ExecutionPlan` carries a `Vec<EncryptedVolumeKey>` — per-volume symmetric keys, each wrapped under the tenant's pubkey. The mvm-supervisor never sees plaintext key material; it materializes the wrapped keys to an in-VM ramfs (never to host disk) and hands the ramfs path to the guest initramfs via kernel cmdline. The guest unwraps inside the VM using the tenant private key, escrowed by mvmd (cross-repo dep).

### Leg 2 — Network traffic audit

gvproxy (macOS) and passt (Linux) are wrapped with a control-socket listener that streams per-flow events to `mvm-supervisor`. Events: `flow_opened`, `flow_closed`, aggregated `flow_bytes` (every N seconds or on close), and `flow_policy_decision` (every deny / allow). All events land in the chained `~/.mvm/audit/<tenant>.jsonl`. The existing `mvm_supervisor::verify_audit_chain` mechanism extends to flow events with no schema break beyond the new enum variants.

No L7 inspection. No TLS termination. Only connection metadata and byte counts.

#### W6.A amendment (2026-05-26 — [Plan 102](../plans/102-gateway-audit-substrate-impl.md) / [Plan 103](../plans/103-w6a-implementation-tracker.md))

**No-bypass invariant.** TSI mode is removed entirely
(`NetworkingPreference::Tsi` deleted; `MVM_NETWORKING=tsi` rejected
with a clear warning + per-OS fallback). Every libkrun-backed VM
boots through `passt` (Linux) or `gvproxy` (macOS); every Vz-backed
VM boots through `gvproxy` via `VZFileHandleNetworkDeviceAttachment`.
No env-var, JSON-config field, or fallback lets a workload skip the
auditable bridge. `mvmctl doctor` flips the gateway probe from
`ok: true` (with a TSI escape note) to `ok: false` when the
gateway binary is missing — there is no escape hatch left.

**Coverage vs. capture.** W6.A commits to **coverage** — every byte
that crosses the trust boundary traverses an auditable bridge.
**Capture** (per-byte content into the chain) is opt-in via a future
`network_audit.mode = full_pcap` field, not the default. Aggregated
`FlowBytes` counters land in W8; full pcap is a forensic-only mode.

**Mediable substrate.** The bridge exposes a `FlowPolicy` hook
([`mvm_supervisor::gateway_bridge::FlowPolicy`]). W6.A ships the
`AllowAll` default; Plan 74's enforcer plugs in later for L4
decisions, and a future SNI inspector + Plan 34 Phase 2 (TLS MITM
in `L7EgressProxy` with workload-CA trust) plug in for hostname /
URL allowlist semantics — all without re-architecting the
bridge. The forward-compat seam is `FlowDecisionCtx`'s optional
`sni_hostname` / `url_path` fields.

**Cross-process chain integrity.** `FileAuditSigner::sign_and_emit`
now takes an `flock(LOCK_EX)` on the tenant chain file across the
read-cursor / sign / append critical section. Without this, two
`mvm-libkrun-supervisor` processes for the same tenant could both
restore the same `prev_hash` and break `verify_audit_chain`. The
flock is the precursor that made claim-10 per-VM emission safe.

**Scope (W6 impl):** gateway egress only — **north-south** through
passt/gvproxy. East-west microVM ↔ microVM lateral flows traverse
the tenant bridge below the gateway and are out of W6 scope;
deferred to W11 as a distinct capture plane. The same substrate
covers all three backends (libkrun+passt, libkrun+gvproxy,
Vz+gvproxy) through a single per-VM `signer_task`.

**Cross-tenant isolation invariant.** The W6.A substrate
introduces no cross-tenant coupling: per-VM gateway, per-tenant
chain file (flock-serialized within tenant only), per-VM mpsc /
broadcast (no shared queues), per-VM subscriber socket. The mvmd
cross-repo `mvmd-network-manager` plan (`tinylabscom/mvmd/specs/plans/50-network-manager.md`)
covers cross-tenant network management (per-tenant gateway pool,
egress quotas, tenant-level audit rollup, cross-tenant traffic
isolation) — out of mvm's scope by design.

### Leg 3 — Crypto state attestability

Every key fingerprint, key rotation, and key-unwrap-failure event lands in the audit chain. `mvmctl audit verify` covers volume-key events alongside flow events alongside the existing plan events. A new CI lane `claim-10-audit-tamper` exercises tamper detection: emit a known sequence, byte-flip one entry, assert `mvmctl audit verify` exits non-zero.

## Out of scope (named, like ADR-002)

- **Host filesystem encryption (FDE).** That's the user's concern — full-disk encryption protects host backups; this ADR protects per-volume at-rest exposure during active workload runs.
- **Per-byte traffic audit.** Aggregated `flow_bytes` only ([Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md) W8); coverage of every byte through the bridge is structural (W6.A amendment above), capture is opt-in future mode ([Plan 203](../plans/203-forensic-network-transcript-capture.md)).
- **Audit metadata at rest.** The chain itself (5-tuples, byte counts, key fingerprints) is plaintext on host disk under `~/.mvm/audit/<tenant>.jsonl`. Tenant *data* is encrypted; tenant *behavior metadata* is not. Future claim 10.1 candidate; not in this sprint.

### Added by W6.A amendment

- **East-west microVM ↔ microVM lateral flows.** Different capture mechanism (`tc mirred` / eBPF / per-TAP libpcap), different policy surface. W11 candidate; named here so readers don't expect it from W6.
- **L7 URL inspection (path-level allowlist).** Composes via `L7EgressProxy` Phase 2 (TLS MITM with workload-trusted host CA per [ADR-006](006-name-constrained-egress-ca.md)); substrate exists, not yet finalized. Separate plan from W6.
- **DNS-over-HTTPS bypass mitigation.** Workloads using DoH (e.g., 1.1.1.1:443) hide queries inside encrypted HTTPS to a public resolver, evading admission-time DNS pinning. Separate Plan 74 follow-up: mandatory-deny well-known DoH endpoints.
- **SNI hostname allowlist.** Cleartext SNI extraction from TLS ClientHello → `FlowPolicy::evaluate` with `sni_hostname` populated. Substrate seam exists in W6.A's `FlowDecisionCtx`; inspector implementation is a separate plan.
- **Side-channel information leakage via flow timing.** Inherent to any flow audit; accepted.
- **Multi-user shared host with same UID.** Same-UID local attacker can read the gateway subscriber socket. Mode 0700 mitigates cross-UID; cross-UID-same-user is documented as accepted (they can already read the chain file directly).
- **Cross-tenant network management.** Per-tenant gateway pool, egress quotas, tenant-level rollup, cross-tenant traffic isolation — owned by mvmd via [`mvmd-network-manager`](https://github.com/tinylabscom/mvmd/blob/main/specs/plans/50-network-manager.md).

## Consequences

- `ExecutionPlan` grows: `volume_keys: Vec<EncryptedVolumeKey>` and `network_audit: NetworkAuditConfig` fields. PROTOCOL_VERSION bump in `crates/mvm-core/src/protocol/protocol.rs`.
- mvmd cross-repo work: tenant root key, key derivation, rotation policy. Tracked as Plan 101 W5.
- `mvmctl doctor` gains a `claim_10` row reporting LUKS-in-guest active + gateway audit emitting + audit chain valid.
- New CI lane: `claim-10-audit-tamper` byte-flip test gates every PR.
- Performance: dm-crypt overhead measurable on hot-path volume reads. Plan 101 W14 validates within threshold; backs out if pathological.

## References

- [ADR-002](002-microvm-security-posture.md) — microVM security posture (claim list extends to 10)
- [ADR-041](041-signed-audited-execution-plans.md) — claim 8, signed ExecutionPlans (volume keys ride this signing path)
- [ADR-047](047-app-deps-audit-pipeline.md) — claim 9, app-deps audit (analogous structure for the audit chain extension)
- [ADR-055](055-cross-platform-backends.md) — gvproxy / passt gateway choice
- [Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md) — implementation rollout
