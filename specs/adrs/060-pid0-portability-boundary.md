# ADR 060 - pid0 Portability Boundary

**Status**: Proposed
**Date**: 2026-05-28
**Cross-refs**: ADR-002 (security posture), ADR-053 (guest protocol versioning & readiness), ADR-055 (passt virtio-net), ADR-059 (host services broker), ADR-061 (broker hardening), ADR-062 (broker rescope — drop secrets, add host.audit.v1), Plan 109 (guest control-layer dep-reduction + encryption design), Plan 25 (microVM hardening), Plan 64 (signed execution plans), Plan 104 (host services broker)

## Context

mvm runs guest workloads across multiple hypervisor backends: **Firecracker** (Linux KVM, production tier 1), **libkrun** (Linux KVM + macOS HVF), **Apple Virtualization.framework / Vz** (macOS 26+ Apple Silicon, ADR-056), **Cloud Hypervisor** (Linux KVM alternative), **Apple Container** (macOS), **Docker** (tier 3 fallback), plus Mock for testing.

The guest-side init layer (pid 1 → `mvm-verity-init` → `switch_root` → minimal init → `mvm-guest-agent`) is structurally identical across backends today *by convention*, not by contract. ADR-053 introduced a guest protocol hello + readiness state machine, and Plan 64 / claim 8 wired a signed `ExecutionPlan` admission path. Neither names the broader **pid0 control surface** the agent must provide on every backend — i.e. what every backend's guest must satisfy for the host's control plane to work uniformly.

Today the convention is implicit. It's documented across CLAUDE.md, scattered code comments in `crates/mvm-guest/`, the verity-init kernel cmdline contract, and the per-backend supervisor wiring. New backends (e.g. the Vz path in ADR-056 / Plan 98, or Cloud Hypervisor in Plan 54) have to re-derive what "this thing is a valid mvm guest" means by reading existing implementations. That's brittle and invites drift.

The motivating question (raised by Plan 109's exploration of Zig vs lean-Rust v2 alternatives at the boundary): **if pid0 is the portability boundary across hypervisors, what does any pid0 implementation — Rust today, lean-Rust v2 future, hypothetical Zig replacement — have to do to be a valid mvm guest?**

This ADR makes the contract explicit. It does **not** mandate a language; it does **not** specify which binaries provide the contract; it does **not** change any current backend's behavior. It documents the invariants every backend's guest must satisfy and gives future contributors a single document to consult before adding a backend or proposing a guest rewrite.

## Decision

mvm treats the **pid0 control surface** — the guest-side code that runs at boot and serves the host's control plane — as a backend-agnostic contract with the following shape.

### 1. What "pid0 control surface" means

The pid0 control surface is the set of guest-side processes the host's control plane talks to or depends on, namely:

- The init binary (`mvm-verity-init` today in the verity-initrd path; whatever pid 1 is after `switch_root`).
- One-shot pre-workload binaries (`mvm-guest-netinit` today — blackhole-route installer).
- The long-lived control-plane agent (`mvm-guest-agent` today, uid 901, listens on vsock `:5252`).
- Any addon binaries that are part of the minimum boot sequence (`mvm-addon-dns`, `mvm-addon-vsock-bridge` when enabled).

The pid0 control surface is **distinct from**:

- The workload itself (defined in the user's `mkGuest { entrypoint = ...; }` flake; runs as a child of the agent on `RunEntrypoint`).
- The host services broker (ADR-059 / ADR-061 / ADR-062 / Plan 104) — the broker's 3 subprocesses (`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`) live on the **host**, not the guest. The guest is a *client* of the broker via vsock port `:5300`, but the broker is not part of the pid0 contract. (Pre-ADR-062 designs referenced a separate secrets channel on `:5301`; that port and `mvm-secrets-dispatcher` are gone as of ADR-062.)

### 2. Transport contract

Every backend MUST provide:

- **Virtio-vsock** with a stable CID assignment for the guest. The host uses CID 2 (loopback); the guest uses CID 3 by convention. Backends that abstract the CID space (libkrun's in-process VSOCK proxy, Vz's vsock API, Cloud Hypervisor's vsock device) MUST expose the guest end as a Unix-domain socket the host supervisor can bind for incoming connections.
- **A length-prefixed JSON framing** carried inside vsock streams, with `AuthenticatedFrame` (Ed25519 + session id + monotonic sequence) wrapping every payload (ADR-002 §W4.1, claim 5, `crates/mvm-core/src/policy/security.rs`).
- **No alternate control transport.** Backends MUST NOT route control-plane traffic over virtio-net, virtio-fs, block devices, or any side channel. The vsock-only invariant is load-bearing for claim 1 (no host-fs access beyond explicit shares) and ADR-058 (no virtio-net bypass).

If a backend cannot satisfy vsock with this framing, it is not a valid mvm backend and must defer to the Mock or Docker tier until it can.

### 3. Boot handshake contract

The guest agent MUST implement the protocol-hello sequence from ADR-053:

- First message in every session: `ProtocolHello` carrying `protocol_version`, `min_supported_protocol_version`, `agent_version`, `supported_capabilities` (see `crates/mvm-guest/src/vsock.rs:77+`).
- Mismatch returns a typed `ProtocolMismatch` before any other dispatch.
- No `Ping`-style compatibility shim. Old guests must be rebuilt; old hosts must be upgraded.

The agent MUST emit `ReadinessStatus` events tracking the components named in ADR-053 §3:
`control_plane`, `entrypoint`, `warm_pool`, `integrations`, `probes`, `volumes`. Components not applicable to a given image report as `not_present`, not as `failed`.

### 4. Lifecycle states

The pid0 control surface MUST move through these named states in this order:

1. **boot** — kernel-userspace handover; `mvm-verity-init` setting up dm-verity (if verity-enabled), then `switch_root`.
2. **netinit** — `mvm-guest-netinit` (or equivalent) installing mandatory deny routes per Plan 74 W2 / claim 1; exits before agent starts.
3. **agent-listen** — `mvm-guest-agent` (or equivalent) bound to vsock `:5252` and serving `ProtocolHello`.
4. **ready** — agent has emitted `ReadinessStatus { control_plane: ready, ... }`; host may dispatch any ProdSafe verb.
5. **workload** — `RunEntrypoint` has spawned the workload as a child of the agent; entrypoint events stream to host.
6. **drain** — host issued shutdown; agent stops accepting new work, drains in-flight RPCs, signals workload `SIGTERM` then `SIGKILL`.
7. **shutdown** — agent exits cleanly; init reaps; backend tears down VM.

States 1–3 are **mandatory**; 4–7 may overlap or be condensed for non-interactive workloads but ordering must hold.

### 5. What pid0 MUST NOT do

- **No host-fs assumptions.** The guest MUST NOT assume any path on the host is visible. Volume mounts arrive via `MountVolume` RPC (virtio-fs share) explicitly bound at runtime — never inferred from environment, never hardcoded.
- **No SSH.** Per CLAUDE.md "no SSH in microVMs, ever" — no sshd, no SSH keys, no SSH users in any rootfs. Console PTY (dev-mode) goes through vsock, not SSH.
- **No shell-out beyond audited verbs.** The agent must not exec arbitrary binaries on uid-0-ish behalf of the host outside the `ProcStart` / `RunEntrypoint` paths that emit `LocalAuditKind::NetworkPolicyAllow` audit events (claim 8). `do_exec` and friends are stripped in sealed-prod builds (claim 4).
- **No broad seccomp escape.** The agent runs under `setpriv --bounding-set=-all --no-new-privs` with the W2.4 standard profile. A pid0 implementation may not require a permissive seccomp profile or `CAP_SYS_ADMIN` beyond what verity-init needs for dm-verity setup.
- **No bypass of `AuthenticatedFrame`.** Every host↔guest control-plane message is signed and replay-protected. Backends MUST NOT introduce an out-of-band control channel that skips signature verification.

### 6. Cross-platform constraints

- **musl-static** binaries. Glibc-linked binaries don't run reliably in minimal initramfs / NixOS-without-glibc setups and break the verity-initrd path. Every pid0-class binary must build static-musl for `x86_64-linux` and `aarch64-linux`.
- **Kernel cmdline contract** is a stable surface (ADR-002 §W3, Plan 27 / claim 3):
  - `mvm.roothash=<64-hex>` — required if verity-enabled.
  - `mvm.runtime_roothash=<64-hex>` — required if runtime-overlay verity is in use.
  - `console=hvc0` — required for libkrun (per memory `reference_libkrun_gotchas`).
  - `init=/init` — points at the verity-init or minimal-init pid1.
  - Additional flags introduced by backends MUST follow the `mvm.*` prefix and document the change in this ADR.
- **No host Nix dependency.** Per CLAUDE.md "Host Nix is never used by mvmctl, even when present" — the guest must boot from an image built inside a builder VM, never from a host-Nix evaluation.

### 7. Audit chain integration

Every RPC dispatch in the pid0 control surface MUST emit a `LocalAuditKind::NetworkPolicyAllow` audit event (Plan 51 W6 / Plan 37 §6) carrying the verb name via `GuestRequest::kind_name()`. The supervisor's `AuditEmitter` is the only writer to `~/.mvm/audit/<tenant>.jsonl`; a pid0 implementation that bypasses this is invalid.

This is the same invariant as Plan 109 §I1 (control-plane audit chain stays intact).

### 8. Language neutrality (explicit non-goal)

This ADR does **not** mandate any specific implementation language. The current Rust implementation satisfies the contract; future lean-Rust-v2 or Zig alternatives explored under Plan 109 satisfy it equally as long as they meet sections 1–7.

The contract surfaces are:

- The vsock framing format (`AuthenticatedFrame`).
- The `GuestRequest` / `GuestResponse` / `GuestCapability` enum variants.
- The `ProtocolHello` semantics.
- The audit-emit invariant.
- The cmdline contract.

Any language change at the boundary MUST preserve these *byte-identically*. See ADR-002 (§"Consolidated from ADR-063 — Boundary Language Policy") for when non-Rust implementations are permitted at all.

## Consequences

**Positive:**

- New backends have a single document to consult. Adding Cloud Hypervisor, future ARM hypervisors, or alternative macOS paths becomes a checklist exercise against sections 1–7.
- Future agent rewrites (lean Rust v2 per Plan 109's recommendation; Zig if evidence supports it) have an explicit contract to satisfy, not an implicit one to reverse-engineer.
- The Plan 104 host services broker is unambiguously *not* part of pid0. Cross-reference confusion about "what's in the boundary" resolves.

**Negative:**

- Codifies status quo before all of it is exercised across every backend. Vz (Plan 98) and Cloud Hypervisor (Plan 54) are still in flight; this ADR will need an amendment if their work surfaces a contract gap.
- The musl-static + no-glibc constraint excludes some library choices that would otherwise be natural in Rust (e.g. `mio` works under glibc but is unproven under all musl matrices). This is a known tradeoff per Plan 109 §"Honest uncertainties."

**Neutral:**

- Does not change any current binary's behavior. Documentation-only ADR establishing what the existing system already does, plus the explicit promise it will keep doing it.

## Out of scope

- The host-side broker (ADR-059 / ADR-061 / ADR-062 / Plan 104) and its port `:5300` (pre-ADR-062 `:5301` is removed). The broker is host-side; the guest's *client* code that calls into the broker is in `mvm-sdk`, not the agent, and is not part of the pid0 contract.
- The encrypted-vsock design (Plan 109 W3, Noise_NK). Encryption is forward-looking and will land via a separate ADR or as an addendum to this one once Plan 109's W3 design doc commits.
- The control-plane-vs-data-plane partition. Forthcoming separate ADR (Plan 109 W4a).

## References

- ADR-002 (microVM security posture, claims 1-10)
- ADR-053 (guest protocol hello + readiness)
- ADR-055 (passt virtio-net / gvproxy)
- ADR-058 (no virtio-net bypass, claim 10)
- ADR-059 (host services broker over vsock — adjacent, not part of pid0)
- Plan 25 (microVM hardening workstreams)
- Plan 64 (signed execution plans, claim 8 wiring)
- Plan 74 W2 (mandatory deny routes, blackhole installer)
- Plan 104 (host services broker implementation)
- Plan 109 (guest control-layer dep-reduction + encryption design — this ADR is W4b)
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` (current pid0 agent implementation)
- `crates/mvm-guest/src/bin/mvm-verity-init.rs` (current verity-init implementation)
- `crates/mvm-guest/src/bin/mvm-guest-netinit.rs` (current netinit implementation)
- `crates/mvm-guest/src/vsock.rs` (`GuestRequest`, `ProtocolHello`, framing)
- `crates/mvm-core/src/policy/security.rs` (`AuthenticatedFrame`)
