---
title: "ADR-027: Iroh-aware encryption layering"
status: Proposed
date: 2026-05-07
related: ADR-002 (security posture), ADR-005 (libkrun pivot), plan 60-mvm-libkrun-migration
---

## Status

Proposed. Implementation across Phases 2 (volumes/snapshots), 6 (mTLS for hostd, attestation), and ongoing.

## Context

mvmd uses **iroh** (https://iroh.computer) for its P2P agent transport. iroh provides QUIC with TLS 1.3 native, ALPN-tagged streams, and relay-mediated NAT traversal. The naive instinct was to layer additional mTLS on top of iroh for the mvmd↔mvm-agent hop "to be safe." This is wasteful (re-encryption costs CPU and adds bugs) and structurally confused (iroh's TLS already authenticates both ends via NodeIDs).

Separately, the **mvmd-agent ↔ mvm-hostd** hop is a *different* boundary — same machine, different process, communicating over a Unix domain socket. Here, mTLS *does* belong, because the agent is unprivileged and the hostd is root; mutual authentication is the safety mechanism.

And separately again, the **host ↔ guest** hop (vsock) needs its own auth model — vsock has no TLS by design.

The encryption story therefore decomposes into four independent boundaries, each with the right primitive for the threat at that layer.

## Decision

Encryption layers, named explicitly:

| Hop | Transport | Security | Owner |
|---|---|---|---|
| mvmd-coordinator ↔ mvmd-agent | iroh QUIC + relay | TLS 1.3 native to iroh; ALPN `/mvmd/agent/1` | iroh — **we do NOT layer extra TLS** |
| mvmd-agent ↔ mvm-hostd | Unix domain socket | mTLS via `rustls` + `rcgen`; certs per-node 7-day rotation | mvm (this repo) |
| host ↔ guest | virtio-vsock | `AuthenticatedFrame` (HMAC + X25519 ephemeral session keys for forward secrecy) | mvm-guest (this repo) |
| host process ↔ keystore | OS API (Keychain / Cred Mgr / Secret Service) | platform-native; HSM/TPM where available | OS + our `Keystore` trait |
| volume bytes at rest | LUKS2 (Linux) / APFS-encrypted (macOS) / BitLocker (Windows) | AES-XTS | OS + our `Keystore` wrap |
| snapshot bytes at rest | AEAD: AES-256-GCM (preferred) / ChaCha20-Poly1305 | per-snapshot DEK wrapped by tenant KEK | mvm (this repo) |

Each layer rotates independently (see plan 60 §"Encryption and key rotation design").

## Consequences

**Positive**:
- No double-encryption at the iroh hop (CPU, latency saved).
- Each layer's key material is scoped to its threat (no master-key compromise across layers).
- Layer documentation matches code structure — each `mvm/src/security/<name>.rs` aligns with one row in the table.

**Negative**:
- Operators must understand the layering to debug cert / key issues. Mitigated by a runbook (`specs/runbooks/key-management.md`, Phase 2).
- Cross-layer key derivation (e.g., a tenant KEK derived from a node identity key) requires careful documentation.

## Alternatives considered

- **Add mTLS over iroh**: rejected. Wasteful CPU; iroh already authenticates both ends via Ed25519 NodeIDs.
- **Plaintext over iroh and rely on the network**: rejected. iroh's QUIC is the security primitive; we just don't *double*-secure.
- **One unified key hierarchy**: deferred. Useful for compliance reporting (single root → many DEKs) but not load-bearing for security; revisit in Phase 9.

## Threat model impact

The four-boundary model maps cleanly onto STRIDE per layer. Each threat (Spoofing, Tampering, Information Disclosure, Elevation of Privilege) is addressed by the layer that owns the boundary, not by all layers redundantly.

## Compliance impact

- SOC 2: positive — encryption-in-transit and at-rest are both covered with explicit owners.
- PCI: positive — segments cardholder data flow from operational flow.
- HIPAA: positive — Transmission Security (§164.312(e)) is satisfied per-layer with documented mechanisms.
