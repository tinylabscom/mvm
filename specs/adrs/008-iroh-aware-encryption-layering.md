# ADR-008: Encryption layering across trust boundaries

## Status

Accepted.

## Context

mvm and the fleet orchestrator that consumes it as a library cross several
distinct trust boundaries, each with its own transport and its own
threat: the fleet control plane's own P2P transport between its
coordinator and its agents; a local host process boundary between an
unprivileged caller and a privileged daemon role; the host-to-guest vsock
channel, which has no TLS by design; a host process reading a long-lived
secret from an OS keystore; data at rest in a volume or a paused-VM
snapshot; and outbound HTTPS traffic the host terminates on a workload's
behalf. Applying one uniform mechanism (e.g. layering mTLS on every hop
regardless of what the hop already provides) is both wasteful — a hop
whose transport already authenticates both ends pays a redundant
encryption cost — and structurally confused, because each hop's real
threat is different and calls for a different primitive.

## Decision

Each boundary gets the primitive its own threat calls for, never a second
layer stacked on a transport that already carries one:

| Boundary | Transport | Mechanism |
|---|---|---|
| Fleet coordinator ↔ fleet agent | QUIC + relay (iroh) | TLS native to the transport, authenticated by both ends' node identity — no additional mTLS layered on top |
| Host ↔ guest (control plane) | virtio-vsock | `AuthenticatedFrame` — Ed25519-signed, session-id and monotonic-sequence replay defense (`mvm_core::policy::security`) |
| Host process ↔ OS keystore | platform keystore API (Keychain / Secret Service / Credential Manager) | platform-native; every returned key wraps `secrecy::SecretBox` so material zeroizes on drop |
| Volume / snapshot bytes at rest | local disk | AES-256-GCM, chunked for large snapshot images; HMAC-SHA256 integrity envelope checked before any AEAD decrypt is attempted (`mvm_core::crypto::snapshot_crypto`, `snapshot_encryption`, `snapshot_hmac`) |
| Outbound HTTPS the host terminates on a workload's behalf | TLS | a per-VM, name-constrained intermediate CA mints a leaf per SNI for the bound hosts only; the guest trusts only that per-run intermediate, never the host CA or any private key (`mvm_core::crypto::egress_ca`) |

**No double-encryption where a transport already authenticates both
ends.** The fleet control-plane hop is iroh's problem to secure and it
already does; this repo does not add a redundant TLS layer there.

**Every secret-carrying type wraps `SecretBox<T>`.** `KeyProvider`,
`SecretStore`, the HMAC key loader, and the key-rotation primitives all
return `SecretBox`-wrapped material, never raw bytes. A workspace lint
(`xtask check-no-display-on-secret-types`) walks the tree and rejects a
hand-written `Debug`/`Display` impl on any type whose name matches
`Secret|Key|Password|Token`, so a secret can't leak through an accidental
derive.

**Key rotation re-wraps rather than re-encrypts.** A tenant's master key
is versioned; rotating it re-wraps every dependent data-encryption key
under the new version without touching the ciphertext those keys protect.
Each rotation primitive is written to converge on retry: re-running it on
an already-migrated record is a no-op rather than a double-transform, so
a crash mid-rotation is recoverable by re-invoking the same call.

**Passphrases and key material never touch argv.** Anywhere a rotation or
volume-encryption primitive needs to hand a secret to a subprocess (e.g.
a disk-encryption tool), it stages the value through a mode-0600 tempfile
that is unlinked on drop, never as a command-line argument another
process on the host could read from `/proc`.

**mvm owns the primitives; the fleet orchestrator composes them.** This
repo ships the AES-256-GCM / HMAC-SHA256 / key-rotation / keystore /
secret-store substrate as single-host building blocks. Object-store volume
encryption, deterministic per-volume key derivation for that path, and
fleet-wide key orchestration are the fleet orchestrator's concern, built
on top of this substrate rather than duplicated inside it.

## Consequences

**Positive.** No wasted CPU or added attack surface from double-encrypting
a hop that's already authenticated. Each layer's key material is scoped
to its own threat, so a compromise of one layer's key does not cascade
into another's. The secrets-in-types contract (`SecretBox` everywhere,
lint-enforced) makes an accidental secret-logging bug a compile-time or
CI-time failure instead of a runtime leak.

**Negative.** Operators debugging a cert or key issue have to understand
which layer they're looking at rather than reasoning about "encryption"
as one uniform concept. Cross-layer key derivation, where one boundary's
key material is derived from another's identity, needs careful
documentation so the derivation doesn't quietly become a hidden coupling
between layers that were designed to be independent.

**Out of scope.** This ADR does not cover the fleet orchestrator's own
key hierarchy, its object-store volume encryption, or hardware-backed key
attestation (TPM/HSM) — those stay one governing decision each, owned
where the code lives.
