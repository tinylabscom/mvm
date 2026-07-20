# ADR-031: Wire, crypto, and storage stay on minimal in-tree primitives

## Status

Accepted.

## Context

Heavyweight frameworks are proposed periodically as replacements for the
three most invariant-laden subsystems: the serialization/wire format
(Cap'n Proto), the crypto layer (libsignal), and state/secret storage
(SQLite, IOTA Stronghold). Each subsystem already carries a CI-enforced
security claim and, for the wire, a byte-for-byte cross-repo contract with
mvmd, so a swap is never a local change.

The incumbent stack:

- **Wire:** `serde` + canonical JSON (JCS). The signed `ExecutionPlan`,
  `ControlRequest`, and audit entries are byte-identical across mvm↔mvmd,
  canonicalized and Ed25519-signed (ADR-014, ADR-015, ADR-019). Every
  host↔guest type is `#[serde(deny_unknown_fields)]` (fail-closed) and
  fuzzed. `mvm-protocol` is `no_std` + `alloc` and compiles on
  `wasm32` for the in-browser core goal (ADR-024).
- **Crypto:** `ed25519-dalek` (signing, chain-signed audit),
  `ring`/`rustls`/`rcgen` (egress-substitution TLS re-origination,
  ADR-023), plus attestation and a keystore/secret_store using
  `mlock` + `zeroize` + `subtle`. The threat model (ADR-002) trusts the
  host with the hypervisor and private keys, runs one workload per guest,
  and keeps secret values out of the guest entirely.
- **Storage:** append-only chain-signed JSONL audit log (verified by the
  `mvm-verify` wasm-clean reader), content-addressed pack-cache
  directories, and mode-0600 key files under a single `~/.mvm` root.

## Decision

Keep the incumbents. Decline all four proposed frameworks; each is
recorded with the condition under which it would be revisited.

1. **Cap'n Proto — declined.** Replacing the wire format breaks the
   mvmd byte-identity contract (a lockstep cross-repo change plus new
   signing semantics) and forces a rewrite of the SDK codegen pipeline
   (schema → language stubs). `serde` already satisfies the
   `no_std`/`wasm32` and fuzz requirements; there is no throughput
   problem it cannot meet, as these are small control-plane messages.
   Zero-copy parsing of untrusted input adds attack surface that would
   have to be re-fuzzed. *Revisit only* if a genuine high-rate data
   path emerges (e.g. the packet tunnel), and then with a targeted
   binary frame codec, not a wholesale format swap.

2. **libsignal — declined.** The Signal Protocol (X3DH + double ratchet)
   targets asynchronous, multi-party, forward-secret messaging over an
   untrusted relay. mvm has no such channel: host↔guest is local vsock
   with a trusted host, and secrets never enter the guest. The real
   needs — signing, TLS re-origination, attestation — are met by focused
   primitives already in-tree. *Revisit only* if a feature introduces a
   true end-to-end messaging requirement across an untrusted relay.

3. **SQLite — declined for mvm.** It works against three deliberate
   designs: the append-only chain-signed JSONL audit (tamper-evidence +
   the wasm-clean verifier), the content-addressed pack cache, and the
   single-root file layout. It is also a host-side C dependency. A
   relational/queryable workload at scale is fleet/multi-tenant state,
   which lives in mvmd; that is where the choice belongs, not here.

4. **IOTA Stronghold — declined, with the strongest residual case.** Its
   encrypted-snapshot and in-memory protection would harden the at-rest
   host signer key and secret memory. But ADR-002 scopes a malicious host
   and hardware-backed key attestation out of the threat model, which is
   most of what Stronghold buys, so it is hardening beyond the stated
   boundary. At-rest key encryption, if wanted, is a focused change using
   an in-tree AEAD, not a new secrets engine. *Revisit only* alongside an
   ADR-002 amendment that brings host compromise into scope.

## Consequences

The dependency surface stays minimal and every wire/crypto/storage
element remains claim-backed, matching the limit-dependencies and
reuse-first posture. Each declined option has an explicit revisit
trigger, so the decision is reversible on evidence rather than
re-litigated from scratch. The bar these four failed — a real problem the
in-tree primitive cannot solve, weighed against a CI-enforced invariant —
is the standard any future framework proposal is held to.
