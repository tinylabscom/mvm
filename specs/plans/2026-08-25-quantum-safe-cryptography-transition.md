# Quantum-safe cryptography transition for mvm and mvmd

Backing: shipped-source
Validation: check-sprint-append

**Status:** NOT STARTED
**Date:** 2026-08-25
**Branch:** `feat/quantum-safe-crypto` (future)

## Goal

Make the cryptographic trust boundary of `mvm` and `mvmd` verifiably post-quantum
safe: every authentication, signature, key exchange, and long-lived trust anchor
must either use post-quantum (PQ) primitives or be provably outside the quantum
attack surface. Preserve operational interoperability during a hybrid
transition, keep all existing security claims green, and add explicit
conformance claims for the new state.

## Background

The current stack relies on classical public-key cryptography that Shor's
algorithm breaks:

- **Signatures:** Ed25519 (host signer, attestation identity, plans/bundles,
  snapshots, audit chain, binary integrity), ECDSA P-256 (Secure Enclave host
  signer path, rcgen default egress CA chain).
- **Key exchange:** X25519 ECDH (host↔guest vsock and FlowMux sessions).
- **Integrity hashes:** SHA-256 and BLAKE3 (not broken, but collision resistance
  is reduced to ~2^85 under BHT-style quantum search).
- **Transport:** TLS 1.3 via rustls+ring, with X25519/secp256r1 key exchange and
  ECDSA/RSA certificate chains.
- **Supply chain:** cosign/Sigstore keyless bundles anchored in Fulcio ECDSA/RSA
  certificates and Rekor ECDSA transparency signatures.

The strongest parts are symmetric: AES-256-GCM and SHA-256/BLAKE3 preimage
resistance remain at ~128-bit post-quantum security. The goal is to protect the
broken signature and key-exchange surfaces.

## Invariants

- No production-claiming build uses classical-only signatures or key exchange
  after the transition is complete.
- Hybrid mode runs PQ primitives alongside classical ones until the ecosystem
  (Sigstore, Web PKI, TLS roots) supports PQ-only operation.
- Symmetric primitives (AES-256-GCM) remain acceptable; the hash security target
  is explicit and documented per use case.
- Existing audit-chain signatures must remain verifiable during the transition;
  dual-signature support is permitted where needed.
- `mvm` and `mvmd` move together: a fleet worker cannot be PQ-safe while its
  control plane is still classical.

## Surface inventory and target primitives

| Surface | Current | Target |
|---|---|---|
| Host attestation identity / reports | Ed25519 | ML-DSA (hybrid with Ed25519 during transition) |
| ExecutionPlan / bundle / audit chain | Ed25519 + SHA-256 | ML-DSA + SHA-256 or SHA-384 |
| Host↔guest vsock control RPC | Ed25519 + X25519 + AES-256-GCM | ML-DSA + ML-KEM + AES-256-GCM |
| FlowMux network session | Ed25519 + X25519 + AES-256-GCM | ML-DSA + ML-KEM + AES-256-GCM |
| Snapshot sealing | Ed25519 over SHA-256 | ML-DSA over SHA-256/SHA-384 |
| Subprocess binary integrity | Ed25519 sidecar | ML-DSA sidecar (or dual) |
| OCI image / release trust | cosign/Sigstore ECDSA/RSA | PQ-aware Sigstore/cosign when available; otherwise dual-signature policy |
| Egress TLS termination | ECDSA P-256 CA + rustls+ring | PQ/hybrid TLS provider + PQ CA chain |
| Ingress TLS | Operator-provplied certs | Policy enforcement: reject non-PQ chains |
| Encrypted volumes / snapshots | AES-256-GCM | Keep AES-256-GCM; protect key transport with ML-KEM |
| dm-verity root hash | SHA-256 | SHA-256 acceptable for 128-bit PQ preimage; consider SHA-384 for headroom |
| Apple Container kernel pin | BLAKE3 | Keep BLAKE3 or move to BLAKE3-512 for collision headroom |
| Workload identity federation | Unsigned claims shape | ML-DSA-signed JWT/OIDC assertions |

## Work

### Phase 0 — Inventory, policy, and crate evaluation

- [ ] Open a tracking worktree at `.worktrees/mvm-quantum-safe-crypto` and branch
      `feat/quantum-safe-crypto`.
- [ ] Audit every direct and transitive crypto dependency in `Cargo.toml` and
      `Cargo.lock` for PQ support (rustls, ring, rcgen, ed25519-dalek,
      x25519-dalek, sigstore-verify, cosign ecosystem).
- [ ] Evaluate and select PQ crates: at minimum ML-KEM (key encapsulation) and
      ML-DSA (signatures). Prefer NIST-standardized algorithms. Document the
      crate audit and MSRV impact in the plan.
- [ ] Decide hybrid composition: classical + PQ signatures (concatenated or
      separate sidecars), classical + PQ KEM (hybrid shared secret), and how
      rollback/downgrade is refused.
- [ ] Add `MVM_PQ_POLICY` environment / config knob with values `classical`,
      `hybrid` (default during transition), and `pq-only` (future goal).
- [ ] Update `model/claims.toml` with a new claim: "All workload authentication
      and key exchange use post-quantum primitives in `pq-only` mode." Add
      placeholder witnesses.
- [ ] Land Phase 0 as a documentation-and-decision PR; do not change runtime
      behavior yet.

### Phase 1 — Foundations: PQ primitives in `mvm-core`

- [ ] Add a new `mvm-core::crypto::pq` module wrapping ML-KEM encapsulation and
      ML-DSA sign/verify with a stable, versioned wire format.
- [ ] Implement `PqKeyPair`, `PqPublicKey`, `PqSignature`, `PqKemCiphertext`, and
      domain-separated `signing_bytes` helpers; derive `serde`, add roundtrip
      tests.
- [ ] Add hybrid key-derivation helper: `SHA-256(classical_shared_secret ||
      pq_shared_secret || session_id)` replacing the current X25519-only KDF.
- [ ] Add hybrid signature verifier: accept `(classical_sig, pq_sig)` and
      require both to verify during `hybrid`; require only `pq_sig` in
      `pq-only`.
- [ ] Gate the new code behind a cargo feature (`post-quantum`) so default
      builds stay small while the transition is in progress.
- [ ] Add negative-path tests: wrong PQ key, truncated signature,
      classical-only input in `pq-only` mode, `pq-only` input in classical
      mode.
- [ ] Ensure `cargo check --workspace --features post-quantum`,
      `cargo clippy --workspace --features post-quantum`, and unit tests pass.

### Phase 2 — Host-guest and FlowMux authenticated session

- [ ] Extend `mvm-contract::policy::security` `SessionHello` / `SessionHelloAck`
      to carry ML-KEM public key and ciphertext alongside X25519 keys.
- [ ] Update `mvm-core::net::session` handshake to derive the AES-256-GCM key
      from the hybrid shared secret (`X25519 || ML-KEM`) and to authenticate
      the handshake transcript with ML-DSA in addition to Ed25519.
- [ ] Update `mvm-agentd::vsock::framing` and `mvm-agentd::flowmux` to negotiate
      the new handshake based on `MVM_PQ_POLICY`.
- [ ] Add wire-version negotiation that refuses downgrade from `hybrid` to
      `classical` when the policy demands PQ.
- [ ] Add positive and negative BDD scenarios: successful PQ session, MITM
      replay of classical-only handshake rejected, tampered PQ ciphertext
      rejected, policy mismatch refuses connection.
- [ ] Update FlowMux fuzz targets to cover the new handshake fields.

### Phase 3 — Snapshot, attestation, and binary integrity

- [ ] Replace or augment `mvm-core::crypto::snapshot_sign` with a PQ signature
      sidecar (e.g., `snapshot.pq.sig`) using ML-DSA over the same
      `SHA-256(content) || epoch` message.
- [ ] Update `mvm-core::crypto::attestation::identity` and attestation report
      signing to support ML-DSA identity keys; keep Ed25519 identity support
      during transition.
- [ ] Update `mvm-hostd::supervisor::services::binary_integrity` sidecar format
      to include a PQ signature and a new `sig_alg` identifier for ML-DSA.
- [ ] Update release key bundle to hold both classical and PQ verifying keys;
      verify according to `MVM_PQ_POLICY`.
- [ ] Add tests that prove snapshots, reports, and binaries with valid PQ
      signatures pass and tampered ones fail; prove classical-only signatures
      are rejected under `pq-only`.

### Phase 4 — ExecutionPlan, bundles, and audit chain

- [ ] Update `mvm-contract::verify::SignedEnvelope` and
      `mvm-contract::merkle::SignedAuditRoot` to carry optional PQ signatures.
- [ ] Update `mvm-cli::commands::trust::add` and key-id derivation to accept
      ML-DSA public keys.
- [ ] Update plan/bundle signing in `mvm-build`, `mvm-contract::plan::bundle`,
      and `mvm-cli::commands::vm::up::policy` to produce dual signatures in
      `hybrid` mode.
- [ ] Update audit chain verification (`mvm-cli::commands::ops::audit`) to
      validate PQ signatures and to refuse classical-only chains under the
      appropriate policy.
- [ ] Add conformance scenarios for PQ-signed plans and audit chains.

### Phase 5 — TLS egress and ingress

- [ ] Evaluate and integrate a PQ-capable rustls crypto provider (e.g.,
      `rustls-post-quantum` or a provider with ML-KEM key exchange). Gate
      behind the `post-quantum` feature.
- [ ] Update `mvm-http::client::build_tls` to prefer PQ/hybrid groups and to
      enforce them when `MVM_PQ_POLICY=pq-only`.
- [ ] Update `mvm-core::crypto::egress_ca` to generate ML-DSA CA/intermediate
      certificates when rcgen supports it (or use a hybrid rcgen algorithm
      selection). Until rcgen supports ML-DSA, document the blocker and keep
      ECDSA P-256 under a clear limitation note.
- [ ] Add ingress TLS policy: `mvm-hostd` rejects inbound TLS connections whose
      certificate chain does not include a PQ signature when policy requires
      it.
- [ ] Add tests with mock PQ TLS certificates and downgrade-refusal cases.

### Phase 6 — Supply chain and release trust

- [ ] Track upstream Sigstore/cosign PQ support. When a PQ-capless release
      pipeline is available, update `mvm-core::crypto::image_verify` and
      `mvm-build::release_signature` to verify PQ cosign bundles.
- [ ] Until upstream support lands, implement a local dual-signature policy:
      release artifacts ship both a classical cosign bundle and a PQ
      `manifest.pq.sig` sidecar; production policy requires both.
- [ ] Update `mvm-cli::update` release archive verification to check the PQ
      signature sidecar.
- [ ] Update builder-pack and runtime-pack tooling
      (`mvm-build::builder_pack`, `mvm-cli::commands::env::builder_vm`) to
      produce and verify PQ signatures.
- [ ] Add CI smoke jobs that round-trip a real PQ signature through the release
      pipeline.

### Phase 7 — mvmd control plane

- [ ] Update mvmd worker attestation enrollment to accept and pin ML-DSA
      attestation public keys alongside Ed25519 keys.
- [ ] Update mvmd snapshot verification path to require PQ snapshot signatures
      for workers enrolled with PQ keys.
- [ ] Update mvmd↔mvm-hostd control messages (`mvm-contract::protocol::broker_control`)
      to sign with ML-DSA (hybrid during transition).
- [ ] Update mvmd workload-identity issuer to mint ML-DSA-signed OIDC/JWT
      assertions.
- [ ] Update mvmd TLS/mTLS termination to require PQ certificate chains.
- [ ] Add mvmd-side integration tests for PQ enrollment, snapshot verification,
      and control-message authentication.

### Phase 8 — Claims, conformance, and rollout

- [ ] Update `model/claims.toml` witnesses for the PQ claim with real function
      and CI witnesses.
- [ ] Add a CI gate that builds and tests with `--features post-quantum`.
- [ ] Add a CI gate that refuses new classical-only signature or key-exchange
      additions (lint or architecture review checklist).
- [ ] Update `CONFORMANCE.md` generation and `xtask check-conformance` to cover
      the new PQ claim.
- [ ] Document the operator-facing transition: how to rotate host identity keys,
      how `MVM_PQ_POLICY` interacts with fleet policy, and when `pq-only`
      becomes the default.
- [ ] Update `specs/SPRINT.md` and the refactor rollup to mark the plan
      complete.
- [ ] Run full validation matrix: `cargo check --workspace`,
      `cargo clippy --workspace --all-targets`, `cargo test --workspace`,
      `just check-gated`, BDD suite, and a live backend boot with `hybrid`
      policy.

## Acceptance

- In `pq-only` mode, every mvm/mvmd signature verifies under ML-DSA and every
  key exchange uses ML-KEM; classical-only inputs are refused.
- In `hybrid` mode, every trust decision requires both classical and PQ
  verification; partial signatures are refused.
- All existing security claims remain green, and the new PQ claim has passing
  unit, integration, and BDD witnesses.
- `cargo audit`, `cargo deny`, and supply-chain checks pass for every new PQ
  dependency.
- Documentation tells operators how to rotate keys and how fleet policy
  propagates from mvmd to workers.
