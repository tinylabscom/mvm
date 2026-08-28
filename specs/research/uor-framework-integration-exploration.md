# Research — UOR Framework integration exploration

**Status:** Research note; host-side UOR-ADDR conformance baseline implemented
**Date:** 2026-07-22 (updated)
**Owner:** mvm
**Source:** [UOR Framework](https://github.com/UOR-Foundation/UOR-Framework), [UOR-ADDR](https://github.com/UOR-Foundation/uor-addr), [Prism](https://github.com/UOR-Foundation/prism), and related UOR Foundation repositories, reviewed against the mvm tree.

## TL;DR

The UOR Foundation has several projects, but only one is a strong fit for mvm today: **UOR-ADDR** as a cross-implementation semantic content-addressing primitive. mvm has implemented a host-side UOR-ADDR-compatible `WorkloadAddress` over the Workload IR (`crates/mvm-core/src/workload_address.rs`).

The broader UOR Framework ontology, Prism substrate, and PrimeShield crypto are not good fits for mvm's current architecture or threat model. The host-side conformance loop is now closed against UOR-ADDR's published vectors; any actual `uor-addr` crate dependency remains deferred to the wasm/browser layer (WS11 P4) where cross-language equality is load-bearing.

## What mvm already has

### Semantic / content identity

| Type / primitive | Location | What it does |
|---|---|---|
| `WorkloadAddress` | `crates/mvm-core/src/workload_address.rs` | `sha256(JCS(Workload))` rendered as `sha256:<64-hex>`, with Unicode NFC normalization. A distinct newtype with validating parse, serde round-trips, a pinned golden test vector, and the published UOR-ADDR JSON fixture set. |
| `workload_address()` | same | Validates IR schema version first, normalizes JSON strings/object keys to NFC, then `serde_jcs::to_vec` + `sha2::Sha256`. |
| `ir_hash()` | `crates/mvm-contract/src/ir/hash.rs` | Same JCS + SHA-256, rendered as bare 64-hex (no `sha256:` prefix). Used inside launch plans and audit records. |
| `canonicalize()` | `crates/mvm-contract/src/ir/canonicalize.rs` | Hand-rolled `no_std` JCS writer. A drift-lock test (`canonicalizer_equivalence.rs`) proves it matches `serde_jcs` byte-for-byte. |
| `mvmctl build address` | `crates/mvm-cli/src/commands/build/address.rs` | CLI surface that prints the independent `WorkloadAddress` and `ir_hash` identities. |

Key boundary property: `WorkloadAddress` is explicitly **not** interchangeable with `Sha256Hex`, `OciDigest`, `KeyId`, or `Nonce`. There are no `From`/`Into`/`Deref` impls between them, and tests enforce that separation.

### Exact-byte identities and cryptography

mvm already has a complete set of exact-byte and cryptographic primitives:

- `Sha256Hex` — exact-file/exact-payload SHA-256.
- `OciDigest` — registry manifest/layer pin.
- `ContentDigest` / `ContentAddressedStore` — SHA-256 blob store with dedup.
- `BundleArtifact.sha256` — exact artifact hash inside signed `.mvmpkg`.
- Ed25519 (`ed25519-dalek`) for signed `ExecutionPlan`, audit log, and `.mvmpkg` signatures.
- AES-256-GCM (`aes_gcm`) for snapshot encryption at rest.
- HMAC (`hmac`) for snapshot integrity.
- SHA-256 (`sha2`) throughout OCI, packs, IR, provenance, and content-addressed storage.
- Optional cosign/Sigstore verification (`sigstore-verify`).

These are intentionally **not** semantic identities. They must stay untouched.

## UOR Foundation ecosystem — what is relevant

### UOR-ADDR (`UOR-Foundation/uor-addr`)

This is the UOR project mvm already assessed in `specs/research/uor-addr-integration-assessment.md` (version `0.2.0`).

- **Core promise:** chain-agnostic canonical content addressing across recursively-grammared formats.
- **JSON realization:** RFC 8785 JCS + Unicode normalization + SHA-256 → `sha256:<64-hex>`.
- **API surface:** `AddressInput`, `AddressLabel`, `AddressOutcome`, `AddressWitness`, `VerifyError`; `uor_addr::json::address`.
- **Other realizations:** S-expressions, XML, ASN.1 DER, CBOR, ring elements, code-module ASTs, in-toto signed statements, GGUF, ONNX.
- **Hash axes:** SHA-256, BLAKE3, SHA3-256, Keccak-256, SHA-512.
- **Distribution:** Rust crate, C ABI, WASM Component Model, Python, TypeScript.
- **Quality signals:** `#![forbid(unsafe_code)]` in core, `no_std` by default, Apache-2.0, Rust 1.83 MSRV, published conformance material.
- **Maturity signal:** `0.2.0`; early; transitive closure includes UOR Foundation / Prism substrate.

**Disposition for mvm:** adopt as a **conformance property** on the host now; consider the crate only for the wasm/browser layer (WS11 P4) where cross-implementation equality is load-bearing.

### UOR Framework (`UOR-Foundation/UOR-Framework`)

A Rust workspace implementing the UOR Foundation ontology: content-addressed, symmetric, multi-metric object spaces with algebraic structure over `Z/(2^n)Z`. Publishes `uor-foundation` (typed Rust traits for the ontology) and `uor-ontology` (the source of truth). Formats: JSON-LD, Turtle, N-Triples, OWL, JSON Schema, SHACL, EBNF.

**Disposition for mvm:** **low direct fit**. The ontology is a general-purpose mathematical reference system; mvm does not need an ontology-driven type system for microVM orchestration. The value is in the *concrete* UOR-ADDR realization, not the full framework.

### Prism (`UOR-Foundation/prism`)

A standard-library façade over the UOR substrate:

- `uor-prism` re-exports `uor-foundation` + Layer-3 sub-crates.
- `uor-prism-crypto` exposes `HashAxis`, `CurveAxis`, `SignatureAxis`, `CommitmentAxis` with SHA-2/3, BLAKE3, Keccak, secp256k1.
- `uor-prism-verify` is a replay façade for verifiers.

**Disposition for mvm:** **medium, but only if mvm adopts `uor-addr` as a dependency**. Prism is the substrate `uor-addr` sits inside; taking `uor-addr` would pull a slice of it. Evaluate the exact transitive closure before adopting.

### Other UOR projects

| Project | What it is | Disposition for mvm |
|---|---|---|
| `PrimeShield` | Quantum-resistant crypto based on Prime Framework math | **Avoid.** Novel, unreviewed cryptography; mvm's threat model does not require post-quantum primitives, and replacing AES-256-GCM / Ed25519 with experimental math would violate the dependency-aversion and audit posture. |
| `atlas-embeddings` | First-principles exceptional Lie-group construction | **None.** Pure math, no engineering surface for mvm. |
| `uor-research` | Research notes | **Low.** May contain relevant content-addressing theory, but no concrete APIs. |

## Concrete integration opportunities

### 1. Close the UOR-ADDR conformance loop (completed 2026-07-22)

The existing `WorkloadAddress` golden test pins:

```text
sha256:bf6f9f61571d7c5080144d83b681eb6718d76ab30ab80f61a715c50ac85b6ab3
```

The 12 published UOR-ADDR JSON byte-identity fixtures are now pinned in
`crates/mvm-core/src/workload_address.rs`. The test covers key ordering, empty
containers, nested values, arrays, numbers, mixed scalar types, and composed /
decomposed Unicode. NFC normalization was added at the JSON boundary so both
café forms produce the upstream label. The existing astral-plane key-ordering
caveat remains documented because the `serde_jcs` implementation still differs
from RFC 8785's UTF-16 ordering for that unrepresented class.

The separate Python and TypeScript SDK parity witness is also green; the
published UOR vectors are the independent implementation check that closes the
conformance loop.

### 2. Semantic address for `BuildProvenance` (short term)

`BuildProvenance` is a structured, versioned document recording source revisions, flake-lock identities, derivation/NAR hashes, OCI inputs, setup-command hashes, and toolchain versions. A UOR-ADDR-compatible workload address over it would let two equivalent provenance records share an identity regardless of JSON formatting.

- Add as an **optional** field or host-side accessor.
- Reuse existing `serde_jcs` + `sha2` (zero new deps).
- Keep exact artifact digests and signatures inside the record; the workload address is an additional correlation key, not a replacement.

### 3. Cross-SDK / IR deduplication and cache keys (short-to-medium term)

The existing `WorkloadAddress` is already useful for:

- Cross-language workload fingerprints.
- Semantic compile/build cache keys (distinct from exact-byte cache keys).
- Registry lookup / deduplication of equivalent declarations.

A natural next step is to persist `WorkloadAddress` in the signed `ExecutionPlan` or a registry index, but **only as optional metadata** until cross-implementation interop is proven.

### 4. `uor-addr` crate adoption (deferred to WS11 P4)

The only scenario where taking the `uor-addr` crate is clearly justified is the browser/wasm path. If `mvm-contract` needs to compute workload addresses in the browser, or if the TypeScript/Python SDKs must produce bit-identical labels with the Rust host, `uor-addr` is purpose-built for that: `no_std`, `forbid(unsafe)`, WASM Component Model, and published conformance vectors.

Before adoption, run the full verification checklist:

1. Exact transitive dependency and feature closure.
2. Compatibility with the workspace toolchain and target platforms, including `wasm32-unknown-unknown`.
3. `cargo deny`, advisory, license, duplicate-version, and unused-dependency results.
4. Compile and runtime behavior with default features disabled where practical.
5. Deterministic output against upstream conformance vectors.
6. Behavior for malformed input, nesting/depth limits, Unicode normalization, and JSON numeric edge cases.
7. Acceptability in guest-facing or embedded binaries.

### 5. Bundle / pack manifest canonicalization (not recommended without migration)

`.mvmpkg` `BundleManifest` is serialized with plain `serde_json::to_vec` today. Moving it to JCS would change existing signature fixtures and the mvmd byte-identity contract. **Do not change the signing input.** If a workload address of a manifest is desired, compute it as a separate field rather than replacing canonicalization.

## Risks and boundaries

### Semantic identity is not exact-byte identity

Canonicalization intentionally makes some byte differences disappear. That is useful for declarations but unsafe where a format defines identity over received bytes. UOR-ADDR must not enter:

- OCI manifest/layer digest verification.
- `.mvm` / `.mvmpkg` archive-entry SHA-256.
- dm-verity roothash.
- Kernel/rootfs/initrd/verity sidecar bytes.
- Signature payloads whose contract is exact bytes.

### A label does not authenticate its producer

A UOR label provides no authentication, authorization, provenance, confidentiality, freshness, or replay resistance. mvm's Ed25519 signing, cosign verification, trust policy, admission, validity windows, and nonce checks must remain unchanged.

### Do not use deterministic labels for ephemeral IDs

VM IDs, operation IDs, session IDs, capability tokens, and plan nonces need uniqueness, unpredictability, or sequencing. A deterministic workload address is the wrong primitive.

### Dependency risk

`uor-addr` 0.2.0 is early and pulls UOR Foundation / Prism substrate. Any crate adoption must be gated by the verification checklist above and justified by a concrete cross-implementation requirement.

## Recommendations

### Do now (host-side)

1. Keep the 12-fixture UOR-ADDR JSON conformance test synchronized with the upstream published vectors.
2. ~~If cross-language identity is a goal, compare Rust output with the TypeScript and Python SDK paths over a shared IR fixture.~~ **Completed 2026-07-22:** the checked-in `hello-parity` fixture now runs through both SDKs and the native Rust IR; all three resolve to the pinned `sha256:b7106af4133c7d678744adb3b617e7289bc3f4c131b2df03a8e9cc49aac90037` workload address, with `xtask check-ir-parity` enforcing drift in CI.
3. Consider a workload address for `BuildProvenance`, computed with the existing `serde_jcs` + `sha2` stack, as a separate optional follow-up.

### Do later (wasm/browser layer, WS11 P4)

1. Verify whether `serde_jcs` compiles under `no_std` / `wasm32-unknown-unknown`. If not, evaluate:
   - a small in-house `no_std` JCS writer,
   - the `uor-addr` crate, gated by the full verification checklist.
2. Adopt the `uor-addr` crate only if cross-implementation equality in the browser is a hard requirement.

### Avoid

1. Adopting the full UOR Framework / `uor-foundation` ontology.
2. Adopting `PrimeShield` or other novel UOR crypto.
3. Replacing `.mvmpkg` signing canonicalization with JCS without a byte-identity migration plan.
4. Using `WorkloadAddress` for ephemeral or replay-sensitive identifiers.

## Alignment with simplification plan

The refactor direction wants fewer crates, fewer features, fewer deps, and `mvm-contract` as a `no_std` wasm-clean core. UOR-ADDR aligns best as a **wasm-layer dependency decision** (P4), not as a host-layer dependency now. The host already has everything it needs (`serde_jcs`, `sha2`). Delaying the `uor-addr` crate decision until the browser/wasm slice is being built keeps the simplification plan on track and avoids premature supply-chain expansion.

## Summary table

| UOR product | Relevance | Recommended action |
|---|---|---|
| `uor-addr` | High | Evaluate as a P4 wasm/browser dependency; keep host path native (`serde_jcs` + `sha2`); run conformance tests. |
| `uor-prism-crypto` | Medium | Only if `uor-addr` is adopted; audit transitive closure. |
| `uor-foundation` / UOR Framework ontology | Low | Do not adopt. |
| `PrimeShield` | Low | Do not adopt. |

## Sources

- [UOR Framework repository](https://github.com/UOR-Foundation/UOR-Framework)
- [UOR-ADDR repository](https://github.com/UOR-Foundation/uor-addr)
- [UOR-ADDR README](https://github.com/UOR-Foundation/uor-addr/blob/main/README.md)
- [UOR-ADDR Rust crate](https://github.com/UOR-Foundation/uor-addr/tree/main/crates/uor-addr)
- [UOR-ADDR conformance contract](https://github.com/UOR-Foundation/uor-addr/blob/main/CONFORMANCE.md)
- [Prism repository](https://github.com/UOR-Foundation/prism)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [mvm UOR-ADDR integration assessment](../research/uor-addr-integration-assessment.md)
- [mvm workload address pilot design](../../specs/refactor/12-workload-address-pilot.md)
