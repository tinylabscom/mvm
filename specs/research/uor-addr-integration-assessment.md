# Research — UOR-ADDR integration assessment

**Status:** Research note; no implementation commitment
**Date:** 2026-07-15
**Owner:** mvm
**Source:** [UOR-ADDR](https://github.com/UOR-Foundation/uor-addr), reviewed at version `0.2.0`

## TL;DR

UOR-ADDR is a plausible addition to mvm as a **semantic content-identity layer**.
Its strongest fit is addressing structured workload declarations, build
provenance, and cross-language SDK output after format-aware canonicalization.

It is not a replacement for mvm's existing exact-byte identities or trust
mechanisms. OCI digests, archive-file SHA-256 values, dm-verity root hashes,
signatures, authorization decisions, replay-resistant nonces, and ephemeral
runtime identifiers must retain their current semantics.

The recommended next step is a small, additive pilot around one versioned
semantic document—preferably Workload IR or build provenance—with a dedicated
`WorkloadAddress` type. The pilot should not change OCI verification, `.mvm`
signing, or any existing wire contract.

## What was reviewed

The upstream project describes UOR-ADDR as typed content addressing for data
crossing system boundaries. The JSON realization uses RFC 8785 JSON Canonicalization
Scheme (JCS), Unicode normalization, and SHA-256 to produce a label shaped like:

```text
sha256:<64 lowercase hexadecimal characters>
```

The upstream Rust API includes:

- `uor_addr::json::address` for JSON input;
- common types including `AddressInput`, `AddressLabel`, `AddressOutcome`,
  `AddressWitness`, and `VerifyError`;
- format realizations for JSON, S-expressions, XML, ASN.1 DER, CBOR, ring
  elements, and code-module ASTs;
- schema-pinned realizations for documents, photographs, and in-toto signed
  software statements;
- optional GGUF and ONNX model realizations;
- selectable hash axes including SHA-256, BLAKE3, SHA3-256, Keccak-256, and
  SHA-512;
- Rust, C ABI, WASM Component Model, Python, and JavaScript/TypeScript
  distribution paths.

The project declares `#![forbid(unsafe_code)]` for its core crate, `no_std` by
default, Apache-2.0 licensing, and Rust 1.83 as its MSRV. Its current release
and public adoption are early enough that mvm should pin the dependency and
independently verify the exact feature set and conformance vectors it adopts.

## Relevant mvm surfaces

mvm already has several kinds of identity. They must not be conflated merely
because more than one serializes as `sha256:<hex>` or a 64-character hex value.

| mvm surface | Current meaning | UOR-ADDR disposition |
| --- | --- | --- |
| `mvm_oci::FetchedManifest::digest` | SHA-256 of the exact manifest bytes fetched from a registry | Keep unchanged; semantic canonicalization would invalidate OCI digest semantics |
| `mvm_core::packs::Sha256Hex` | SHA-256 of an exact file or payload | Keep unchanged |
| `OciDigest` | OCI `sha256:<hex>` digest identity | Keep unchanged |
| `.mvm` `Manifest::files` | Exact SHA-256 and size for every archive entry | Keep unchanged; this is part of the signed artifact boundary |
| dm-verity `roothash` | Hash defined by the verity block-device format | Keep unchanged |
| Ed25519, cosign, HMAC, and related signatures | Authenticity, integrity, and authorization evidence | Keep unchanged; a UOR label is not a signature |
| VM, operation, session, and replay identifiers | Runtime correlation, uniqueness, or anti-replay values | Keep existing typed/random/sequenced mechanisms |
| Workload IR and structured build metadata | Meaning-bearing documents that may be serialized by multiple tools | Strong candidate for an additive workload address |

The implementation should introduce a distinct domain type rather than aliasing
an existing digest type:

```rust
struct WorkloadAddress(String);
```

The exact final shape should follow mvm's existing newtype and validation
conventions. It should be impossible to pass a workload address to an API that
expects an OCI or exact-byte digest without an explicit conversion.

## Potential uses

### Workload IR identity

The SDKs produce structured workload descriptions across language boundaries.
A workload address could identify equivalent declarations despite irrelevant
JSON formatting or object-key ordering differences. This could support:

- cross-language workload fingerprints;
- semantic compilation-cache keys;
- registry lookup and deduplication;
- audit correlation for a declared workload shape;
- comparison of generated manifests without treating formatting as content.

This is the best initial candidate because the value being addressed is
meaning-bearing structured data rather than a registry-defined byte sequence.

### Build provenance identity

mvm already records source revisions, flake-lock identities, derivation and NAR
hashes, OCI inputs, setup-command hashes, and toolchain versions. A semantic
address could identify the complete provenance record independently of its JSON
serialization details.

This should be additive. A provenance record should continue to carry exact
artifact hashes and signatures, for example:

```text
semantic provenance address
+ exact input and output hashes
+ signature or attestation
+ policy validation
```

The workload address answers whether two records express the same structured
provenance. It does not establish that a trusted producer created the record or
that the referenced bytes are present.

### Cross-language metadata and model references

The published Rust, Python, and JavaScript/TypeScript paths could make a common
semantic identity useful at SDK and control-plane boundaries. Possible examples
include addon metadata, model descriptors, document-like registry metadata, and
structured broker records that are intentionally language-neutral.

This should be limited to documents for which the canonicalization rules are
explicitly part of the contract. It should not be applied generically to every
JSON message in the broker or guest protocols.

## Security and compatibility boundaries

### Semantic identity is not exact-byte identity

Canonicalization intentionally makes some byte differences disappear. That is
useful for declarations but unsafe where a format defines identity over received
bytes. In particular, mvm's OCI fetcher documents that any normalization of a
manifest would change its digest and break the registry pin. UOR-ADDR must not
be inserted into that verification path.

The same rule applies to `.mvm` archive entries, kernel and rootfs files,
initrds, verity sidecars, and any signature payload whose contract is defined in
terms of exact serialized bytes.

### A label does not authenticate its producer

A UOR label is a deterministic digest-like identifier. It does not provide:

- producer authentication;
- authorization to boot or execute an artifact;
- proof of supply-chain provenance;
- confidentiality;
- freshness or replay resistance.

Any integration must preserve mvm's existing signature, trust-policy, admission,
validity-window, and nonce checks. A workload address may be included in a
signed or attested record, but it cannot replace those checks.

### Canonicalization must be versioned

Changing a canonicalization implementation, realization, schema, or hash axis
can change an address without changing the apparent source document. An mvm
field using UOR-ADDR should therefore record enough context to make its meaning
unambiguous, either through a versioned enclosing document or a dedicated type
whose contract pins:

- the realization, such as JSON/JCS;
- the hash algorithm;
- the schema or IR version;
- the accepted input shape and limits.

Unknown versions should fail closed at security-sensitive boundaries.

### Do not use deterministic semantic labels for ephemeral IDs

VM IDs, operation IDs, session IDs, capability tokens, plan nonces, and other
replay-sensitive values need uniqueness, unpredictability, or sequencing. A
deterministic address is the wrong primitive for those roles.

## Dependency and supply-chain assessment

The dependency is attractive from a systems perspective: it is Rust-native,
has a `no_std` core, forbids unsafe code in the core crate, and publishes
conformance material. However, the project is young (`0.2.0`) and its broader
architecture includes UOR Foundation and Prism dependencies beyond mvm's
current direct crypto and serialization set.

Before adoption, mvm should verify:

1. the precise transitive dependency and feature closure for the chosen
   realization;
2. compatibility with the workspace's Rust toolchain and target platforms;
3. `cargo deny`, advisory, license, duplicate-version, and unused-dependency
   results;
4. compile and runtime behavior with default features disabled where practical;
5. deterministic output against the upstream conformance vectors;
6. behavior for malformed input, nesting/depth limits, Unicode normalization,
   and JSON numeric edge cases;
7. whether the selected implementation is acceptable in guest-facing or
   embedded binaries, rather than only in host-side code.

The first integration should be host-side and isolated behind a small module.
There is no reason to place the full dependency in guest binaries until a
specific guest use case earns that cost.

## Recommended pilot

The pilot should be deliberately additive and reversible:

1. Add the pinned `uor-addr` dependency only to the crate that owns the chosen
   semantic document.
2. Define a validated `WorkloadAddress` newtype distinct from `Sha256Hex` and
   `OciDigest`.
3. Address one versioned document, preferably Workload IR or build provenance.
4. Store the address as an optional field initially; do not make it a required
   wire field or cache key until interoperability is demonstrated.
5. Add tests for deterministic output, key-order and whitespace invariance,
   Unicode normalization, numeric edge cases, malformed input, version
   rejection, and serde round trips.
6. If cross-language identity is a goal, compare Rust output with the published
   TypeScript and Python paths using shared fixtures.
7. Run the full dependency and workspace quality gates before considering the
   pilot complete.

The pilot should explicitly prove that existing OCI, `.mvm`, verity, signature,
and replay tests remain unchanged and continue to pass.

## Decision

**Adopt for investigation, not yet as a general project-wide dependency.**

UOR-ADDR is a good candidate for semantic workload and provenance identities,
especially where mvm needs a stable cross-language reference to structured
meaning. It is a poor fit for exact-byte verification, cryptographic
authorization, or runtime identity generation. A focused pilot can establish
whether its canonicalization and dependency closure provide enough value without
disturbing the existing trust and artifact-integrity model.

## Sources

- [UOR-ADDR repository](https://github.com/UOR-Foundation/uor-addr)
- [UOR-ADDR README](https://github.com/UOR-Foundation/uor-addr/blob/main/README.md)
- [UOR-ADDR Rust crate](https://github.com/UOR-Foundation/uor-addr/tree/main/crates/uor-addr)
- [UOR-ADDR conformance contract](https://github.com/UOR-Foundation/uor-addr/blob/main/CONFORMANCE.md)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [OCI Image and Distribution Specifications](https://github.com/opencontainers/image-spec)