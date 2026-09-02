# Workload address (UOR-ADDR-compatible) — pilot design (DECISION-READY)

A scoped, additive increment: give the **Workload IR** a canonical content
address. Two declarations that deserialize to the same IR value receive the
same address regardless of JSON formatting, object-key order, or which SDK
language emitted them; array order remains significant. This does not touch
any exact-byte or trust mechanism. Builds on the research note
[`specs/research/uor-addr-integration-assessment.md`](../research/uor-addr-integration-assessment.md)
and its decision ("adopt for investigation, additive pilot around the Workload
IR"). This document is the concrete, ready-to-execute cut; it is **not** a
dependency commitment.

## Intent

The SDKs emit the Workload IR across Rust / Python / TypeScript. Formatting and
object-key order differ while the deserialized IR value does not. A
`WorkloadAddress` lets mvm:
- fingerprint the same workload IR value cross-language;
- key a canonical workload compile/build cache (distinct from exact-byte keys);
- correlate audit entries by declared workload shape;
- dedupe/registry-lookup equivalent declarations.

The address is `sha256(JCS(ir))` rendered `sha256:<64-hex>` — the UOR-ADDR JSON
realization (RFC 8785 JSON Canonicalization + SHA-256). Matching that spec buys
UOR-ecosystem interop *as a conformance property*, not as a dependency (see
§"The dependency question").

## Non-negotiable boundary (this is the load-bearing part)

A workload address is a deterministic digest of a normalized Workload IR value. It authenticates
nothing, proves no provenance, is not confidential, and is not fresh. It
**never** enters — and this pilot must prove, by leaving their tests green — any
of:

- **Exact-byte identities:** OCI manifest/layer digests, `.mvm` archive-entry
  SHA-256, kernel/rootfs/initrd/verity-sidecar bytes, dm-verity roothash. These
  are defined over *received bytes*; canonicalization would silently change
  them. UOR-ADDR must not be inserted into any verification path (the OCI fetcher
  explicitly documents that normalizing a manifest breaks the registry pin).
- **Trust/authorization:** ed25519 / cosign / HMAC signatures, plan admission,
  validity windows, trust policy. A label is not a signature — every existing
  check stays.
- **Ephemeral/replay identifiers:** VM/op/session IDs, capability tokens, plan
  nonces. Those need unpredictability or sequencing; a deterministic address is
  the wrong primitive.

The type system enforces the separation: `WorkloadAddress` is a **distinct
newtype**, never interchangeable with `Sha256Hex`, `OciDigest`, `KeyId`, or
`Nonce`. Passing one where an exact-byte digest is expected must not compile
without an explicit, intentional conversion.

## The type + its versioned contract

```rust
/// Canonical content address of a versioned Workload IR value (JSON/JCS
/// realization, SHA-256). NOT an exact-byte digest, a signature, or a
/// runtime id.
pub struct WorkloadAddress(String); // "sha256:<64 lowercase hex>"
```

The address is only meaningful with its canonicalization context pinned — the
research note's "canonicalization must be versioned" rule. The contract fixes:
the realization (JSON/JCS), the hash axis (SHA-256), and the **IR schema
version** (the IR already carries `schema_version` / `IR_MAJOR.IR_MINOR` with
`validate_schema_version`). The address is computed over the validated IR at a
known schema version; an unknown/rejected schema version fails closed *before*
addressing. If the realization or hash axis ever changes, that is a new address
version, surfaced explicitly — never a silent reinterpretation.

## Where it lives — and the host pilot

**Host-side first (the pilot).** mvm uses `serde_jcs = "0.1"` (RFC 8785 JCS —
the same canonicalizer that signs `ControlRequest`), `sha2`, and the small
`unicode-normalization` dependency to apply UOR-ADDR's Unicode NFC boundary.
The `mvm-core` module computes `workload_address(&Workload) -> WorkloadAddress`
as `sha256(NFC(JSON value) → serde_jcs::to_vec(value))`, formatted
`sha256:<hex>`. No `uor-addr` crate or Prism/UOR-Foundation transitive closure
is adopted, which preserves mvm's hard dependency-aversion (ADR-002).
Interop with the UOR ecosystem becomes a **conformance-vector test** (assert our
label equals UOR-ADDR's published vectors for the same input), not a dep.

The Workload IR itself lives in `mvm-contract` (`#![no_std]`, wasm-clean). The
*host-side* address computation reads that IR from `mvm-core` — fine, that is the
normal direction. Do **not** put the address computation in `mvm-contract` for
the pilot: `serde_jcs`'s `no_std` status is unverified, and there is no host need
for it in the no_std layer yet.

## The dependency question (deferred to the browser slice, WS11 P4)

The reason to ever take the `uor-addr` crate is **not** host-side — it is the
browser. WS11 P4 wants `mvm-contract` running in the browser, and if a workload
address is computed there (or in the TS/Python SDKs), you want a **guaranteed
identical label** across Rust-host / browser-wasm / SDK. `uor-addr` is built for
exactly that: `no_std`, `forbid(unsafe)`, a WASM Component Model distribution
path, and published conformance material — i.e. cross-implementation equality *is
its contract*. That guarantee is a wasm-layer value, not a host-layer one.

So the crate decision is a **P4 question**, and it is gated on the research
note's full verification checklist before adoption: the exact transitive/feature
closure, `cargo deny` / advisories / license / duplicate-major / unused-dep
results, toolchain + target compatibility, deterministic output vs. upstream
conformance vectors, malformed-input / depth / Unicode / numeric-edge behavior,
and whether it is acceptable in guest/embedded binaries. If a no_std IR address
is wanted before then, the alternatives are (a) verify `serde_jcs` no_std, (b) a
small in-house no_std JCS, or (c) `uor-addr` — decided at P4, not now.

## Pilot steps (additive, reversible)

1. Add the `WorkloadAddress` newtype (validated: `sha256:` + 64 lowercase hex)
   in the host-side crate that owns IR authoring, distinct from every existing
   digest type.
2. `workload_address(&Workload) -> WorkloadAddress` via `serde_jcs` + `sha2`
   over the schema-validated IR. Zero new deps.
3. Expose it as an **optional** field / accessor — never a required wire field,
   never a cache key or lookup key *yet* (the note: don't make it load-bearing
   until interop is demonstrated).
4. Do NOT touch OCI verification, `.mvm` signing, verity, or any wire contract.

## Tests (the pilot's gate)

- Deterministic output; **key-order + whitespace invariance** (two JSON encodings
  of the same IR → same address); Unicode normalization; JSON numeric edge cases;
  malformed-input rejection; **schema-version rejection fails closed**; serde
  round-trip of the newtype.
- **Conformance interop:** the label equals UOR-ADDR's published vector(s) for a
  shared IR fixture (proves spec-compatibility without the dep).
- **Boundary proof (mandatory):** the existing OCI, `.mvm`, verity, signature,
  admission, and replay/nonce tests remain unchanged and green — the address
  layer is provably additive.
- (If cross-language identity is pursued) compare Rust output with the TS/Python
  SDK paths over shared fixtures.

## Sequencing

Orthogonal to WS11 P3 (the egress-seam integration) — do not weave it in. It is
a bounded, self-contained increment that can land any time after WS11 P2. Its
natural *browser* extension aligns with WS11 P4 (compute-in-browser + SDK
equality is where the `uor-addr` dependency, if any, is evaluated).

## Open decisions (surfaced, not pre-decided)

1. **Host crate placement:** `mvm-core` vs `mvm-sdk` for the pilot module (wherever
   Workload-IR authoring/compile is owned host-side).
2. **Crate vs. native for the no_std/browser path** (P4): `uor-addr`, verified
   `serde_jcs`-no_std, or an in-house no_std JCS — decided when the browser slice
   needs it, under the full dependency verification.
3. **When (if) the address becomes load-bearing** — a canonical workload cache key or
   registry-dedup key — only after cross-impl interop is demonstrated.

## Decision

Additive host-side pilot, `WorkloadAddress` over the Workload IR, matching the
UOR-ADDR JSON realization (including Unicode NFC normalization) as a conformance
property. The published 12-fixture UOR-ADDR baseline is pinned in the
`mvm-core` tests.
The `uor-addr` crate itself is a deferred, verification-gated WS11-P4/browser
decision — that is where its cross-implementation guarantee actually earns its
keep. The pilot changes no exact-byte, trust, or replay mechanism, and proves it.
