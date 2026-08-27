# serde_jcs 0.1.0 — RFC 8785 object-key-ordering non-conformance

**Status:** Upstream-facing finding; reproducing evidence in-tree
**Scope:** `serde_jcs` 0.1.0 (the JCS canonicalizer `mvm-core` hashes for `WorkloadAddress`)
**Owner:** mvm (finding); resolution belongs to the `serde_jcs` / UOR-Foundation upstream

## Summary

`serde_jcs` 0.1.0 does not order object keys per RFC 8785 §3.2.3, which mandates
sorting by **UTF-16 code units**. It instead serializes each key to its UTF-8
bytes and emits keys in **UTF-8 byte** order (lexicographic on the encoded
bytes), which equals Unicode **scalar-value** order. The two orderings coincide
for every code point up to U+FFFF and diverge for astral-plane code points
(> U+FFFF), because a UTF-16 surrogate pair's leading unit (0xD800–0xDBFF)
sorts *before* U+FFFF, whereas the scalar value U+10000 sorts *after* U+FFFF.

## Reproduction

An object with the two keys `"\u{FFFF}"` and `"\u{10000}"`:

- RFC 8785 (UTF-16 code-unit order): `"\u{10000}"` sorts first (0xD800 < 0xFFFF).
- serde_jcs 0.1.0 (UTF-8 byte / scalar order): `"\u{FFFF}"` sorts first
  (U+FFFF < U+10000).

Mechanism: `serde_jcs`'s object serializer buffers entries as
`BTreeMap<Vec<u8>, Vec<u8>>` keyed on the serialized key bytes and emits in that
map's byte order. UTF-8 lexicographic order is identical to scalar-value order,
not to UTF-16 code-unit order.

mvm's own hand-rolled `no_std` canonicalizer (`mvm_contract::ir::canonicalize`)
sorts keys by `str` `Ord` (also scalar-value order), so the two agree with each
other — which is why mvm's internal `workload-address ↔ ir-hash` equivalence
holds byte-for-byte. This is pinned as a drift-lock in
`crates/mvm-core/src/canonicalizer_equivalence.rs`, with a caveat now on the
`workload_address` and `ir::canonicalize` module docs.

## Impact

- Any address computed via `serde_jcs` (or mvm's matching canonicalizer)
  differs from one a strictly-conformant JCS implementation would produce **for
  documents carrying astral-plane object keys** (e.g. an emoji key in a workload
  `env` or `extensions` map). ASCII/BMP keys — i.e. all realistic workloads —
  are unaffected.
- For mvm this is a cross-implementation interop caveat, not an internal
  correctness bug: mvm never claims two *different* documents share an address,
  and both its canonicalizers agree. It matters only if a second toolchain
  computes the "same" workload address with a spec-correct JCS and expects
  byte-identical results.

## Proposed upstream fix

Order object keys by UTF-16 code units before emission. In Rust this is a
one-line comparator over the key strings:

```rust
keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
```

`str::encode_utf16` is `core`-available, so this is compatible with a `no_std`
realization. A conformance vector for the U+FFFF / U+10000 pair should accompany
the fix.

## mvm follow-through

- Keep the drift-lock test; it will catch the day `serde_jcs` changes ordering
  (mvm's two canonicalizers would then disagree and the lock fails, signalling
  that `ir::canonicalize` must adopt the same UTF-16 order in lockstep).
- If mvm ever needs true cross-language address parity with a spec-correct JCS
  SDK, adopt the UTF-16 ordering in **both** `serde_jcs` (or its replacement)
  and `mvm_contract::ir::canonicalize` together, and add cross-language
  conformance vectors.

## Sources

- RFC 8785 §3.2.3 (Sorting of Object Properties).
- `serde_jcs` 0.1.0 object serialization (`BTreeMap<Vec<u8>, Vec<u8>>` emit order).
- In-tree reproducing test: `crates/mvm-core/src/canonicalizer_equivalence.rs`.
