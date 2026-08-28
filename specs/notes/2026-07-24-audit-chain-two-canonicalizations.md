# Two audit chains, two canonicalizations — the deliberate design

_2026-07-24 — resolves the re-scoped workstream D of #1810._

## Context

#1810 originally proposed converging mvm's two chain-signed audit logs onto a
single canonicalization (JCS / RFC 8785). Investigation rejected that: the two
chains sign payloads of different *shapes*, each canonicalization is the correct
one for its shape, and the constraint that blocks convergence
(`serde_jcs` is std-only, so it cannot enter the `no_std` browser mirror) is
structural, not incidental. This note records the design so a future reader does
not re-file the same "inconsistency".

There are two chains. They are not redundant — they attest different things and
are read by different verifiers — and they are, together, one provable spine:
both are Ed25519-signed under the **same** host key, both fail closed on tamper,
and the integration test `audit_chain_spine` (in `mvm-hostd/tests/`) proves each
verifier accepts its valid chain and rejects a tampered one.

## Chain A — host lifecycle chain

- **Writer / verifier:** `mvm-hostd/src/supervisor/audit_file.rs`
  (`FileAuditSigner`, `verify_audit_chain`).
- **Stream:** `~/.mvm/audit/<tenant>.jsonl`, one `SignedEnvelope` per line.
- **Signed bytes:** `serde_json::to_vec(entry) || prev_hash`, where `entry` is a
  **fixed-shape** `AuditEntry` struct (timestamp, tenant, plan id/version,
  optional bundle id/version, image name/digest, event, `BTreeMap` labels).
- **Canonicalization:** *none needed.* The struct's field order is fixed at
  compile time and `serde_json` emits in declaration order (this workspace does
  not enable `serde_json/preserve_order`). The one map, `labels`, is a
  `BTreeMap`, so its key order is already canonical. The byte stream is therefore
  deterministic and — critically — **reproducible from the struct definition
  alone**, with no sorting pass.
- **Browser mirror:** `mvm-contract/src/verify.rs`
  (`verify_audit_chain_bytes`, `MirrorEntry`) re-implements the exact same
  verification in `#![no_std]` + `alloc`, so anyone can audit a downloaded log in
  a browser tab (`web/audit-verify/`) with no host and no trusted server. The
  mirror reproduces `AuditEntry`'s serde shape field-for-field. The
  equivalence is pinned by `mvm_verify_matches_supervisor_chain` in
  `audit_file.rs`: if the upstream struct drifts, a genuine line stops
  verifying and CI fails loudly rather than only the browser tool breaking.

## Chain B — per-VM workload chain

- **Writer / verifier:** `mvm-hostd/src/audit_signer/` (`Chain::append` in
  `chain.rs`, `verify_workload_chain` in `verify.rs`, `CanonicalEntry` in
  `canonical.rs`).
- **Stream:** `~/.mvm/audit/<tenant>.workload.jsonl`, one `OnDiskEntry` per
  line (base64 canonical bytes + signature + `sig_alg` + `entry_hash`).
- **Signed bytes:** the JCS-canonical form of a `CanonicalEntry`, which carries
  a **dynamic** `fields: serde_json::Value`. `fields` is populated per-category
  and, for `workload_audit` entries, reflects data the workload itself supplied
  through `host.audit.v1`. Its object-key order is *not* struct-controlled.
- **Canonicalization:** JCS (RFC 8785) via `serde_jcs::to_vec`
  (`CanonicalEntry::jcs_bytes`). A dynamic value bag has no compile-time key
  order, so a canonicalization pass that sorts object keys is genuinely
  required to make the signed bytes deterministic and standalone-verifiable.
  The verifier re-canonicalizes the parsed entry and rejects any line whose
  stored bytes are not exactly the JCS re-serialization (`NonCanonical`), so a
  non-canonical blob cannot enter through the writer or survive replay.
- **Browser mirror:** none today. Host-only. `verify_workload_chain` is the sole
  verifier and runs behind `mvmctl trust audit verify`.

## Why the two canonicalizations don't converge

The shapes force the choice:

- Chain A signs a fixed struct → declaration-order `serde_json` is already
  canonical and is trivially reproducible in a `no_std` mirror that mirrors the
  struct field-for-field. Adding a sorting pass would buy nothing and would only
  create a second thing that could drift from the mirror.
- Chain B signs a dynamic `Value` → there is no struct order to lean on, so JCS
  key-sorting is load-bearing.

And the mirror constraint blocks moving A onto JCS even if we wanted uniformity:
`serde_jcs` 0.1 is **std-only** — it writes through `std::io::Write`, uses
`std::collections`, forces `serde_json/std`, and contains `unsafe`. It cannot
compile to `wasm32-unknown-unknown` and therefore cannot enter `mvm-contract`
(which is `#![no_std]` + `forbid(unsafe_code)`, the wasm/browser foundation).
So:

- Chain A's browser mirror could not adopt JCS; Chain A keeps declaration-order.
- Chain B, being host-only, can and does use `serde_jcs`; it has no wasm mirror
  to keep in lockstep.

Each scheme is correct for its payload. This is a deliberate split, not an
inconsistency, and `mvm-contract` must **not** take a `serde_jcs` dependency.

## Astral-plane object-key ordering (Chain B caveat)

`serde_jcs` 0.1 orders object keys by their serialized **UTF-8** bytes. RFC 8785
mandates ordering by **UTF-16** code units. The two orders coincide for every
code point up to U+FFFF and diverge only for astral-plane keys (> U+FFFF, e.g.
emoji), where the UTF-16 leading surrogate `0xD800` sorts *below* U+FFFF —
opposite to the UTF-8/scalar-value order. Chain B's dynamic `fields` could carry
such a key.

We **document** this rather than add a runtime guard, deliberately:

1. The divergence is astral-plane-only, not "non-ASCII". An ASCII-only key guard
   would wrongly reject benign BMP keys (`"café"`, `"你好"`); a precise
   "> U+FFFF" guard is an oddly narrow special case.
2. `verify_workload_chain` re-canonicalizes with the **same** `serde_jcs`, so
   Chain B is internally self-consistent for any key plane — there is no actual
   mismatch inside mvm. The `audit_chain_spine` integration test pins this with
   an astral-plane `fields` key that still verifies.
3. No external, spec-strict RFC 8785 verifier consumes Chain B today. The only
   cross-implementation verifier in the tree is Chain A's browser mirror, which
   uses declaration-order and is unaffected.
4. The same scalar-value key ordering is used workspace-wide — `workload_address`,
   `ir_hash`, `broker_control`, and the IR `env`/`extensions` maps — un-guarded,
   and is already pinned in `mvm-core::canonicalizer_equivalence`. Guarding only
   this one chain would be inconsistent.

The caveat only bites a hypothetical *third-party* verifier that reimplements
strict RFC 8785 UTF-16 ordering and is fed an astral-plane workload key. If that
ever becomes a real interop requirement, the fix is a canonicalizer change (or an
input restriction) applied uniformly across the workspace, tracked with the
`canonicalizer_equivalence` drift-lock — not a Chain-B-local patch.

## Optional future migration (Chain B → browser-verifiable)

If Chain B ever needs a browser verifier like Chain A's, migrate its
canonicalization onto the existing `no_std` writer
`mvm-contract::ir::canonicalize` instead of adding `serde_jcs` to `mvm-contract`.
`mvm-core::canonicalizer_equivalence` already proves that
`ir::canonicalize` and `serde_jcs` emit **byte-identical** output over a
divergence-prone corpus (astral-plane keys, escaped values, large integers,
nested/empty containers). So the migration would:

- be **byte-preserving** — existing chains keep verifying, no re-signing, nothing
  changes on the wire; and
- carry the **same** astral-plane-key ordering (`ir::canonicalize` also sorts by
  scalar value), so the caveat above is unchanged.

Until such a requirement exists, Chain B stays host-only on `serde_jcs`. There is
no migration code to write now, and this note is not a commitment to write it.
