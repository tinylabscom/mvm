---
title: Evidence Archive Format
description: Normative .mvmev member layout, canonicalization, and offline verification rules.
---

An `.mvmev` file is an uncompressed POSIX tar archive. Schema version 1 is
designed so an independent verifier can check it without running mvm.

The words **MUST**, **MUST NOT**, and **SHOULD** below are normative.

## Members

| Path | Contents |
| --- | --- |
| `manifest.json` | Pretty-printed JSON `SignedEvidenceManifest` envelope |
| `manifest.sig` | Raw 64-byte Ed25519 signature, equal to the decoded envelope `signature` |
| `host.pub` | Raw 32-byte Ed25519 host verifying key |
| `host.did` | The host's `did:key`, as UTF-8 text |
| `receipts/NNNN-<type>.json` | Signed execution receipt |
| `cited/<leaf>.json` | In-scope audit entry without a receipt mapping |
| `proofs/leaf-<index>.json` | RFC 6962 inclusion proof for one manifest leaf |
| `audit/<tenant>*.jsonl` | Exact chain-signed audit log bytes |

Every path named by `manifest.members` MUST exist and its bytes MUST have the
listed `sha256:<lowercase hex>` digest. Every `manifest.leaves` item MUST name
one receipt or citation and MUST have a proof at
`proofs/leaf-<leaf.index>.json`. Extra members provide no authenticated
evidence and SHOULD be ignored.

## Canonicalization identifier

`manifest.schema_version` is also the canonicalization identifier. Version 1
means all of the following:

1. Parse the JSON value.
2. Refuse any JSON number that is not an integer representable as an unsigned
   or signed 64-bit integer.
3. Refuse any string value or object key containing a non-ASCII code point.
   JSON `null`, booleans, arrays, and objects are allowed.
4. Serialize the admitted value with the JSON Canonicalization Scheme (JCS),
   RFC 8785, with no trailing newline.

A future change to any of these rules MUST use a new schema version. A verifier
MUST refuse a schema version whose canonicalization rule it does not implement.
The integer and ASCII restrictions remove the cross-implementation differences
in ECMAScript floating-point rendering and UTF-16 versus UTF-8 key ordering.

The frozen, language-neutral version-1 vectors live at
`tests/vectors/mvmev-canonicalization-v1.json`. They cover ordering, escaping,
integer bounds, empty and nested containers, invalid values, the manifest
content address, and Ed25519 signature material. The private key in that file
is test data only.

## What is signed and hashed

The bytes stored in `manifest.json` are **not** the signed bytes. Parse the
envelope, select its nested `manifest` object, apply the version-1
canonicalization above, and verify the envelope's Ed25519 `signature` over
those canonical bytes. The detached `manifest.sig` MUST match that signature.
The key derived from `signed_by` MUST equal both `host.pub` and `host.did`.
The envelope's `signed_at` is informational and is not signed.

`manifest.archive_id` is computed by cloning the manifest, replacing
`archive_id` with the empty string, canonicalizing that object, and computing
`sha256:<lowercase hex>` over the canonical bytes. The populated archive ID is
then inside the bytes covered by the manifest signature.

Each signed execution receipt uses the same version-1 canonicalization. Its
receipt ID is SHA-256 over its payload with `receipt_id` blank, and its Ed25519
signature is over the populated canonical payload.

These SHA-256 addresses are part of the `.mvmev`, OCI, and audit wire
contracts. Other internal content-addressed data may use BLAKE3; verifiers MUST
use the algorithm named by each field rather than substituting one for another.

## Verification results

Verification produces three independent results and SHOULD continue after one
result fails so the report retains every finding.

- **Integrity** checks the manifest content address and signature, binds the
  embedded host key and DID to the signer, checks every member SHA-256 digest,
  and verifies every signed receipt.
- **Inclusion** verifies every RFC 6962 proof against the host-signed audit
  root and separately requires `proof.leaf_index == leaf.index`. Membership
  without that equality can prove a valid but different leaf.
- **Completeness** is derived only for a tenant-scoped full-chain archive, by
  comparing the number of leaves with `audit_root.tree_size`. A plan-scoped
  archive is a subsequence, so its completeness is host-`attested`, not
  independently passed.

The CLI uses exit bits 1, 2, and 4 for integrity, inclusion, and completeness
failures respectively. Attested completeness is not a failure, but MUST be
reported as an assertion rather than a successful check.

## Operator input constraint

Version 1 intentionally keeps the existing fail-closed export boundary:
non-ASCII tenant IDs, workload IDs, label values, or member paths make the
manifest unsignable, so export fails without emitting an archive. Admission
does not reject those historical identifiers globally. Operators who need an
evidence archive MUST use ASCII identifiers and labels for the archived scope.
