# Diagnostic data protection and retention

Backing: preview
Validation: none — this contract defines required behavior, not a claim of complete runtime enforcement.

This contract belongs to [diagnostic confidentiality and retention](https://github.com/tinylabscom/mvm/issues/4184).
The issue owns implementation and verification status. This document defines the
data boundary and the rules implementations must satisfy.

## Trust boundary

Protection is against unintended persistence, disclosure to other local users,
and accidental export under a trusted host. It is not protection from the host
administrator, a compromised host, or a process already holding a decrypted
payload or an open descriptor. Private permissions are not encryption.

Encryption does not hide file sizes, traffic timing, or the existence of a
capture. Removing a file name is not secure erasure of storage blocks, snapshots,
backups, or data still reachable through an open descriptor.

## Classification

Classify fields by their contents, not by a filename or the word "metadata".
Unrecognized fields and free-form strings are sensitive by default.

| Data | Class | Required handling |
|---|---|---|
| Console output, supervisor stderr, exception text and command output | Sensitive diagnostic payload | Retained copies require protected capture; transient plaintext needs an explicit owner and lifetime. |
| Telemetry messages, attributes, span names and user-supplied labels | Sensitive diagnostic payload | Apply the same protection as console payload; a JSON encoding or a byte cap is not a confidentiality boundary. |
| Configuration values, environment values, command arguments and user-selected paths | Sensitive configuration | Do not copy into diagnostic metadata. Capture only when explicitly authorized as protected payload. |
| Fixed status codes, bounded counters, byte counts, timestamps and opaque generated identifiers | Operational metadata | May remain unencrypted in private managed state when the schema explicitly allows them. |
| Ciphertext digests, verification roots, wrapped data keys and opaque recipient identifiers | Integrity and key-envelope metadata | May accompany protected data in private managed state. Never include raw keys or plaintext digests of low-entropy secrets. |
| Audit event kinds and explicitly typed, payload-free verification fields | Audit metadata | Preserve independently of payload retention. An arbitrary audit label is not automatically allowed metadata. |
| Operator-selected decrypted exports | Intentional plaintext disclosure | Require verified decryption and explicit selection of the destination; disclose the export event without putting its payload in the audit record. |

Human-selected machine names and labels are not equivalent to generated opaque
identifiers. A metadata schema that exposes them must explicitly account for
their sensitivity. "May remain unencrypted" does not mean world-readable or
safe to publish.

## Protected capture

Reuse the existing transcript envelope rather than introduce another encryption
format: a per-capture data key, host-key wrapping, encrypted chunks, ciphertext
digests, and a sealed manifest bound to the admitted capture identity.

The capture owner must exist for the entire producer lifetime, including
detached runs. Creating an empty manifest or arming a sink with no producer does
not demonstrate capture. A plaintext console fallback is not an acceptable
substitute when the selected policy requires encrypted persistence.

Loss remains explicit. Queue saturation, storage refusal, eviction and a
reconstructed seal must not produce a manifest that silently claims a complete
recording. Capture must not introduce unbounded producer work or block workload
output while waiting for storage.

A new capture may initialize its required wrapping key through the existing
key-custody facility. Reading, verifying or exporting an existing capture must
load its existing key without creating a replacement. Missing keys, malformed
envelopes, incorrect keys or failed integrity checks refuse decryption; they
never authorize plaintext fallback.

## Private creation and replacement

Managed payload files and key material must be created at `0600`; managed
directories must be created at `0700`. Restriction must hold before publication
and before sensitive bytes are written, not after a permissive creation window.

Starting a fresh diagnostic capture replaces the managed file with a private
inode rather than following or modifying an existing symbolic-link target or
another hard link's inode. Failure must not damage the previous destination or
leave an exposed staging file. The caller remains responsible for a trusted
parent directory; safe replacement of the last path component alone does not
establish that trust.

Managed path-following readers reopen a replaced capture from byte zero and do
not replay bytes from the previous inode. A reader that encounters a missing
path may wait for recreation. Existing external descriptors are not revoked by
replacement and must not be described as erased.

## Independent retention dimensions

An admitted retention policy must distinguish these quantities:

- **Byte/chunk budget:** the maximum retained payload window, with a defined
  accounting basis. Plaintext lengths, ciphertext lengths and total on-disk
  allocation are different quantities; the policy must identify which is bounded.
- **Capture duration:** how long a producer may contribute to a capture.
- **At-rest age:** how long persisted payload remains eligible for retention.
  This is measured from an explicit persisted timestamp, not from the last read,
  collector restart, or key lookup.

A byte-bounded ring does not establish an age limit, and a capture-duration
field does not establish at-rest expiry. An implementation must not advertise a
deadline unless a lifecycle owner actually performs or reconciles expiration.
Expiry uses checked time arithmetic and must not delete payload on an invalid
clock reading or arithmetic overflow.

The numerical age policy must be explicitly selected and recorded before
automatic deletion is enabled. This contract does not enable a default TTL or
retroactively authorize deletion of existing captures. Operator-selected exports
are outside managed retention; capture cleanup must not traverse arbitrary
export paths, backups or unrelated files.

## Audit preservation during cleanup

Payload expiry and audit-evidence retention are separate operations. Cleanup
must not rewrite a sealed manifest to conceal removed payload or present a
retained suffix as a complete run. Keep the immutable verification identity and
an authenticated record of intentional removal so verification can distinguish
expiry from corruption or unaccounted loss.

Audit-segment cleanup preserves the existing seal, continuation and deliberate
prune records and their chain linkage. If the required evidence cannot be
recorded, cleanup must not silently advance the deletion boundary. An expired
payload is not exportable merely because its audit metadata still verifies.

## Required witnesses

Use synthetic sensitive markers, never real customer data. Exercise protected
persistence, restart, replacement, missing and incorrect keys, explicit export,
byte pressure, age expiry, clock errors and interrupted cleanup. Assert that
protected payload is absent from plaintext managed artifacts and audit labels,
that permitted operational metadata remains usable, and that loss and intentional
removal cannot be mistaken for complete capture. Permission-only tests cannot
stand in for encryption or retention tests.
