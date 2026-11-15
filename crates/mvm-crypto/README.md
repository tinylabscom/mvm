# mvm-crypto

Backing: shipped-source
Validation: `cargo test -p mvm-crypto`

Internal, unpublished shared cryptographic primitives.

## Purpose

Keep low-level crypto operations together, organized as modules rather than
separate crates per algorithm. The current `aead` module provides AES-256-GCM.

AES-GCM's generic encryption loops are instantiated in their caller. Optimizing
the entire `mvm-core` crate to accelerate those loops makes development builds
expensive. This small crate owns the concrete calls and receives the development
profile's optimization override; the rest of `mvm-core` stays unoptimized.

The implementation delegates directly to the existing `aes-gcm` dependency.
It does not implement a cipher or introduce a new third-party dependency.

## Ownership

Callers borrow a 32-byte key and 12-byte nonce for one encryption or decryption.
They remain responsible for key custody and zeroization, nonce uniqueness,
associated-data selection, framing, signatures, admission, and replay protection.
This crate returns ciphertext with its authentication tag, or verified plaintext;
it neither generates nor prepends a nonce.

## Tests

Run `cargo test -p mvm-crypto` for the AES-256-GCM known-answer vector and rejection
of wrong keys, nonces, associated data, truncated tags, and tampered bytes.
`mvm-core` retains its independent direct-cipher compatibility tests, at-rest
frame tests, and authenticated-session tests.
