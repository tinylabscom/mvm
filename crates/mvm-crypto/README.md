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

## Algorithm interface

`aead::Aead` exposes encryption and authenticated decryption with associated
`Key`, `Nonce`, and `Error` types. Implementations can use different key and
nonce representations; callers can use a generic bound or a trait object with
those types specified.

`aead::Aes256Gcm` is the current implementation. Existing storage and session
protocols select it explicitly, keeping their wire formats unchanged. The trait
does not introduce algorithm negotiation or a runtime configuration switch.

## Ownership

AES-256-GCM callers borrow a 32-byte key and 12-byte nonce for one operation.
They remain responsible for key custody and zeroization, nonce uniqueness,
associated-data selection, framing, signatures, admission, and replay protection.
This crate returns ciphertext with its authentication tag, or verified plaintext;
it neither generates nor prepends a nonce.

## Tests

Run `cargo test -p mvm-crypto` for the AES-256-GCM known-answer vector and rejection
of wrong keys, nonces, associated data, truncated tags, and tampered bytes.
Integration tests exercise trait-object dispatch and a downstream refusal-only
test implementation with different key, nonce, and error types.
`mvm-core` retains its independent direct-cipher compatibility tests, at-rest
frame tests, and authenticated-session tests.
