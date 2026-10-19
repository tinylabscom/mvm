<!-- This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. See LICENSE. -->

# mvm-macho-sign

An internal, byte-only library for ad-hoc Mach-O signing.
The package is not published to a registry.

## Boundary

`sign` accepts Mach-O bytes and a property-list entitlement value and returns
new bytes, replacing entitlements on every architecture.
Thin and universal binaries are supported within the checked layout limits.
The library refuses layouts without existing signature space or unused
load-command room; it does not relink or shift existing executable data.
Malformed inputs and layout refusals return errors rather than partial output.
File-backed sections must fit their containing segment's file range, not merely
the enclosing binary. Zero-fill section types do not claim file bytes.

This crate does not read or publish executable files, launch processes, use
signing keys, perform CMS cryptography, contact a network, or notarize code.
Parsing and constructing signature bytes is not native signature authority.
The caller owns role policy, publication, and native signature validation.
It must not treat this library as loaded-process entitlement evidence.

## Provenance and licensing

This is modified MPL-2.0 Covered Software adapted from Gregory Szorc's
`apple-codesign` 0.29.0.
See [PROVENANCE.md](PROVENANCE.md) for the archive hash, upstream revision,
file-by-file source mapping, modifications, and redistribution obligations.
[LICENSE](LICENSE) contains the MPL-2.0 text; retain the source notices.
Native redistribution requires the license and source-availability notice
identifying the exact source build revision, not a moving branch.

## Validation

Run `cargo test --locked -p mvm-macho-sign` from the repository root.
These in-memory format tests do not establish Security.framework acceptance,
Developer ID identity, notarization, installed boot, or live VM readiness.
