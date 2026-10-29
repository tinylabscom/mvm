# Vendored gix 0.87.1

This directory contains the published `gix` Rust Git repository library
with a narrow local optional-cache feature patch.
It is not a checkout of the complete Gitoxide workspace.

## Source and license

Upstream: https://github.com/GitoxideLabs/gitoxide
Published archive: https://static.crates.io/crates/gix/gix-0.87.1.crate
Archive SHA-256:
`fdefc1465d8631807deaf504dacdeff628b978de515653b47976ca7c28ab2a7a`.
The recorded upstream revision is `3ebca8b66017ab2dd02a38f75f78f485bee1ded8`.
The upstream MIT OR Apache-2.0 licensing is unchanged.
Both [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)
are retained in this directory.
This README is local integration documentation, not restored upstream text.

## Local integration

The root Cargo patch selects this source for the pinned package.
The checkout-identity consumer requests attributes, excludes, and SHA-1
with default features disabled.
That consumer reads repository data and configuration; it does not use
Git hooks, command filters, credential helpers, or network operations.
The crate itself contains broader APIs; this is not a claim that those
capabilities have been removed from its source.

The local patch makes the dynamic object cache independently optional,
preserves the upstream default cache behavior, and selects the basic
signature feature without the optional high-performance tempfile registry.
See [the patch provenance](../gitoxide-cache-patches.md) for the complete
source delta, source hashes, feature rationale, and update procedure.
Both normalized and original Cargo manifests carry the feature changes.

## Validation

Reconcile through the root workspace lockfile and inspect the selected
feature closure rather than assuming disabled defaults remove all support crates.
Run the workspace checkout-identity tests, closure gates, and dependency checks
described in the patch provenance when changing this integration.
Source provenance alone does not establish runtime parity or a passing build.
