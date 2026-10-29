# Vendored gix-object 0.64.1

This directory contains the published Gitoxide object representation crate
with a narrow local signature-feature split.
It provides borrowed and owned Git object representations and encoding support.
The vendored source is a single package, not the complete Gitoxide workspace.

## Source and license

Upstream: https://github.com/GitoxideLabs/gitoxide
Published archive:
https://static.crates.io/crates/gix-object/gix-object-0.64.1.crate
Archive SHA-256:
`56fef799ca40cdeab4de5a3e74a696d8fa9b9c6264592646bf022e026f13ce2c`.
The recorded upstream revision is `e52fe9d03e82437a25bdfb1098e7046ec7e1b558`.
The upstream MIT OR Apache-2.0 licensing is unchanged.
Both [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)
are retained in this directory.
This README is local integration documentation, not restored upstream text.

## Local integration

The root Cargo patch selects this package alongside the patched `gix` source.
The added `signature-basic` feature retains command and tempfile dependencies
without requiring the optional high-performance tempfile registry.
The existing `signature` feature includes `signature-basic` plus that registry,
preserving the existing signature API and feature behavior.
Two signature module gates use the new basic feature; their implementation
bodies are unchanged.
Both normalized and original manifests carry the feature split.

See [the patch provenance](../gitoxide-cache-patches.md) for the complete
upstream delta, immutable source evidence, and reconciliation procedure.
The presence of signature APIs here is not evidence that the checkout-identity
consumer executes signing commands or grants native signing authority.

## Validation

Review the root lockfile and selected feature graph when updating either patch.
Run the coordinated checkout-identity tests and workspace dependency gates.
Source hash verification alone does not establish compilation or runtime parity.
