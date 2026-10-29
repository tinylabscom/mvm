<!-- This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. See LICENSE. -->

# Narrow ad-hoc Mach-O signing extraction

This is modified MPL-2.0 Covered Software adapted from Gregory Szorc's
`apple-codesign` 0.29.0, not an independently Apache-licensed implementation.
The historical local candidate at `9e6a6a43ac` was inspected per file; no older
tree was checked out or imported.

The locally cached crates.io archive was independently hashed during extraction:
SHA-256 `f24e9ebdb70a2aee3ca1cea217009fb50776955f0d7678c31d22e48c1524667f`.
Its `.cargo_vcs_info.json` identifies commit
`2312b1e5bd77322c019613e0ca624e222c6c6e08`, path `apple-codesign`, in
https://github.com/indygreg/apple-platform-rs. The cached unpacked source and
license were available for inspection. Upstream author: Gregory Szorc
(`gregory.szorc@gmail.com`).

## Source mapping and modifications

| Covered local file | Upstream algorithm or wire format |
| --- | --- |
| `src/lib.rs` | `signing_settings.rs::import_settings_from_macho`: compatibility metadata, first signed identifier fallback, universal-wide legacy digest selection |
| `src/macho.rs` | `macho.rs`: final `__LINKEDIT`, unsigned command room, embedded Info.plist, platform targeting; `macho_signing.rs`: signature alignment and header mutation; `macho_universal.rs`: fat descriptors and 16 KiB alignment |
| `src/signature.rs` | `code_directory.rs`: versioned headers and page/special-slot digests; `macho_signing.rs`: ad-hoc/hardened/runtime flags and SDK fallback; `entitlements.rs`: executable flags; `embedded_signature.rs` and `embedded_signature_builder.rs`: blob formats, alternate CodeDirectory, empty requirements and CMS wrapper |
| `src/der.rs` | `plist_der.rs`: application-16/version-1 wrapper, dictionary/array/string/boolean/signed-integer encoding |
| `src/tests.rs` | In-memory tests of these adapted algorithms, including upstream DER boolean wire vectors |

Checked byte slices replace Goblin/Scroll. Bounded TLV parsing replaces Rasn.
Duplicate keys, malformed/nonminimal lengths, trailing values and excessive
nesting are refused; dictionary key order is not used as entitlement authority.
Fat alignment, reserved fields, duplicate commands/segments, build-tool extents,
and versioned CodeDirectory boundaries are checked. The layout refusal is typed.
Rewriting never moves referenced non-signature file data. Two passes size the
signature exactly and hash the final headers, rather than estimate CMS padding.
SHA-1 0.10 and SHA-256 0.11 use the workspace's existing compatible versions;
the algorithm is unchanged, and no new duplicate-version policy is introduced.

Existing slice identifiers, hardening, runtime SDK, embedded Info.plist and
complete launch/library constraint blobs are retained, with fresh digests.
Unsigned slices use the first signed identifier or `com.mvm.prepared`.
Legacy compatibility is selected for the entire universal binary as upstream
does, with a SHA-256 alternate directory. XML and DER entitlements are replaced
on every slice. Team identity, signing keys, previous entitlement authority and
certificates are not inherited. An empty CMS-format wrapper is emitted, but no
CMS cryptography, certificate, filesystem, process or network API is present.

## Authority, limitations and redistribution

The caller owns fixed role policy, staged publication, and public
Security.framework validation with `CHECK_ALL_ARCHITECTURES`. The loaded-process
boundary retains SecTask entitlement authority. Parsing here is not signature
authority. A final `__LINKEDIT` and either existing signature or unused
load-command room are required. Output signature offsets and fat descriptors
must fit 32 bits; this core does not relink. External bundle resources are not
inputs. Destination publication requires exclusive ownership or cooperating
writers: a byte re-read and regular-file guard is not a malicious-writer CAS.

Every source file and the manifest/documentation in this directory are MPL-2.0;
`LICENSE` reproduces the upstream license. Preserve all notices. File-level MPL
does not change unrelated files' licenses. Native binary archives and SDK
packages must include the MPL text and source-availability notice identifying
this directory at the exact 40-hex source build revision, never moving `main`.
That revision must identify the source actually used to build the native
artifact. These notices cover this extraction, not the entire artifact's license
closure. Source-only SDK distributions do not contain this native core.

Tests and native evidence require the integrating owner's coordinated run grant.
No unrun test is evidence that the extraction is accepted by Security.framework.
