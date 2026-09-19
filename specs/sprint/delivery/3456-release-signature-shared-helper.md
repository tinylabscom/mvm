# Release-archive signatures go through the shared keyless identity loop

Backing: shipped-source
Validation: cargo nextest run -p mvm-build --features manifest-verify -E 'test(/release_signature/)'

`mvm_build::release_signature::verify_release_archive_bytes` kept its own copy
of "try each accepted keyless identity, keep the last failure, refuse an empty
set". `mvm_core::crypto::image_verify::verify_signed_payload_under_any_identity`
is the shared implementation that packs, pack revocation and the image-set
verifier already call. The copy here was the one that could drift unnoticed.

It now calls the shared helper and only attributes the refusal to the asset
(`RuntimeOverlayError::SignatureInvalid { asset, reason }`). Behaviour is
unchanged: the reason is still the verifier's error text, the first identity
that verifies still admits, and an empty set still refuses. The one visible
difference is the empty-set reason, which now reads the helper's "no accepted
identities configured for keyless verification" rather than a second phrasing
of the same fact.

The existing release-signature tests are the behaviour witness: the committed
`v0.18.0-rc.1` bundle still verifies under the CLI train and is still refused
under the boot-image train, a missing or malformed bundle still refuses naming
the asset, and a refusal still carries no bundle bytes. Empty-set refusal had
no test at this layer; `an_empty_identity_set_refuses_and_names_the_asset`
adds one.
