# Application descriptor acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issues; it is not a claim of complete enforcement.

This reconciles the acceptance criteria of
[#4509](https://github.com/tinylabscom/mvm/issues/4509) and
[#4510](https://github.com/tinylabscom/mvm/issues/4510) against code on main
(landed by #4513 and #4523). The issues own status. "Witnessed" names a test
that exists and was run; every limit is stated rather than implied.

One limit applies to both sections. No test signs an application descriptor
with Sigstore: signing is keyless and needs Fulcio, which an offline test
cannot reach. The positive application cases inject the signature checker
(`adopt_with` / `verify_with` in `mvm-core` `registry_pack/dispatch.rs`), and
the real Sigstore fixtures under `crates/mvm-cli/tests/fixtures` are legacy
manifests. A genuine signed application through the full CLI is unwitnessed.

## #4509 — verify application descriptors in the pack pull path

| Criterion | Evidence | Limit |
|---|---|---|
| Legacy and application manifests are distinguished without a permissive fallback | `strict_dispatch_refuses_unknown_hybrid_duplicate_and_malformed_descriptors` (unknown kind, schema 3, duplicate `kind`, a legacy `files` field on an application, reference mismatch, non-JSON); `legacy_dispatch_preserves_strict_legacy_validation` (`registry_pack/dispatch.rs`) | None beyond the shared signing limit. |
| Catalog exact-byte digest and publisher identity are checked before strict validation; parsing is not authentication | `application_dispatch_authenticates_before_parsing_and_checks_pins` (a rejecting checker refuses valid bytes; an empty namespace policy gives `UntrustedNamespace`); `application_checks_the_namespace_authority_not_a_descriptor_claim`; CLI `application_catalog_mismatch_refuses_before_signature_or_acquisition` and `application_bytes_cannot_reuse_a_legacy_publishers_signed_bundle` (`mvm-cli` `tests/signed_registry_pack.rs`, real Sigstore bundle over legacy bytes, no pin and no cache written) | The accepted-publisher case runs with an injected checker; the real-signature cases are all refusals. |
| Legacy policy pull and recursive signed dependency pulls are preserved | `a_signed_profile_include_fetches_verifies_and_pins_its_dependency`, `a_tampered_signed_dependency_is_not_pinned`, `published_signed_pack_pulls_pins_and_loads_without_network`, `a_real_signed_image_pack_pulls_with_its_image_and_reopens_under_the_pin` (real Sigstore fixtures) | None. |
| Identity/digest pins and revocation stay coherent with registry trust | `application_dispatch_authenticates_before_parsing_and_checks_pins` (drifted pin gives `Lock`, matching pin verifies); `application_evidence_uses_the_existing_current_revocation_feed` (revoked identity, revoked manifest digest, expired feed, through the existing `check_verified_pack_at`) | Revocation is checked against synthetic feeds with an injected feed verifier. |
| Tests: valid authenticated metadata; unknown kind/schema, malformed/duplicate fields, catalog mismatch, wrong publisher, revocation, pin drift | All the tests above | "Valid authenticated" is witnessed only through the injected checker (shared limit). **This is the unmet part of the bullet.** |
| A verified handoff suitable for bundle acquisition, not a second trust system | `VerifiedRegistryApplication` carries the original bytes, signature bundle, signer and digest; `trusted_archive_is_bound_to_descriptor_and_private_snapshot` and `current_revocation_policy_and_same_version_pin_drift_refuse_before_installation` (`application_bundle/tests.rs`) consume it | None beyond the shared limit. |

Verdict: every bullet has a passing named test except the positive half of the
fifth, which needs a genuine signed application. The issue stays open on that.

## #4510 — acquire and atomically install application bundles

| Criterion | Evidence | Limit |
|---|---|---|
| Signed archive size and SHA-256 are enforced while acquiring supported sources, with bounded resource use | `size_digest_key_architecture_and_independent_trust_are_mandatory` (size, digest); `archive_bounds_and_nonregular_inputs_refuse_before_verification` (ceiling `MAX_APPLICATION_ARCHIVE_BYTES`, directory, symlink, hard link); `bounded_download_streams_exact_bytes_and_refuses_oversize_or_interruption` (`mvm-cli` `http.rs`, a local TCP server); `bounded_registry_pull_refuses_a_layer_above_the_signed_size` (`bundle/fetch.rs`) | Bounds are witnessed on a loopback HTTP server and an in-memory OCI registry, not a real network. The CLI-level `application_source` rule (4 GiB cap, file and HTTP refused) has no direct test of its own. |
| Independent `.mvmpkg` verification against the existing trust store; key ID must match the descriptor | `size_digest_key_architecture_and_independent_trust_are_mandatory` (key-ID mismatch, truncated archive, unenrolled store); `trusted_archive_is_bound_to_descriptor_and_private_snapshot` (re-verify against the private snapshot, and failure when trust is removed) | Archives are signed with hermetic ephemeral Ed25519 keys. |
| A key is never enrolled because the descriptor names it | Same test asserts the empty trust root is not created after refusal | None. |
| Architecture and compatibility/revocation at the existing seams | Architecture: `size_digest_key_architecture_and_independent_trust_are_mandatory` (`x86_64` descriptor against an aarch64 bundle). Revocation, publisher policy, pin: `current_revocation_policy_and_same_version_pin_drift_refuse_before_installation`, `publisher_policy_load_occurs_under_lease_and_withdrawal_before_commit_refuses` | Host and backend compatibility stays at the execution admission seam, which belongs to #4511 and is not exercised here. |
| Atomic install; failure leaves no runnable partial install or premature pin | `install_commit_is_last_and_failed_commit_leaves_only_complete_unreferenced_content`; `bundle_removal_is_excluded_until_application_reference_commit` | Per the confirmed design, a failed pull may leave complete, verified, unreferenced content; this is install-before-pin, not a distributed transaction. Filesystem sync ordering is not a power-loss certification, and no process-kill test exists. Interruption is witnessed at the download and at the commit step only. |
| Repeated pull reuses verified content or repairs a poisoned cache without bypassing trust | `repeated_install_rechecks_trust_and_repairs_poisoned_cache_without_digest_drift` | None. |
| Tests: digest, size, key ID, trust, architecture, interruption, cache tampering, idempotence, source-locator rules | Above, plus source-locator syntax in `mvm-core` `registry_pack/application/tests.rs` against `application_source_vectors.json`; `symlinked_roots_and_bundle_leases_refuse_without_following_targets` | No end-to-end CLI pull of an application was run (shared limit); the CLI output is covered by `installed_application_text_names_the_manifest_and_bundle` and `installed_application_json_binds_the_bundle_and_key` (`commands/pull.rs`) only. |

Verdict: the core install transaction and its refusals are witnessed. Missing:
a genuine signed application installed through the CLI, a CLI-level test of
`application_source`, a process-kill interruption test, and Linux-target runs.
The issue stays open on those.

## Native boot

Nothing here boots an installed application; launching from the installed
reference is #4511.
