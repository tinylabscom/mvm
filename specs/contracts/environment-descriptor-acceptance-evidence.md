# Environment descriptor acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles the acceptance criteria of [#4225](https://github.com/tinylabscom/mvm/issues/4225)
against code on main. The issue owns status. A test is named only after it was
run and passed. Every test below is synthetic, locally signed; none is a
release-image or native-boot witness.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| Contract, export, verification, install and admission changed together; schema decision with old-reader fixtures | `an_environment_survives_export_and_stamps_schema_five`, `an_export_without_an_environment_keeps_the_schema_older_readers_accept` (`mvm-bundler` `tests/export.rs`); `an_environment_stamped_with_an_older_schema_is_refused`, `a_schema_four_bundle_without_an_environment_still_verifies` (`mvm-core` `plan/bundle.rs`) | Old-reader fixtures are in-test manifests, not archived bytes from a released reader. |
| Entrypoint, resources, volumes, secret slots and capabilities survive export and install | `an_environment_survives_sign_verify_and_install`, `a_complete_descriptor_validates_and_round_trips` | Survival is of the signed record. Working directory, named volumes and application services are not fulfilled at launch; admission refuses them (next rows). |
| Advisory resources mapped to launch defaults, not enforced by signature alone | `unnamed_flags_take_the_descriptor_resources`, `a_named_flag_wins_over_the_descriptor`, `a_descriptor_without_resources_changes_nothing` (`mvm-cli` `environment_defaults.rs`) | Defaults only; host policy still decides. |
| No security semantics in labels or silently ignored sidecar fields | `requirements_the_launcher_cannot_enforce_are_not_silently_ignored`, `each_unsupported_requirement_is_sufficient_to_refuse` (`mvm-client`); `unsupported_requirements_are_explicit_and_do_not_change_export_validation` (`mvm-core`); `direct_and_external_admission_refuse_unenforced_environment_requirements` (`mvm-hostd`); `an_unknown_capability_or_field_fails_the_parse` | This is a deliberate fail-closed tightening, not fulfillment: a bundle declaring a working directory, volume or application service is refused. |
| Application services distinct from broker service IDs | `ApplicationService` is its own type in `environment.rs`, separate from plan broker bindings; the unsupported-requirement tests above refuse it | Type-level separation; no test asserts the two namespaces cannot collide, and services are not started. |
| Complete embedded boot closure; empty-cache archive-only boot | None on main | **Unmet.** Needs a native boot and the signed `mvm-guest-bins` release asset, which does not exist for the running version. |
| Tamper, incompatible arch, unsupported descriptor, secret-boundary refusals | `tampering_with_a_signed_environment_breaks_the_signature`, `an_environment_for_another_arch_is_refused_at_verify`, `an_environment_beyond_its_posture_is_refused_at_verify`, `an_unsupported_descriptor_version_is_refused`, `a_secret_slot_with_a_value_fails_the_parse`, `inline_secret_values_in_argv_are_refused`, `an_unbound_required_slot_is_refused_and_an_optional_one_is_not`, `direct_host_admission_enforces_signed_environment_slots` | "Incompatible base" is witnessed for architecture only; no test refuses an incompatible base image contract through the environment path. |

## What remains

Blocked on the release asset and a native boot: complete embedded boot closure
and empty-cache archive-only boot. Other: incompatible-base refusal beyond
architecture, and fulfillment (rather than refusal) of working directory,
volumes and application services.
