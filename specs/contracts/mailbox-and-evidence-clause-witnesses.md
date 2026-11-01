# Mailbox operational contract and evidence completeness: clause witnesses

Backing: preview
Validation: none — this table maps clauses to the code and tests that exist today; it promotes no claim.

Scope: two boxes of [#4839](https://github.com/tinylabscom/mvm/issues/4839).
The issue owns status. Verdicts are MET (an outcome test exercises the
clause), PARTIAL (a type, a unit-level piece, or a single layer is witnessed,
the end-to-end behaviour is not), or NOT YET (no enforcing code in this tree).

## Mailbox operational contract (ADR-057)

What is in the tree: the canonical contract (`mvm-contract::protocol::mailbox`),
the crypto and capability gate (`mvm-core::mailbox`), and the peer overlay,
transport and resource limits (`mvm-core::mailbox::transport`). The dedicated
service and local queue (#4629), journal (#4630), movement (#4631) and
benchmarks (#4635) are open; nothing below claims them.

| Clause | Enforcing code | Witness | Verdict |
| --- | --- | --- | --- |
| Synchronous admission/refusal of `cast` (ADR-057 §5) | Reply-route shape per kind (`MailboxMessageKind` validation); capability gate `open_envelope` | `call_cast_and_reply_enforce_their_reply_route_shape`, `every_capability_operation_is_checked_by_the_same_authority_gate` | PARTIAL: the authority and shape refusals exist; the local queue that refuses full/rate-limited/shutting-down synchronously is #4629 |
| No silent loss after acceptance (§6, §7) | `DeliveryOutcome` vocabulary only | none | NOT YET: no journal or queue exists to lose or keep a message (#4629, #4630) |
| Timeout ambiguity (§5) | none beyond the typed `Unavailable`/`Late` outcomes | none | NOT YET |
| Deduplication (§6) | `ReplayIdentity` and `InMemoryReplayProtector` refuse a replayed nonce; `DeliveryOutcome::Duplicate` is a signed outcome | `tampering_wrong_key_and_replay_fail_closed`, `destination_receipt_signature_covers_outcome_and_identity` | PARTIAL: replay is refused; the bounded retained-dedup store that answers a duplicate with the original disposition is #4630 |
| Retry bounds (§7) | `ResourceLimits::max_retries`, `take_retry`, transport fallback order | `retries_are_bounded_per_peer_until_that_peers_delivery_resets_them`, `retry_tracking_cannot_grow_past_the_peer_bound`, `fallback_and_reconnect_are_deterministic_and_bounded` | PARTIAL: transport retries are bounded and witnessed; delivery-attempt, backoff and dead-letter state (default eight attempts) are not built |
| Fencing / stale epoch (§2, §10) | Epoch and policy-epoch checks in `verify_identity_and_time` and `verify_capability_scope`; transport binding verification | `identity_scope_epoch_expiry_and_content_type_are_checked`, `binding_verification_rejects_tamper_identity_epoch_policy_time_and_assurance` | PARTIAL: stale epochs are refused at verification; durable source fencing before activation is #4631 |
| Host-blindness tiers (§11) | Binding assurance field checked at transport binding verification; ciphertext-only direct delivery | `binding_verification_rejects_tamper_identity_epoch_policy_time_and_assurance`, `direct_delivery_is_pass_by_value_bounded_and_cancelable` | PARTIAL: tier is carried and checked; no attestation or key-release witness, so no host-blind claim |
| Relay is explicit, never a silent fallback (§13) | `RelayPolicy`, overlay ordering | `overlay_orders_direct_then_customer_relay_and_requires_public_relay_opt_in`, `relay_policy_defaults_to_no_public_relay_and_orders_path_classes`, `relay_bytes_are_bounded_exactly_and_direct_is_free` | MET |
| Authenticated transport is not mailbox authority (§13) | `open_envelope` runs the capability gate independent of transport | `authenticated_connection_is_not_mailbox_authority`, `coordinator_hint_cannot_substitute_a_route_token` | MET |
| Separate topology/acceptance performance measurements (§15) | none | none | NOT YET (#4635) |

Accepted architecture is not security-claim promotion: no mailbox claim is
added to ADR-001 by this table.

## Evidence completeness (ADR-110)

Enforcing code: `mvm-hostd::audit::{receipt_export,receipt_archive,receipt_archive_verify}`
and the manifest types in `mvm-core::receipt_archive`. Witnesses are in
`tests/audit_receipt_archive.rs` unless noted.

| Clause | Enforcing code | Witness | Verdict |
| --- | --- | --- | --- |
| In-scope entries accounted for, receipt or citation (exhaustive mapping) | `map_event` returns the two-armed `EntryMapping`; no `Option` fall-through | `every_leaf_is_accounted_for_and_counted_by_event`, `a_transcript_anchor_becomes_a_citation_pointing_at_its_chain_leaf` | MET |
| Exactly once | `check_completeness` requires distinct leaf indices; a derivable archive must carry exactly `0..tree_size` | `a_leaf_listed_twice_in_place_of_another_fails_completeness_despite_equal_count` (count-only check missed this), `a_derivable_archive_missing_a_leaf_fails_completeness` | MET |
| Attested vs derivable, never a boolean | `Completeness` and the three-arm `CompletenessResult` | `a_plan_scoped_archive_records_completeness_as_attested`, `a_tenant_scoped_archive_records_completeness_as_derivable`, `the_three_results_are_reported_independently` | MET. Limit kept: a plan-scoped archive cannot detect an omitted in-scope entry; the verifier reports `Attested`, not a pass |
| Leaf-inclusion proofs, not just a signed receipt | One proof per leaf; `proof.leaf_index == leaf.index` binding | `every_receipt_member_has_a_matching_inclusion_proof`, `every_proof_in_the_archive_verifies_against_the_signed_root`, `each_proof_is_bound_to_the_leaf_its_own_receipt_came_from`, `a_proof_swapped_between_receipts_fails_inclusion` | MET |
| Valid signature alone is insufficient | Integrity, inclusion and completeness are separate bits | `a_tampered_receipt_member_fails_integrity_and_sets_only_that_bit`, `a_foreign_host_key_fails_integrity` | MET |
| Audit/receipt parity with the client boundary (#4415/#4416) | not in this tree's archive path | none | NOT YET, owned by those issues |
