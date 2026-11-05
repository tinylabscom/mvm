# Cold HVF owner: recovery receiver and lifetime

Status: **Contract draft. Nothing here is implemented as a receiver, and no
requirement below is witnessed by a test that exists today unless it is cited
as existing.**

Scope: [#4655](https://github.com/tinylabscom/mvm/issues/4655), under
[ADR-022](../adrs/022-target-architecture.md#cold-hvf-invocation-owner).
It refines [hvf-entrypoint-owner.md](hvf-entrypoint-owner.md), which owns the
process, authority, qualification and key-custody text; this file states only
the recovery receiver and lifetime rules and does not restate or relax that
contract. Issue comments own approval provenance and delivery status.

## Evidence rule

Tests named below are in two classes. A test written in code format
exists in the tree today and covers the pure lifecycle table only. A test
written in plain text is **planned**: it names a test to be written and exists
nowhere yet. Planned names may change when written; the requirement stays.

**Mocks do not close #4655.** A mock owner, a fake clock, a stub signer or the
pure lifecycle table can show that a refusal rule is coded; none shows that a
real cold HVF owner keeps the original VMM child through a real frontend exit.
**The real HVF witness is still required** for the two documented-build
scenarios and for every row marked HVF below, and both Firecracker-only
scenario gates stay until those pass. Host-only tests, gated compilation and
foreground diagnostic runs are not that evidence.

## Boundaries

- The recovery receiver is the original per-VM owner process itself, reached
  by a typed local client call. It is not a root service, a fleet service, a
  process host, or a second launcher.
- The recovery surface has exactly three verbs: observe, cancel-stop and
  acknowledge-result. It has no start, no detach, no command or argument
  carrying request, no generic replay of what the CLI sent, and no way to hand
  it a process identifier.
- A PID, a pid file, a socket path or a saved generation number never
  reconstitutes custody. Recovery reaches the live original owner or it
  reaches nothing.
- CLI and Studio call the same client library. Neither holds a `Child`,
  admission capability, or native completion proof.

## Requirements

### R1. Original custody from birth

The owner holds the original VMM `Child`, the admitted plan, frozen inputs,
leases and helper lifetimes from before the first native effect until terminal
cleanup. The quarantine record is durable before VMM birth. Nothing is
serialized, transferred or reacquired after a frontend exit.

Planned witnesses:
- owner_holds_child_and_leases_across_frontend_exit (HVF)
- quarantine_record_is_durable_before_vmm_birth
- no_code_path_constructs_a_child_from_a_pid

### R2. Bounded resources

Every buffer, queue, connection and wait on the recovery path is bounded
before allocation, within the qualification envelope of the entrypoint-owner
contract. The accepted macOS bound is the in-process one recorded there; the
rows of that table the maintainer decision marks not enforced are not claimed
here. Zero never means unlimited, and an out-of-envelope request refuses.

Planned witnesses:
- oversized_declared_length_is_refused_before_allocation
- fifth_control_connection_is_refused_and_does_not_evict_cancellation
- slow_unauthenticated_peer_is_dropped_at_the_exchange_deadline
- output_overflow_requests_cancellation_and_never_projects_success

### R3. Generation and identity refusal

A request applies only if its whole binding equals the retained one: operation,
request digest, controlling principal, tenant, owner incarnation and, once
native, the instance generation. Any difference refuses and consumes no
sequence number. A request carrying a generation before the owner has one is
malformed, not an invitation to invent one.

Existing: `a_stale_generation_or_identity_is_refused_and_consumes_nothing`.

Planned witnesses:
- receiver_refuses_wrong_principal_tenant_incarnation_and_plan_over_a_real_socket
- receiver_refuses_a_generation_from_a_prior_owner_incarnation (HVF)
- pre_native_request_naming_a_generation_is_refused

### R4. Authentication of the peer, not only the bytes

Same UID, socket mode and a discoverable generation are necessary and not
sufficient. Each connection answers a fresh receiver-issued challenge bound to
the request and sequence, signed by the enrolled controlling principal, and the
receiver checks the actual connected peer. A forwarded socket or replayed proof
refuses. Until the keyless lifecycle operations exist, recovery connections
refuse outright.

Planned witnesses:
- recovery_connection_refuses_while_the_keyless_operations_are_absent
- a_proof_replayed_on_a_second_connection_is_refused
- a_proof_for_one_verb_does_not_authorize_another
- a_forwarded_socket_without_the_controlling_credential_is_refused

### R5. CLI exit or disconnect during uncertain execution

Frontend EOF, kill or crash is not completion and not detach. The owner records
one cancellation intent, keeps all custody, and quiesces through the original
child only. It does not replay dispatch and does not keep a detached workload
running as a feature. Cancellation is accepted on its reserved path even while
startup, dispatch or output delivery is blocked.

Existing: `disconnect_requests_cancellation_and_keeps_custody`,
`repeated_cancellation_coalesces_and_never_completes`.

Planned witnesses:
- kill_the_cli_mid_dispatch_owner_stops_the_original_child (HVF)
- cancel_is_accepted_while_output_reader_is_blocked
- cancel_is_accepted_during_startup
- disconnect_at_every_state_never_infers_success

### R6. Failed recovery handoff

A reconnect that fails to authenticate, times out, loses its response or
reaches a busy owner changes nothing. Lost acknowledgement of an accepted
request is resolved by observing the same operation, never by a new start. A
conflicting start with the same operation identifier refuses without a second
admission.

Existing: `foreign_requests_in_recovery_required_consume_no_sequence`.

Planned witnesses:
- lost_response_is_resolved_by_observe_and_not_a_second_start
- conflicting_start_binding_refuses_without_a_second_admission
- failed_authentication_leaves_owner_state_and_sequence_unchanged

### R7. Repeated recovery

Any number of observe calls is allowed and read-only. Repeated cancel coalesces
into one pending intent. Repeated result acknowledgement is reported as already
acknowledged and repeats no cleanup and no audit sealing. A stop is attempted at
most once; deadline exhaustion retains uncertainty and starts no retry loop.

Existing: `acknowledgement_is_exact_and_repeated_delivery_repeats_nothing`,
`stop_is_attempted_at_most_once`.

Planned witnesses:
- repeated_observe_does_not_advance_state_or_sequence
- repeated_acknowledge_seals_the_audit_chain_once

### R8. Stale generation and stale sequence

Equal or lower sequence numbers refuse (`replayed_and_reordered_sequences_are_refused`
exists). A sequence cannot wrap. An acknowledgement of an earlier or later
result revision than the retained terminal revision refuses. After owner loss
there is no stale-generation recovery: the operation stays quarantined.

Planned witnesses:
- sequence_at_u64_max_is_refused_not_wrapped
- early_and_stale_result_acknowledgement_over_the_receiver_are_refused
- new_owner_incarnation_cannot_observe_or_clear_a_prior_quarantine

### R9. Owner death is quarantine, never recovery

If the original owner dies, the operation and its resources are quarantined.
Nothing in this contract clears that, re-admits the operation, rebuilds custody,
or treats a missing endpoint as proof the VM stopped. Volume reuse, image
deletion, generation replacement and automatic restart all honor the record.

Existing: `owner_death_quarantines_and_nothing_clears_it`.

Planned witnesses:
- kill_owner_then_volume_reuse_and_restart_are_refused (HVF)
- crash_between_quarantine_write_and_vmm_birth_stays_quarantined
- torn_or_partial_retirement_keeps_reuse_refused

### R10. Eventual authenticated completion and cleanup

Terminal success needs all three halves, as the entrypoint-owner contract
defines them: the same-session completion and storage barrier,
original-generation authenticated finalization with lifetime exit, and the
required cleanup and audit outcome. Until then the operation is recovery
required and no result revision exists. Cleanup and audit run once, in the
owner, independent of whether the result was delivered. Only the original live
owner retires its generation's quarantine, after the compound proof and a
durably committed retirement.

Existing: `each_missing_half_of_the_terminal_proof_stays_recoverable`,
`recovery_required_completes_only_with_all_three_halves`.

Planned witnesses:
- cli_exit_then_reconnect_observes_terminal_result_after_cleanup (HVF)
- result_delivered_but_cleanup_failed_is_not_terminal
- acknowledge_does_not_retire_quarantine
- retirement_is_durable_before_reuse_is_allowed

### R11. Typed client surface only

The client library exposes observe, cancel-stop and acknowledge-result over the
bounded unauthenticated request representation already in the tree, plus the
possession proof. Responses carry sanitized observations. They never carry
`NativeCompletion`, `ConfirmedExit`, an admission, or a cleanup capability.
There is no verb that takes an executable, argument vector, shell string,
descriptor, process identifier or key. CLI and Studio use the same service.

Planned witnesses:
- the_client_surface_enumerates_exactly_three_recovery_verbs
- responses_cannot_be_converted_into_completion_or_cleanup_capabilities
- cli_and_studio_reach_the_receiver_through_one_client_service
- no_recovery_request_field_accepts_a_path_pid_or_command

## Not covered here

Key-holder operations for admission, audit and adoption; native resource
enforcement; the locally built frozen-input route; and snapshot capture
exclusion keep their own owners, listed in the entrypoint-owner contract. This
file grants no VM execution, credential, signing or publication authority.
