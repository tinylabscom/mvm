# Cleanup preservation ledger (umbrella #4839)

Backing: preview
Validation: none — this records evidence gathered on one commit; it is not a claim of enforcement.

This ledger records, for the preserve and disposition boxes of the cleanup
umbrella (#4839), what evidence exists on `main` and what does not. It owns no
status: the issues do. A verdict here is a statement about evidence, not a
decision to close anything.

- **MET**: a command I ran against the commit below, or a stated disposition
  with a tracked issue, fully covers the box's wording.
- **PARTIAL (what remains)**: the invariant holds in what was run, but the box
  asks for more than was run or more than a gate can show.
- **BLOCKED (who)**: needs a live VM, signing, publication, another repository,
  or a maintainer decision.

Evidence commit: `d95c9a4303` (origin/main when this was written). Date:
2026-10-31. Every gate below was run as
`cargo run -q -p xtask -- <gate>` from a worktree at that commit.

## Gate results

| Gate | Result |
|---|---|
| `check-claim-catalog` | clean (21 claims, 153 witnesses verified) |
| `check-adr-coverage` | 58 ADRs, 54 referenced, 0 broken refs; warns ADR-057 has 0 in-code references |
| `check-witness-citations` | clean (329 citations resolved) |
| `check-asserted-absence` | clean (13 names still absent across 4 regions) |
| `check-single-network-path` | clean: one endpoint implementation, one NetworkFlow channel per backend, no retired L3/NIC path |
| `check-no-cli-shellout` | clean: no SDK source spawns a process or resolves the CLI |
| `check-no-vz` | clean |
| `check-sdk-transport-free` | clean |
| `check-core-runtime-free` | clean |
| `check-no-spec-refs-in-comments` | clean |
| `check-claim-witness-freshness` | clean, but it reasons only about workflow definitions: "external run history reserved for scheduled reporting", and ci.yml/release.yml carry no schedule it can use |
| `check-stream-redaction-seam` | clean |
| `check-telemetry-inventory` | exit 0 but prints "30 runtime gaps ... runtime coverage is NOT certified" |
| `check-no-network-literals` | clean |
| `check-image-lock` | clean (pinned to image-set/v0.2.4) |
| `check-no-host-nix` | clean |
| `check-guest-images-no-builder-tools` | clean (mk-guest.nix bakes no mvmctl, mvm-builderd) |
| `check-dormant-controls` | clean (15 live, 2 declared dormant: `default_sdk_uses_sidecar`, `apply_install_gate`) |
| `check-no-overclaim` | clean |
| `check-honesty` | clean |
| `check-no-guest-tool-client` | clean |
| `check-spec-hygiene` | clean |
| `check-doc-claims` | clean |
| `check-conformance` | docs/CONFORMANCE.md equals the model (25 claims) |
| `check-image-reproducibility` | clean (0 mkfs, 0 veritysetup, 0 cpio) |

Targeted tests (one nextest invocation over `mvm-contract`, `mvm-gpu`,
`mvm-core`, filtered to the names cited below):

`cargo nextest run -p mvm-contract -p mvm-gpu -p mvm-core -E 'test(/.../)'`: 81 tests run, 81 passed. Every test name this ledger cites from those crates ran and passed (the one revocation name that did not match the filter is not cited).

Tests named from `mvm-cli`, `mvm-agentd`, `mvm-hostd`, `mvm-runtime` and `mvm-backends`
are named where they matter but were **not run** for this ledger (workspace
build too heavy on the shared host); a name there is a pointer, not evidence.

Issue states below were read with `gh issue view` on 2026-10-31.

## Accepted contracts and roadmap dispositions (ADR review)

### Tracing/stream completeness

Box: reconcile closed #3419 and merged PR#4379 with open #3422-3426 and #4184;
preserve producer coverage, bounded queues/export storage, detached lifetime,
cancellation, stopped-reader/full-queue behavior, explicit loss/gaps and
synthetic-secret non-disclosure; mandatory signed audit stays separate.

Evidence: #3419 CLOSED, PR#4379 MERGED; #3422, #3423, #3424, #3425, #3426 and
#4184 all OPEN (W3-W7 plus confidentiality policy). `check-stream-redaction-seam`
clean. `check-telemetry-inventory` states runtime coverage is not certified (30
runtime gaps). Witness names present, not run here:
`a_full_queue_drops_the_span_and_counts_it_without_blocking`
(mvm-cli otlp export), `a_full_queue_sheds_output_with_counted_loss_instead_of_waiting`
and `stopped_reader_consumer_bounds_bytes_and_counts_every_loss` (mvm-agentd).

Verdict: **PARTIAL**. Remaining: the open W3-W7 issues own completeness; the
telemetry inventory gaps are the honest measure; the named tests need a run.

### Current security witnesses

Box: retain no-SSH guest posture and check scheduled witness freshness (#4788);
keep #2101/#4612/#4819 visible; do not promote ADR-026's stronger claim.

Evidence: #4788 OPEN ("Claim-bearing CI lane has stopped running"); #2101, #4612
and #4819 OPEN. `check-claim-witness-freshness` clean but cannot see run
history, so it does not establish freshness. ADR-026 status line reads
"Proposed", and the claim-1/2 rows in ADR-001 are unchanged (`check-claim-catalog`
clean). No-SSH is enforced at the network layer by
`ssh_flow_is_refused_even_when_listed` (mvm-vmm egress gate) and
`mandatory_deny_iptables_script_drops_ssh_port` (mvm-core).

Verdict: **BLOCKED (#4788 owner)**. Freshness of the scheduled witness cannot be
asserted while #4788 is open. The no-promotion half is MET.

### Protocol and readiness (ADR-019)

Evidence: ADR-019 Accepted. Negotiation witnesses in `mvm-contract`
(`capability_negotiation`, including `share_grant_on_wasm_is_refused_at_negotiation_naming_fuel`)
and `resource_usage_is_capability_negotiated_and_unary` (mvm-agentd, not run).
#4414, #4415, #4416 and #4809 OPEN.

Verdict: **PARTIAL**. Remaining: readiness-versus-process-running, typed
backpressure and cancellation have no single cited witness; owners are the open
issues.

### Mailbox operational contract (ADR-057)

Evidence: ADR-057 Accepted. `check-adr-coverage` warns ADR-057 has **0 in-code
references**. The implementation program #4622 and #4628-4631, #4633, #4635 are
all OPEN. `binding_verification_rejects_tamper_identity_epoch_policy_time_and_assurance`
exists in `mvm-core` mailbox transport tests.

Verdict: **PARTIAL**. The contract is preserved by being unimplemented and
unpromoted (no security-claim row cites it). Admission, durability, dedup and
fencing behavior cannot be evidenced until #4628-4631 land.

### Evidence completeness (ADR-110)

Evidence: ADR-110 Accepted, 5 in-code references. Inclusion proofs:
`build_inclusion_proof` / `verify_inclusion` in `mvm-contract::merkle` with
`inclusion_proof_serde_round_trip` and `inclusion_proof_rejects_unknown_field`;
`check_inclusion` in `mvm-hostd` receipt archive verification;
`completeness_serializes_as_a_word_not_a_bool` in `mvm-core::receipt_archive`.
#4415 and #4416 OPEN.

Verdict: **PARTIAL**. Exactly-once accounting and the attested-versus-derivable
distinction are not covered by a single named witness here; receipt parity is
owned by #4415/#4416.

### Owner-mediated application access (ADR-056 / #4460)

Evidence: ADR-056 states "Accepted by the owner on 2026-10-20".
`specs/contracts/owner-mediated-application-access.md` exists. #4460 is still
OPEN and still titled "Design owner-mediated application access", which is the
stale tracker wording the box names. Sealed-console refusal:
`console_refused_on_sealed_image` (claim 15 row, `check-claim-catalog` clean).

Verdict: **BLOCKED (maintainer: retitle or close #4460 against the accepted ADR
and contract)**. I did not edit the issue.

### GPU remoting (ADR-053 / #3560)

Evidence: ADR-053 Accepted 2026-09-20. PR#4727 MERGED. #3560 OPEN. Refusal
witnesses in `mvm-gpu`: `forged_streams_and_events_are_refused_without_queueing_work`,
`an_oversized_frame_prefix_is_refused_without_a_huge_allocation`,
`a_launch_past_the_param_cap_is_refused_without_touching_the_backend`.
`check-single-network-path` clean (vsock only).

Verdict: **PARTIAL**. Native-hardware, fork and device-memory witnesses are
absent by design and remain open under #3560.

### Capture, authoring, function entrypoints (ADR-050 / ADR-005)

Evidence: ADR-050 "Accepted - initial slice implemented"; ADR-005 Accepted.
#4230 OPEN. No issue was found that owns removing the deliberately retained
singular-entrypoint/string-environment compatibility.

Verdict: **BLOCKED (maintainer: open or name the owning follow-up issue)**.

### Browser/WASM capability tiers (ADR-024 / ADR-049)

Evidence: ADR-024 Accepted (claim-free portability tier); ADR-049 Accepted
(preview). #4222, #4224, #4226, #4228 OPEN. WASM refusal and bounds witnesses:
`a_fuel_only_grant_is_refused` and `an_unbounded_wall_clock_does_not_satisfy_a_fuel_grant`
(mvm-runtime wasm_backend, not run), `share_grant_on_wasm_is_refused_at_negotiation_naming_fuel`.

Verdict: **PARTIAL**. Deferral of WebLinux/local-builder is carried by the four
open issues; no WASM-as-isolation claim exists in the claims table.

### Future Windows direction

Evidence: ADR-009 Accepted; its Status text says the permanent Windows exclusion
is superseded by the future libkrun/WHP direction in #3553 and "does not promote
Windows to a supported or witnessed execution tier". #3553 OPEN.

Verdict: **PARTIAL**. The documentation correction is on `main`. Qualified boot,
private-state ACL, signing, doctor/refusal and capability evidence are future.

### Staged-state contradictions

Evidence: ADR-028 "Accepted - staged"; #4577 OPEN. ADR-046 is Proposed while
ADR-035 is Accepted for the output half, so the proposal does not displace the
stream plane. #4794 OPEN. The README says "no Docker, no host Nix, no Homebrew
packages" while macOS 13-25 is a libkrun preview whose boot witness #4577 still
owes. `check-doc-claims` clean.

Verdict: **PARTIAL**. Remaining: README versus ADR-028/#4577 wording on macOS
13-25; #4794 proposal versus prepared-launch semantics.

## Protected core goals

### Tracing/telemetry-affecting deletions retain fire-and-forget behavior

Evidence: `check-stream-redaction-seam`, `check-no-spec-refs-in-comments` clean;
`check-telemetry-inventory` not certified (see above). This is a per-change
review duty with no whole-tree gate.

Verdict: **PARTIAL**. Remaining: review each telemetry-touching diff; close the
inventory's 30 gaps.

### Cold/warm startup evidence (<300 ms / <50 ms)

Evidence: none produced. Needs a native HVF (and per-backend) measurement of
invocation-to-ready; #4391 is OPEN.

Verdict: **BLOCKED (operator with native hardware; #4391)**.

### Backend/feature combinations including WASM

Evidence: `check-no-vz` and `check-single-network-path` clean; WASM witnesses named above. No per-platform or
feature-matrix run was done. WHP is future (ADR-009, #3553), not claimed.

Verdict: **PARTIAL**. Remaining: `just check::gated` and a native-platform
witness per backend.

### Authenticated vsock and host-held secret custody

Evidence: `check-single-network-path` clean (no guest NIC, one NetworkFlow
channel, one workload socket owner); `check-sdk-transport-free` clean;
`check-no-network-literals` clean. Negative tests, not run here:
`handed_placeholders_never_contain_the_secret_value`
(`crates/mvm-hostd/tests/egress_secret_leak_gate.rs`),
`start_workload_puts_no_secret_environment_on_the_kernel_cmdline` (mvm-runtime),
`relay_config_disables_the_guest_nic` (libkrun driver), `qemu_has_no_guest_nic`,
`ssh_flow_is_refused_even_when_listed`.

Verdict: **PARTIAL**. Structural gates are clean; the negative tests need a run
on the affected paths.

## Security posture and installation

### Map shipped claims to enforcement and witnesses

Evidence: the ADR-001 claims table is the ledger; `check-claim-catalog` clean
(21 claims, 153 witnesses resolve), `check-witness-citations` clean (329),
`check-conformance` clean (25 claims), `check-no-overclaim` clean. Preview
claims 16-18 are labelled `Preview` in that table and in `CLAUDE.md`. Two
controls are declared dormant (`default_sdk_uses_sidecar`, `apply_install_gate`),
which `check-dormant-controls` pins.

Verdict: **PARTIAL**. The map exists and is gated. The gate proves a witness
exists, not that it is meaningful, and two controls are dormant by declaration.

### Relocatable installation and no-host-Nix/no-Docker

Evidence: `check-no-host-nix` clean; `check-guest-images-no-builder-tools`
clean; README Install section separates the release binary from the source
build. `tests/install_sh.rs` and `tests/smoke_fresh_install.rs` exist but were
not run; prepared/cache-only launch is owned by #4794 (OPEN).

Verdict: **PARTIAL**. Remaining: run the install tests; a relocation witness
on an installed release is a live-host check.

## Image and application trust

### Linux-only image producer boundary

Evidence (mvm side): `linux_only_schema_refuses_retired_runtime_source_fingerprints_including_null`
and `linux_only_schema_refuses_every_retired_guest_runtime_role` (mvm-core
image_set tests), `check-guest-images-no-builder-tools` clean,
`check-image-lock` clean. The producer side lives in mvm-images; #49 ("Build only
the Linux layer: drop the mvm input") is OPEN.

Verdict: **BLOCKED (mvm-images#49)**. The consumer half is gated; the producer
boundary cannot be verified from this repository.

### Staged image migration and release order

Evidence: #4100 CLOSED; mvm-images#49 and #64 OPEN; #4764 ("Release lane is red")
OPEN. No same-version signed CLI/runtime and installed-product boot evidence
exists for the new order.

Verdict: **BLOCKED (release owner #4764; mvm-images#49/#64; publication)**.

### Image-set identity distinct from application identity

Evidence: `held_application_rechecks_archive_and_independent_key_without_enrollment`
(mvm-core), `a_set_for_another_architecture_is_refused`,
`a_set_mixing_architectures_is_refused`, `a_set_without_a_base_image_contract_is_checked_as_the_legacy_contract`.

Verdict: **PARTIAL**. Remaining: the box also asks that helpers be consolidated
only where semantics match, which is a code review, not a gate.

### One pack catalog; descriptor naming a key does not enroll it

Evidence: `a_signed_image_descriptor_names_only_declared_in_pack_source_files`,
`a_catalogued_application_installs_atomically_and_resolves_for_launch`,
`bundle_origin_is_release_verified_only_for_enrolled_keys`. The generated
catalog and its exact-byte hashes live in mvm-packs, which was not inspected.

Verdict: **PARTIAL**. Remaining: mvm-packs catalog generation and exact-byte
hash checks.

### Separate image and pack revocation authority

Evidence: separate modules `image_set_revocation` and `pack_revocation` in
mvm-core. Run and passed: `an_applied_list_goes_stale_at_load`,
`an_old_unexpired_list_cannot_undo_an_applied_image_set_revocation`, and
`the_authority_is_disjoint_from_every_other_compiled_identity` (mvm-core
release_trust, the image-set revocation signer identity). Not examined: whether
any path deletes historical signed artifacts.

Verdict: **PARTIAL**. Remaining: a pack-revocation signer-identity test and a
no-deletion-of-historical-artifacts check were not run.

### Atomic immutable publication and reproducibility

Evidence: `check-image-reproducibility` clean (local); no published artifact
exists to admit and boot. The box itself says local checks are not a substitute.

Verdict: **BLOCKED (publication authority; mvm-images release)**.
