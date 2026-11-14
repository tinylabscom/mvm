# Claims ledger: witness adequacy matrix (umbrella #4839)

Backing: preview
Validation: none — this records what each cited witness does as read on one commit; it promotes, upgrades and weakens no claim.

Measured at `615eb5e150778ee82478034a230c229a59cba04c` (origin/main, 2026-11-12). CI freshness
was read with `gh run list` / `gh run view` the same day. The issue owns status;
ADR-001's claims table is the ledger and wins wherever this file disagrees.
Preview rows 16-18 are listed separately and are not promoted.

Scope: the #4839 box "Map the current shipped claims in MVM README/ADR-001 to
retained enforcement and meaningful witnesses". The ledger rows use the witness
tokens `fn:` and `ci:` that `xtask check-claim-catalog` parses, and that gate only
proves a named symbol or lane string exists. This matrix adds what the gate
cannot see: what each witness actually asserts.

## 1. Method and vocabulary

Every `fn:` witness was resolved with a single `git grep 'fn <name>'` over
`crates/`, `xtask/`, `tests/` and `src/`; all 154 distinct names resolve (none missing). Test bodies
were read for the entries called out below; entries marked `(by location)` were
classified from the file, the test attribute and the name, not read line by
line, and should be re-read before anyone relies on the classification.

| Class | Meaning |
|---|---|
| OUTCOME-REAL | Exercises the real mechanism (kernel syscall, real binary, real signed bytes) and asserts the security outcome. |
| OUTCOME-UNIT | Calls the production function in-process over synthetic inputs (tempdir, test keys, mock backend) and asserts the refusal or result. Real code path, not a real VM. |
| STRUCT | Asserts a constant, a parse result or a data shape, not a behaviour. |
| TEXT | Scans source or script text. Passes when the string is present, regardless of behaviour. |
| IMPL | The cited symbol is production code, not a test. It proves existence only. |
| GATED | `#[ignore]`d, Linux-only, or skips silently without a host tool; does not run in the default `cargo nextest run --workspace`. |
| CI | A workflow lane; freshness is stated. |

## 2. Cross-cutting findings

1. **`fn:` witnesses that are not tests.** `acquire_from` (6), `synthesize_plan`,
   `admit_for_run`, `verify_audit_chain` (8), `read_and_verify_bundle`,
   `verify_plan_bundle` (9), `assert_vsock_only_device_model` (10),
   `verify_sealed_volume`, `apply_install_gate` (11), `substitute_bound_credential`
   (13), `inventory_rootfs`, `scan_inventory`, `apply_base_image_gate` (21) are
   production functions. `check-claim-catalog` is satisfied by them; no test is
   implied. Deleting or renaming one of those would trip the gate, which is the
   only job they do.
2. **TEXT witnesses.** `fresh_install_trust_precedes_verifier_execution`,
   `fresh_install_requires_tag_pinned_bundle`, `fresh_install_has_no_unsigned_fallback`
   (claim 20, `crates/mvm-conformance/tests/steps/installer.rs`) read the text of
   `install.sh` and check that substrings are present and ordered. They do not
   run the installer. `the_rootfs_is_always_mounted_read_only` and
   `the_workload_identity_is_never_root` (claim 2) assert constants, and the
   sibling `every_rootfs_mount_call_site_uses_the_read_only_flags` (not cited) is
   an `include_str!` scan of `guest_mount.rs`.
3. **`ci:single-network-path` (claim 10) matches a step name.** The only
   occurrence in `.github/workflows` is the step title
   `Policy gates (check-abi-layout) (single-network-path)` in `ci.yml`, which runs
   `cargo run -p xtask -- check-all`. The real gate is `xtask check-single-network-path`
   (itself a source scan); the lane string would survive the gate being dropped
   from `check-all`. The step is path-scoped (a sibling no-op step keys off the
   `architecture` scope output), so it does not run on every PR.
4. **GATED witnesses cited as if routine.** `seccomp_allows_listed_denies_unlisted`
   (claim 1) is `#[ignore]` and runs only in two lanes with `--ignored` /
   `--include-ignored` (`security.yml` jailer property job, `ci-main.yml`
   `test-musl-confinement`); it tests the host jailer's filter, not the guest
   workload tier. The three claim-18 live witnesses
   (`a_granted_cpu_share_binds_a_real_spawn_to_its_quota`,
   `a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded`,
   `a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited`) are `#[ignore]`
   and need a Linux host with a systemd user session. `seal_detects_post_format_rootfs_tamper`
   (claim 3) returns early, passing, when `veritysetup` or `mke2fs` is absent.
   `drops_identity_groups_capabilities_and_enables_no_new_privs` (claim 2) runs
   only as root and skips otherwise (the ledger says so).
5. **Last-run freshness is weaker than the cadence suggests.** The scheduled
   Security run of 2026-11-12 04:20Z (`43154164922`) **failed**: the
   `cargo-deny` and `cargo-audit` jobs. Scheduled runs on 2026-11-10 and
   2026-11-11 succeeded. Manual dispatches on `main` through 2026-11-13 01:26Z
   succeeded (`43344932988`), which is the evidence for the lane rows below; a
   dispatch is not the nightly cadence. `claim-witness-freshness.yml` exists to
   detect a lane that stops running; this document does not re-implement it.
6. **Several claims are witnessed by one layer.** Claim 8's chain tests, claim 9's
   bundle tests and claim 20's refusal tests are strong at the function boundary.
   None of the shipped rows has an end-to-end witness that boots a real backend
   under the claim's failing condition and shows the refusal, except where the
   row below says so.

## 3. Shipped claims (1-15, 19, 20, 21)

Enforcement locations are the files the witnesses and ADR-001 point at, checked
to exist at the measured commit. "Adequacy" is a judgement of what the witness set
proves about the claim as worded; it is not a recommendation to change a claim.

### Claim 1 — no host-fs access beyond explicit shares / seccomp tier

Enforcement: `crates/mvm-agentd/src/bin/mvm-seccomp-apply.rs` and the agent's
activation path (tier installed per workload process); tier selection in
`crates/mvm-core/src/plan/synthesis.rs`; warm-claim tier check in
`crates/mvm-runtime/src/workload_runner/runner/refusal.rs`; mount allow-list in
`crates/mvm-core/src/crypto/policy/mount.rs` and
`crates/mvm-cli/src/commands/shared/parse.rs`; share re-verification in
`crates/mvm-hostd/src/plan_admission.rs`; libkrun refusal in
`crates/mvm-backends/src/driver/libkrun.rs`.

| Witness | Where | Class |
|---|---|---|
| `an_exec_under_the_admitted_standard_tier_cannot_open_a_socket`, `a_started_process_under_the_admitted_standard_tier_cannot_open_a_socket`, `an_exec_child_reports_a_seccomp_filter_and_no_new_privs`, `a_warm_claimed_child_under_standard_cannot_open_a_socket`, `a_warm_claimed_childs_workload_reports_a_seccomp_filter`, `vsock_tier_allows_an_af_vsock_socket_and_denies_af_inet`, `standard_tier_denies_an_af_vsock_socket_with_eperm` | `crates/mvm-agentd/tests/seccomp_apply.rs` (`#![cfg(target_os = "linux")]`) | OUTCOME-REAL: a probe process under the real filter gets `EPERM` from the real kernel. Linux only; skipped at compile time on macOS. |
| `ci:seccomp-functional` | `security.yml`, job "Seccomp tier functional denial", runs `cargo test -p mvm-agentd --test seccomp_apply` | CI. Last green: `43344932988` (manual dispatch on main, 2026-11-13). |
| `seccomp_allows_listed_denies_unlisted` | `crates/mvm-hostd/tests/seccomp_property.rs` | GATED; tests the host jailer filter, not the guest tier. |
| `a_child_must_report_holding_the_admitted_seccomp_tier` | `crates/mvm-runtime/src/workload_runner/runner/refusal.rs` | OUTCOME-UNIT (by location). |
| `admitted_seccomp_tier_grants_sockets_only_to_a_launch_that_needs_them`, `a_gpu_grant_admits_the_vsock_tier_and_no_wider` | `crates/mvm-core/src/plan/synthesis.rs` | OUTCOME-UNIT: tier chosen by plan synthesis. Proves the tier is selected, not that a guest enforces it. |
| `validated_conversion_enforces_mount_allow_list`, `dir_share_two_part_defaults_ro` | `crates/mvm-cli/src/commands/shared/parse.rs` | OUTCOME-UNIT (by location): CLI parse-time allow-list. |
| `bare_mnt_is_refused_because_it_shadows_the_config_drive` | `crates/mvm-core/src/crypto/policy/mount.rs` | OUTCOME-UNIT. |
| `libkrun_refuses_any_virtio_fs_share_before_mapping` | `crates/mvm-backends/src/driver/libkrun.rs` | OUTCOME-UNIT (by location): driver config refusal, no VM. |
| `enforce_admitted_shares_refuses_unadmitted_or_mismatched` | `crates/mvm-hostd/src/plan_admission.rs` | OUTCOME-UNIT over temp directories. |

Limits carried through (ADR-001 row and `CLAUDE.md`): a cold boot whose guest
agent is older than the `mvm.seccomp=<tier>` token runs workloads **unfiltered**,
including the agent in the pinned image set a release binary boots until it
assembles its own guest runtime; a warm claim whose child agent predates the
handshake field is refused rather than run unfiltered; a warm-process worker
pool started in the standby parent ran unfiltered; a VM restored from a template
snapshot keeps the tier its captured VM admitted.
Adequacy: the tier mechanism is well witnessed on Linux. No witness covers the
claim's headline ("no host-fs access beyond explicit shares") by attempting a
host-fs escape in a booted guest on any backend; the share witnesses are
admission-side. The old-agent cold-boot gap has no witness because it is a
known non-enforcement.

### Claim 2 — no guest binary can elevate to uid 0

Enforcement: `crates/mvm-setpriv/src/lib.rs`, `crates/mvm-agentd/src/workload_identity.rs`,
`crates/mvm-agentd/src/guest_mount.rs` (read-only rootfs flags).

| Witness | Where | Class |
|---|---|---|
| `drops_identity_groups_capabilities_and_enables_no_new_privs` | `crates/mvm-setpriv/tests/mvm_setpriv.rs` | OUTCOME-REAL but GATED: needs root, skips otherwise. |
| `rejects_a_drop_without_no_new_privs` | `crates/mvm-setpriv/src/lib.rs` | OUTCOME-UNIT. |
| `set_no_new_privs_actually_sets_the_kernel_bit` | `crates/mvm-agentd/src/bin/mvm-seccomp-apply.rs` | OUTCOME-REAL (Linux, by location). |
| `never_writes_a_uid_zero_entry` | `crates/mvm-agentd/src/workload_identity.rs` | OUTCOME-UNIT: provisioner over a temp root; appended lines contain no uid 0. |
| `the_rootfs_is_always_mounted_read_only` | `guest_mount.rs` | STRUCT: asserts the flag constant. |
| `the_workload_identity_is_never_root` | `guest_mount.rs` | STRUCT: asserts `WORKLOAD_UID != 0`. |

Adequacy: partial. The read-only mount and non-root uid are constant assertions;
the verity-sealed read-only property is claim 3's, which has its own gap. No
witness runs a setuid or capability-acquiring binary in a booted guest and shows
it stays non-root.

### Claim 3 — a tampered rootfs ext4 fails to boot

Enforcement: verity construction `crates/mvm-fs/src/ext4/verity.rs`; sealing
`crates/mvm-build` (`oci_verity_sealing`); roothash delivered in
`ActivateEnvironment` and checked by the initramfs agent (ADR-018; the check
itself is not located by this document); snapshot envelope in
`crates/mvm-runtime/src/vm/instance_snapshot.rs`.

| Witness | Where | Class |
|---|---|---|
| `a_single_flipped_byte_in_any_block_no_longer_matches_the_recorded_root` | `crates/mvm-fs/src/ext4/verity.rs` | OUTCOME-UNIT: the pure-Rust hash tree changes root when a byte flips. Proves detectability, not a boot refusal. |
| `seal_detects_post_format_rootfs_tamper` | `crates/mvm-build/tests/oci_verity_sealing.rs` | GATED: skips (passes) without `veritysetup`/`mke2fs`; when it runs, a userspace `veritysetup verify` rejects. |
| `verify_and_resume_rejects_tampered_mem` | `instance_snapshot.rs` | OUTCOME-UNIT: snapshot **memory** HMAC refused before resume. This is the snapshot envelope, not the rootfs. |
| `a_fresh_release_install_assembles_every_piece_from_its_own_archive` | `crates/mvm-build/src/runtime_pieces.rs` | OUTCOME-UNIT over a fixture archive; proves overlay assembly provenance, not tamper refusal. |
| `ci:verified-boot-artifacts` | `security.yml` job "Verified boot artifacts" | CI: builds the overlay with `mvmctl dev runtime-overlay build`, flips a byte, and checks `veritysetup verify` fails (host-side userspace verify). Last green `43344932988`. |

Limits carried through: **no CI lane boots a tampered rootfs under KVM**
(`CLAUDE.md`, "Security model" item 3). A virtiofs root does not witness the
claim (ADR-001 "Claim 3 backend scoping"). Adequacy: the claim text "fails to
boot" is not witnessed as stated. What is witnessed is that the hash changes and
that `veritysetup verify` on the host rejects a tampered overlay. The kernel and
initramfs refusal path has no automated witness in this table.
Proposal (not implemented): a Linux/KVM lane that boots a Firecracker guest on a
rootfs with one flipped byte and asserts the guest never reaches the agent
handshake. The live KVM evidence contracts already in this directory show the
box exists; whether a flipped-byte boot is feasible there is unmeasured.

### Claim 4 — production-safe run cannot invoke DevOnly guest-agent verbs

Enforcement: `crates/mvm-agentd/src/vsock/verb_grant.rs`.

| Witness | Where | Class |
|---|---|---|
| `prod_safe_grant_refuses_all_dev_only_requests` | `verb_grant.rs` | OUTCOME-UNIT: builds a signed `VerbGrant` over every prod-safe verb and asserts every DevOnly request is refused. |
| `ci:guest-agent-runtime-boundary` | `security.yml`, runs `scripts/check-prod-agent-no-exec.sh` = `cargo test -p mvm-agentd --lib --all-targets` plus `run_detached` | CI: a wide unit-suite lane, not a boot of the shipped agent. Last green `43344932988`. |

Adequacy: good at the request-policy boundary; no witness sends a DevOnly verb
to a real sealed guest agent over vsock. The lane name suggests more than it
runs.

### Claim 5 — vsock framing, supervisor-config JSON, FlowMux decode/state fuzzed

Enforcement: `crates/mvm-agentd/fuzz/`, `crates/deps/libkrun-sys/fuzz/`, the
fuzz directories under the FlowMux and input-frame crates.

Witnesses: `ci:fuzz_guest_request`, `ci:fuzz_sealed_frame`,
`ci:fuzz_supervisor_config`, `ci:fuzz_network_flow_decode`,
`ci:fuzz_network_flow_state`, `ci:fuzz_input_frame`. Class: CI. Each is a named
step in the "Fuzz — parsers" job of `security.yml` running `cargo fuzz run <target>
-- -max_total_time=$DURATION`. Last green: `43344932988`. The lane string is
a step name; the job passes if no target crashes within the duration. A fuzz
step proves no panic found in that budget, nothing more, and the corpus size is
not asserted by any gate.
Adequacy: appropriate for the wording ("are fuzzed"). It does not witness
correctness of decode, only absence of crashes under the budget.

### Claim 6 — pre-built dev image is hash-verified

Enforcement: `crates/mvm-build/src/published_image_set.rs` (`acquire_from`).

| Witness | Where | Class |
|---|---|---|
| `acquire_from` | `published_image_set.rs:206` | IMPL. |
| `a_member_whose_bytes_differ_from_the_root_is_refused_and_removed` | `published_image_set/tests.rs` | OUTCOME-UNIT over fixture set. |
| `the_hash_skip_hatch_does_not_admit_a_member_the_root_does_not_describe` | same | OUTCOME-UNIT. |
| `ci:hash-verify-tests` | `security.yml` job "Hash-verify regression" | CI; last green `43344932988`. |

Adequacy: good for the member-digest contract. The signature on the root is
claim 20's.

### Claim 7 — cargo deps audited nightly and on release tags

Enforcement: `deny.toml`, `security.yml` jobs.

Witnesses: `ci:cargo-deny`, `ci:cargo-audit`, `ci:reproducibility` (all CI). The
lane strings are job keys in `security.yml`; `reproducibility` also appears in
`ci-main.yml` and `release.yml`. **Freshness: the 2026-11-12 04:20Z scheduled
run failed in exactly `cargo-deny` and `cargo-audit`**; the dispatch runs after
it were green. The claim wording is "audited", which a red advisory run
satisfies (the audit ran and reported), but a reader of the ledger should not
infer a currently clean dependency set. There is no `pull_request` trigger.

### Claim 8 — every workload runs from a signed, audited ExecutionPlan

Enforcement: synthesis `crates/mvm-core/src/plan/synthesis.rs`; admission and
replay `crates/mvm-hostd/src/plan_admission.rs`; chain
`crates/mvm-hostd/src/supervisor/audit_file.rs`; sessions
`crates/mvm-hostd/src/audit/session.rs`.

| Witness | Where | Class |
|---|---|---|
| `synthesize_plan`, `admit_for_run`, `verify_audit_chain` | synthesis.rs, plan_admission.rs, audit_file.rs | IMPL. |
| `a_tampered_payload_is_refused`, `an_unknown_signer_is_refused`, `a_not_yet_valid_plan_is_refused`, `a_replayed_nonce_is_refused`, `admission_refuses_before_signing`, `propagates_synthesis_failures` | `plan_admission.rs` tests | OUTCOME-UNIT: real verification code, test keys and a temp replay store. |
| `naively_dropping_old_entries_fails_verification_at_line_zero`, `a_spliced_segment_is_refused`, `a_missing_segment_is_named_not_silently_skipped`, `an_interrupted_rotation_continues_history_instead_of_restarting_it` | `crates/mvm-hostd/tests/audit_chain_rotation.rs` | OUTCOME-REAL at the file level: real files, real signatures, tamper by editing bytes. |
| `a_prune_record_that_over_claims_is_refused`, `the_same_deletion_without_a_record_is_still_refused`, `pruning_a_broken_chain_is_refused_before_anything_is_deleted` | `crates/mvm-hostd/tests/audit_chain_prune.rs` | same. |
| `a_correctly_signed_seal_that_lies_is_refused_field_by_field`, `truncating_through_the_seal_leaves_the_session_unsealed` | `crates/mvm-hostd/src/audit/session.rs` | OUTCOME-UNIT. |

Limits carried through (ADR-001): tail truncation of whole sessions, and of a
session that never sealed, is undetectable without an off-host witnessed root;
a pruned range verifies "with a corroborated gap", and only its upper boundary
is cross-checked. Adequacy: strongest-witnessed row in the ledger at the
chain/admission boundary. No witness drives a real `mvmctl machine run` on a
real backend and then verifies the resulting chain; the integration is by
composition. The host signing key is host-held (out of scope per ADR-001).

### Claim 9 — published bundles content-addressed and re-verified

Enforcement: `crates/mvm-core/src/plan/bundle.rs`; boot-time re-verification in
`crates/mvm-client/src/admission/`.

| Witness | Where | Class |
|---|---|---|
| `read_and_verify_bundle`, `verify_plan_bundle` | `bundle.rs:1103`, `:741` | IMPL. |
| `a_builtin_author_key_verifies_with_no_enrollment`, `a_revoked_builtin_key_is_refused` | `crates/mvm-core/src/registry_pack/application_bundle/tests/builtin_author.rs` | OUTCOME-UNIT. These test registry-pack author keys, which is adjacent to, not identical with, the `.mvmpkg` content-address check. |
| `an_installed_rootfs_changed_after_install_is_refused_at_admission`, `every_installed_artifact_is_checked_not_only_the_ones_the_plan_pins` | `crates/mvm-client/src/admission/bundle_admission_tests.rs` | OUTCOME-UNIT: the right tamper-after-install witnesses. |

Adequacy: the rejection ladder tests named in `CLAUDE.md` (unknown key,
tampered manifest, key_id mismatch, tampered artifact, unsafe path, schema bump)
live in `bundle.rs` tests but are not cited as witnesses; the ledger anchors on
two implementation symbols and four admission/author tests. A rename of those
tests would not trip the gate. Proposal: add the ladder tests to the ledger row.

### Claim 10 — no workload reaches the network unless admitted

Enforcement: egress gate `crates/mvm-vmm/src/vsock_egress_bridge/egress_gate.rs`;
flow admission `crates/mvm-hostd/src/supervisor/flowmux/open_flow.rs`; policy
`crates/mvm-contract/src/policy/{network_policy,dns_guard,restricted_address}.rs`;
snapshot NIC refusal `crates/mvm-vmm/src/snapshot.rs` and
`crates/mvm-runtime/src/vm/instance_snapshot.rs`; DNS audit
`crates/mvm-hostd/src/supervisor/dns_audit.rs`.

| Witness | Class |
|---|---|
| `a_flow_no_rule_admits_is_refused_and_audited_under_the_default_policy`, `open_tcp_to_unknown_host_is_refused_by_default_deny_gate` (open_flow.rs), `policy_default_is_deny_all` (network_policy.rs), `run_net_default_is_deny_all` (mvm-client admission), `private_link_local_loopback_ula_metadata_are_forbidden` (dns_guard.rs), `an_embedded_ipv4_form_is_classified_by_the_address_it_reaches` (restricted_address.rs), `private_range_is_denied_by_default_and_readmitted_only_by_a_grant_naming_it`, `metadata_and_the_absolute_ranges_are_never_readmitted`, `a_name_that_resolves_inward_is_refused_as_the_address_it_reached` (egress_gate.rs), `the_forward_leg_gets_the_gate_s_answer_not_a_fresh_lookup` (pinned_dns.rs) | OUTCOME-UNIT: decision functions over synthetic flows. The gate's decisions are checked; no guest-originated packet is. `policy_default_is_deny_all` is closer to STRUCT (asserts the default value). |
| `verify_and_resume_refuses_nic_on_restore`, `fork_restore_refuses_nic` | OUTCOME-UNIT: restore refuses a device model carrying a NIC. |
| `assert_vsock_only_device_model` | IMPL. |
| `emits_resolved_query_with_ip_list`, `admitted_projection_is_one_object_graph_for_every_network_surface` | OUTCOME-UNIT / STRUCT (the second compares projections, by location). |
| `ci:single-network-path` | CI-by-step-name; see section 2 item 3. The underlying `check-single-network-path` is a source scan. |
| `ci:fuzz_dns_codec` | CI fuzz; last green `43344932988`. |

Adequacy: the default-deny and SSRF-class decision logic is densely witnessed
at the function boundary. The structural claim "no NIC, one path" rests on a
source-scan gate and on the device-model assertions, not on a guest attempting
raw network access on each backend. `CLAUDE.md` itself records that the
unrestricted-policy warning and its escape hatch do not exist; no witness
covers them and none is cited.

### Claim 11 — app-dep volumes CVE-scanned/SBOM-enumerated, hash-locked

Enforcement: `crates/mvm-core/src/deps_audit.rs` (`verify_sealed_volume`);
seal gate `crates/mvm-build/src/app_deps_gate.rs`.

| Witness | Class |
|---|---|
| `verify_detects_tampered_content`, `verify_detects_tampered_cve`, `verify_detects_tampered_sbom` (deps_audit.rs) | OUTCOME-UNIT: byte-flip on a sealed fixture volume is refused. |
| `prod_rejects_high_cve_finding_pip_audit_shape`, `prod_rejects_stub_sbom_as_missing_sbom` (app_deps_gate.rs) | OUTCOME-UNIT; they witness the severity gate. |
| `verify_sealed_volume`, `apply_install_gate` | IMPL. |
| `ci:app-deps-audit` | CI (nightly and release tags only, not PRs); last green `43344932988`. |

Limit carried through: **the severity gate has no production launch caller and is
declared dormant** (ADR-001 row, `CLAUDE.md`). Two of the seven witnesses
therefore test a control that does not run at launch; only the sealed-byte
reverify does. The full builder-VM install round-trip is not in the lane.
Adequacy: the "hash-locked and reverified at admission" half is witnessed; the
"CVE-scanned when sealed" half is witnessed only in the seal-time test lane.

### Claim 12 — host-side service bindings are plan-gated and audited

Enforcement: `crates/mvm-hostd/src/broker/registry.rs`,
`crates/mvm-contract/src/protocol/broker.rs`.
Witnesses: `unbound_service_returns_not_bound`,
`a_policy_refusal_is_audited_without_the_argument_value` (registry.rs, OUTCOME-UNIT),
`service_call_rejects_unknown_envelope_fields` (broker.rs, OUTCOME-UNIT; a
`deny_unknown_fields` parse check, close to STRUCT).
Adequacy: adequate for dispatch refusal and audit payload-freedom; three
witnesses cover three behaviours. The earlier prose names four tests, a fuzz target
and three xtask gates that never existed; that correction is kept in `CLAUDE.md`
and enforced by `check-asserted-absence`.

### Claim 13 — substitution path hands the guest placeholders, never raw secrets

Enforcement: `crates/mvm-hostd/src/keyholder/substitution.rs`,
`crates/mvm-hostd/src/supervisor/network_endpoint*`.

| Witness | Where | Class |
|---|---|---|
| `handed_placeholders_never_contain_the_secret_value` | `crates/mvm-hostd/tests/egress_secret_leak_gate.rs` | OUTCOME-UNIT/integration (by location): minted environment inspected for the secret bytes. |
| `endpoint_bin_serves_substitution_and_refuses_unbound_destination` | `crates/mvm-hostd/tests/network_endpoint_bin.rs` | OUTCOME-REAL: spawns the real endpoint binary. Also run with `--include-ignored` in `ci-main.yml` `test-musl-confinement`. |
| `substitute_bound_credential` | `substitution.rs` | IMPL; the ledger calls it the "bound-credential control" for `check-dormant-controls`. |

Adequacy: sound for the host side. The claim "never enters the guest" is also
bounded by what a workload can do with a placeholder; that is not witnessed
here. Claim 17's secret scan covers only stdin, with its own limits.

### Claim 14 — OCI provenance recorded in the chain-signed audit log

Enforcement: `crates/mvm-hostd/src/audit/emitter.rs`
(`emit_oci_provenance`), `crates/mvm-cli/src/commands/image/pull_core.rs`.
Witnesses: `oci_provenance_event_is_chain_signed_with_required_labels`
(OUTCOME-UNIT), `prod_pull_requires_digest_pin_before_network`,
`prod_run_image_requires_digest_pin_before_network` (OUTCOME-UNIT, by location).
The ledger row cites no `ci:` witness; the `oci-hardening` matrix is nightly and
release-tag only and is not cited. Adequacy: event shape and the `--prod` digest
pin are witnessed; the cosign-verdict-before-admission requirement stated in
`CLAUDE.md` has no witness in the row.

### Claim 15 — sealed production microVM has no shell, DevOnly verbs, or PTY

Enforcement: `crates/mvm-cli/src/commands/vm/console.rs` (`enforce_accessible_gate`),
`crates/mvm-agentd/src/console.rs`, the console capture in
`crates/mvm-runtime`.

| Witness | Where | Class |
|---|---|---|
| `console_refused_on_sealed_image` | `console.rs:1450` | OUTCOME-UNIT: writes VM metadata with `accessible: false` and asserts the gate refuses. Host gate only. |
| `following_the_console_never_writes_to_it` | `crates/mvm-hostd/tests/workload_stream_plane.rs` | OUTCOME-REAL (file-level): a live follower must leave the capture file bytes unchanged. Plane-level test (by location). |
| `ci:guest-agent-runtime-boundary` | as claim 4 | CI. |

Adequacy: appropriate to the narrowed wording (input-less console, host gate).
The claim's "no shell in a sealed rootfs" is the static `check-no-ssh` /
no-authority lanes in `security.yml`, which are not cited here.

### Claim 19 — assets and pinned shares content-identified; drift fails closed

Enforcement: `crates/mvm-hostd/src/plan_admission.rs`
(`enforce_admitted_shares`), `crates/mvm-core/src/plan/synthesis.rs`,
`crates/mvm-contract/src/plan/types.rs`, `crates/mvm-hostd/src/audit/emitter.rs`.

| Witness | Class |
|---|---|
| `admitted_share_digest_refuses_directory_changed_after_admission` | OUTCOME-UNIT over a temp directory; the key witness. |
| `synthesized_plan_records_share_and_caller_asset_identities` | OUTCOME-UNIT. |
| `asset_identities_event_carries_kind_name_digest_labels` | OUTCOME-UNIT. |
| `asset_identity_rejects_malformed_digests` | STRUCT (type-boundary validation). |
| `test_audit_asset_id_parses` | STRUCT: a clap argument-parse test; says nothing about digest recomputation. Weak for the "offline digest recomputation" part of the row. |

Adequacy: good for share drift; mount-time enforcement on a booted backend is
not exercised. The claim is `Shipped` though numbered after the preview rows,
as `CLAUDE.md` notes.

### Claim 20 — release artifacts authenticated; refuse missing/invalid signature

Enforcement: `crates/mvm-build/src/release_signature.rs`,
`crates/mvm-build/src/published_image_set.rs`, `crates/mvm-cli/src/update.rs`,
`install.sh`, `crates/mvm-build/src/guest_bins/release.rs`, `release.yml`.

| Witness | Where | Class |
|---|---|---|
| `a_real_release_bundle_verifies_under_its_tag` | `crates/mvm-cli/src/update.rs` | OUTCOME-REAL: verifies a real v0.18.0-rc.1 Sigstore bundle checked into `crates/mvm-build/tests/fixtures/release-signature/`; strongest witness in the row. Requires `manifest-verify`. |
| `a_missing_bundle_refuses_and_names_the_asset`, `an_archive_without_a_bundle_is_refused`, `self_update_refuses_an_unsigned_checksum_manifest_before_parsing`, `self_update_refuses_a_checksum_manifest_signed_for_another_tag` | `release_signature.rs`, `update.rs` | OUTCOME-UNIT. |
| `acquire_refuses_a_root_without_a_signature`, `the_hash_skip_hatch_does_not_waive_the_root_signature` | `published_image_set/tests.rs` | OUTCOME-UNIT. |
| `an_unsigned_release_runtime_is_refused_and_nothing_is_cached`, `a_release_runtime_that_misses_its_digest_is_refused_before_its_signature` | `guest_bins/release.rs` | OUTCOME-UNIT. |
| `accepted_identities_are_the_versioned_release_workflow` | `release_signature.rs` | STRUCT: asserts the identity strings contain `release.yml` and end in the version tag. |
| `fresh_install_trust_precedes_verifier_execution`, `fresh_install_requires_tag_pinned_bundle`, `fresh_install_has_no_unsigned_fallback` | `crates/mvm-conformance/tests/steps/installer.rs` | TEXT: substring checks on `install.sh`; do not execute it. |
| `ci:verify-release`, `ci:release-provenance` | `release.yml` | CI: run only on tag/dispatch release runs. `verify-release` was **skipped** in the failed v0.28.0-rc.1 run (`43267400764`) and the v0.28.0-rc.2 release run (`43344965783`) was still queued when read. No completed green `verify-release` was observed in the six most recent release runs. |

Limits carried through (ADR-001 "Claim 20 boundaries"): a copy of the guest
runtime found beside `mvmctl` or in the cache is held to its own manifest, not
the signature; `MVM_SKIP_COSIGN_VERIFY` skips the signature at download time;
**no published release carries the guest-runtime asset yet**; the SLSA
provenance is Build L2. Adequacy: strong refusal coverage in Rust; the
installer half of the claim is witnessed only by text scans, though
`tests/install_sh.rs` (named in `CLAUDE.md`) is the behavioural test and is not cited.
Proposal (not implemented): replace the three TEXT witnesses with the
`tests/install_sh.rs` cases that execute the installer against a local archive
fixture, after confirming those cases cover the ordering and no-fallback
properties.

### Claim 21 — OCI base images inventoried, CVE-scanned against OSV, SBOM-enumerated; prod refuses missing scan

Enforcement: `crates/mvm-fs/src/os_inventory.rs`,
`crates/mvm-build/src/base_image_scan.rs`, `crates/mvm-build/src/base_image_gate.rs`,
`crates/mvm-cli/src/commands/image/pull_core.rs`.
Witnesses: `inventory_rootfs`, `scan_inventory`, `apply_base_image_gate` (IMPL);
`a_prod_run_refuses_a_base_image_with_no_scan`,
`a_prod_run_refuses_a_base_image_with_a_high_severity_finding` (OUTCOME-UNIT).
The two behaviour witnesses cover the gate refusals. Limits carried through
(ADR-001 row): the sidecars live in the host cache, so a host insider can forge a
clean one; severity is best-effort and `unknown` never refuses; rpm is an
unsupported gap; local ingest paths are dev-only. Nothing witnesses the
inventory parsers or the sidecar digest binding by name; the row's
"sidecar bound to another digest" refusal has no cited witness.

## 4. Preview rows (16-18), not promoted

| Row | Witness set (summary) | Read |
|---|---|---|
| 16 | `handed_placeholders_never_contain_the_secret_value`, `network_endpoint_refuses_unbound_destination`, `audit_chain_carries_no_secret_value` (all in `egress_secret_leak_gate.rs`), `substitution_is_audited_when_upstream_fails_after_send` (`terminator/flow.rs`) | OUTCOME-UNIT/real-binary integration (by location). Appropriately `Preview`. |
| 17 | 9 witnesses in `input_gate.rs`, `network_endpoint.rs`, `network_endpoint_spawn.rs`, `workload_input_plane.rs`, `mvm-client` admission | OUTCOME-UNIT with one plane-level integration (`a_secret_split_across_two_frames_does_not_reassemble_in_the_workload`). Its permanent limits (fingerprint match is not identity; encoding and window-straddling splits defeat the scan) are in ADR-001 and are not witnessed away. |
| 18 | 32 witnesses across `admission_budget.rs`, `plan_admission.rs`, `spawn_scope.rs`, `wall_clock.rs`, restored-child tests | Mostly OUTCOME-UNIT. Three live kernel-cgroup witnesses are GATED (`#[ignore]`, Linux + systemd). The Firecracker and HVF restored-child witnesses assert the **launch-line/argv prefix** carries the quota (the test comments say so), not an effective cgroup or scheduler bound. Firecracker has no wall-clock supervisor; libkrun CPU is declared-only. |

## 5. Text-scan and weak-witness replacement proposals (not implemented)

1. Claim 20 installer witnesses: cite `tests/install_sh.rs` behavioural cases
   instead of the three TEXT steps, or extend that file; keep the conformance
   scenario only as documentation.
2. Claim 2 constants: replace the two STRUCT asserts with a test that drives
   `mount_rootfs` through a recording seam and asserts the flags actually
   passed; the `include_str!` sibling test is the same weakness.
3. Claim 3: a KVM lane that boots a flipped-byte rootfs and asserts no agent
   handshake. Until then the row's wording is stronger than its witnesses.
4. Claim 10: cite the behaviour of `check-single-network-path`'s own unit tests
   or the endpoint binary tests instead of a step-name `ci:` token.
5. Claim 19: replace `test_audit_asset_id_parses` with a test that recomputes a
   digest for a file via the CLI path and compares it to the plan's identity.
6. Claim 9: add the rejection-ladder tests in `bundle.rs` to the row.

## 6. Reproduce

`git grep -n -E 'fn [A-Za-z_0-9]+' -- crates xtask tests src` and match the
`fn:` tokens in ADR-001's table; `gh run list --workflow security.yml --event
schedule`; `gh run view <id> --json jobs`; `cargo run -q -p xtask -- check-claim-catalog`.
