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
#4230 OPEN. #4926 now owns removing the deliberately retained
singular-entrypoint compatibility.

Verdict: **PARTIAL** (owner: maintainer assigns #4926).

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

Evidence: a Firecracker attempt on Linux on 2026-11-02, recorded in "Firecracker
startup attempt 2026-11-02" below. It produced no lane-valid sample, and the
gate was not weakened to obtain one. Native HVF is not measured: the only Mac
available ran at a load average near 200. #4391 is OPEN.

Verdict: **BLOCKED**. Firecracker: the prepared-cold lane refuses every launch
for hashing artifacts, and the warm-claim lane refuses a 1,248 ms sample against
its 300 ms ceiling. HVF: needs a quiet native Mac.

### Backend/feature combinations including WASM

Evidence: `check-no-vz` and `check-single-network-path` clean; WASM witnesses named above. No per-platform or
feature-matrix run was done. WHP is future (ADR-009, #3553), not claimed.

Verdict: **PARTIAL**. Remaining: `just check::gated` and a native-platform
witness per backend. See "Evidence run 2026-11-01" and "Linux evidence run 2026-11-01" for what was run since.

### Authenticated vsock and host-held secret custody

Evidence: `check-single-network-path` clean (no guest NIC, one NetworkFlow
channel, one workload socket owner); `check-sdk-transport-free` clean;
`check-no-network-literals` clean. Negative tests, not run here:
`handed_placeholders_never_contain_the_secret_value`
(`crates/mvm-hostd/tests/egress_secret_leak_gate.rs`),
`start_workload_puts_no_secret_environment_on_the_kernel_cmdline` (mvm-runtime),
`relay_config_disables_the_guest_nic` (libkrun driver), `qemu_has_no_guest_nic`,
`ssh_flow_is_refused_even_when_listed`.

Verdict: **MET** as of the 2026-11-01 evidence run below: the named negative
tests ran and passed on the affected crates and the structural gates are clean.

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
2026-11-01 run: 99 of 132 claim-witness pairs ran and passed; the rest did not
run on this host (table below). The "Linux evidence run 2026-11-01" section
below ran 16 of the 33 by name on Linux; 17 remain, none of them tests.

### Relocatable installation and no-host-Nix/no-Docker

Evidence: `check-no-host-nix` clean; `check-guest-images-no-builder-tools`
clean; README Install section separates the release binary from the source
build. `tests/install_sh.rs` and `tests/smoke_fresh_install.rs` exist but were
not run (they were run in the 2026-11-01 evidence run below).

Verdict: **MET** as of the 2026-11-01 evidence run below: `install_sh`,
`smoke_fresh_install` and `pin_installer_default` pass (121 tests), including
running an unpublished archive beside the binaries it ships, and no host
`nix`/`docker` spawn exists. Prepared/cache-only launch semantics (the box's
last sentence) are also witnessed; see "Box: prepared/cache-only launch".

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

## Evidence run 2026-11-01

Tree: `9168754adca89a00dbaf4bee109bd1966b2081bf` (origin/main), worktree build,
macOS arm64 (Darwin 27.0.0), `~/.cargo/bin/cargo`, nextest 0.9.143,
`CARGO_BUILD_JOBS=6`. Load average at start 37 (below the 40 gate; it was 60+
for the preceding half hour and rose again to 90-180 during the run because of
other sessions on the host). Only default-feature test builds were run.

### Gates (`cargo run -p xtask -- <gate>`), all exit clean

| Gate | Result |
|---|---|
| `check-claim-catalog` | clean (21 claims, 153 witnesses verified) |
| `check-claim-witness-freshness` | clean (3 witness workflows resolved; run history reserved for scheduled reporting) |
| `check-single-network-path` | clean |
| `check-no-cli-shellout` | clean |
| `check-no-display-on-secret-types` | clean |
| `check-no-host-nix` | clean |
| `check-no-vz` | clean |
| `check-witness-citations` | clean (329 citations) |
| `check-asserted-absence` | clean (13 names, 4 regions) |

### Box: authenticated vsock and host-held secret custody (MET)

`cargo nextest run -p <crate> -E 'test(<name>)'`, all PASS:
`handed_placeholders_never_contain_the_secret_value`,
`endpoint_bin_serves_substitution_and_refuses_unbound_destination`,
`network_endpoint_refuses_unbound_destination`, `audit_chain_carries_no_secret_value`
(mvm-hostd); `unbound_service_returns_not_bound` (mvm-hostd);
`service_call_rejects_unknown_envelope_fields`, `policy_default_is_deny_all`
(mvm-contract); `run_net_default_is_deny_all` (mvm-client);
`start_workload_puts_no_secret_environment_on_the_kernel_cmdline`,
`qemu_has_no_guest_nic` (mvm-runtime); `relay_config_disables_the_guest_nic`
(mvm-backends); `ssh_flow_is_refused_even_when_listed` (mvm-vmm). Claims 12, 13,
16 and 17 witnesses are 2/2, 2/3, 4/4 and 9/9 PASS (the one claim-13 miss is a
function name, `substitute_bound_credential`, that matched no test). Fuzz
targets (claim 5) were not run locally (cargo-fuzz needs nightly); the last
scheduled `security.yml` run 41272659459 (2026-11-01, success) carries its job
`Fuzz - parsers (vsock + OCI)` green.

### Box: backend/feature combinations including WASM (PARTIAL)

- `cargo build -p mvm-contract --target wasm32-unknown-unknown`: Finished.
- `cargo build -p mvm-contract --lib --target riscv32imac-unknown-none-elf`:
  fails to compile `core` consumers because the target is not installed here
  (`rustup target list --installed` has no riscv32imac). Unavailable, not a code failure.
- Not run: `wasm32-wasip1` test (CI needs wasmtime), `just check::gated`
  (needs zig and cargo-zigbuild for Linux), the `ci.yml` all-features clippy
  with the release feature set (cold whole-workspace build on a saturated host),
  the `mvm-runtime/wasm-backend` and `mvm-hostd/wasm-backend` builds.
- Unavailable witnesses on this host: KVM/Firecracker (macOS), Windows and WHP
  (future per ADR-009, #3553, not claimed), native Linux `cfg(target_os)` tests.

### Box: shipped claims mapped to witnesses (PARTIAL)

Every `fn:` witness in the ADR-001 table (rows 1-21) was resolved to its crate and
run by name with nextest. 99 of 132 claim-witness pairs ran and PASSed with no
failure. The 33 that did not run matched no test in a default-feature run on
macOS: Linux-gated tests (seccomp, cgroup scope, no_new_privs), names that are
plain functions rather than tests, or feature-gated tests. They were not
individually diagnosed.

| Claim | fn witnesses run PASS | fn witnesses not run (see note) |
|---|---|---|
| 1 | 8/16 | `seccomp_allows_listed_denies_unlisted`, `a_started_process_under_the_admitted_standard_tier_cannot_open_a_socket`, `a_warm_claimed_child_under_standard_cannot_open_a_socket`, `a_warm_claimed_childs_workload_reports_a_seccomp_filter`, `an_exec_child_reports_a_seccomp_filter_and_no_new_privs`, `an_exec_under_the_admitted_standard_tier_cannot_open_a_socket`, `standard_tier_denies_an_af_vsock_socket_with_eperm`, `vsock_tier_allows_an_af_vsock_socket_and_denies_af_inet` |
| 2 | 0/2 | `set_no_new_privs`, `virtiofs_mount_flags_keep_workspace_read_only` |
| 3 | 2/2 | - |
| 4 | 1/1 | - |
| 6 | 2/3 | `acquire_from` |
| 8 | 9/12 | `admit_for_run`, `verify_audit_chain`, `synthesize_plan` |
| 9 | 2/4 | `read_and_verify_bundle`, `verify_plan_bundle` |
| 10 | 12/13 | `assert_vsock_only_device_model` |
| 11 | 0/2 | `verify_sealed_volume`, `apply_install_gate` |
| 12 | 2/2 | - |
| 13 | 2/3 | `substitute_bound_credential` |
| 14 | 2/2 | - |
| 15 | 2/2 | - |
| 16 | 4/4 | - |
| 17 | 9/9 | - |
| 18 | 27/32 | `a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited`, `a_granted_cpu_share_binds_a_real_spawn_to_its_quota`, `a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded`, `an_unresponsive_manager_fails_the_launch_instead_of_hanging_it`, `a_grant_that_fails_to_apply_refuses_the_cli_boot` |
| 19 | 5/5 | - |
| 20 | 8/13 | `a_real_release_bundle_verifies_under_its_tag`, `self_update_refuses_a_checksum_manifest_signed_for_another_tag`, `fresh_install_has_no_unsigned_fallback`, `fresh_install_requires_tag_pinned_bundle`, `fresh_install_trust_precedes_verifier_execution` |
| 21 | 2/5 | `apply_base_image_gate`, `scan_inventory`, `inventory_rootfs` |

`ci:` witnesses: scheduled `security.yml` run 41272659459 (2026-11-01, success)
has green jobs for cargo-deny, cargo-audit, reproducibility, verified boot
artifacts, guest-agent runtime boundary, seccomp functional denial, hash-verify,
app-deps-audit, fuzz parsers and the OCI hardening matrix. The `ci-main.yml` push run
41286801836 on this SHA is success. Claim 20 is not proven by CI: the most
recent `release.yml` run (41279625530, tag v0.26.0) failed, and its
`verify-release` job was skipped. A scheduled security run on 2026-10-31
(41168068368) failed.

### Box: relocatable installation and no host Nix/Docker (MET)

`cargo nextest run -p mvmctl --test install_sh --test smoke_fresh_install --test pin_installer_default`:
121 tests run, 121 passed (43.8 s). `rg` for `Command::new("nix"|"nix-build"|
"nix-shell"|"nix-store"|"docker"|"podman")` outside tests finds only a doc comment
in `xtask/src/check_no_host_nix.rs`; `check-no-host-nix` is clean; the string
`"docker"` appears only in tests and in a backend-name refusal.

### Box: prepared/cache-only launch (MET)

Tree `d876633332` (origin/main), macOS arm64, `~/.cargo/bin/cargo`.
`cargo nextest run -p mvm-client -p mvm-runtime -p mvm-cli --lib -E '<23 names>'`:
23 tests run, 23 passed, 5596 skipped. No new test was needed.

(a) A launch resolves only prepared pieces. Each miss refuses naming
`mvmctl bootstrap`, with the download mirror pointed at an empty/nonexistent
`file://` location and nothing cached afterwards:
`a_download_mode_host_refuses_an_unprepared_sidecar` (sidecar; asserts no
artifact dir is created), `required_overlay_cache_miss_names_explicit_bootstrap`
(overlay; asserts no overlay attached and no cache layout written),
`launch_refuses_an_unprepared_published_runtime_without_acquiring_it` (OCI guest
runtime; refusal under 300 ms), `a_library_launch_without_a_prepared_runtime_names_the_preparation_verb`
(library embedder), `a_required_but_missing_sidecar_fails_closed_with_an_actionable_message`
(mvm-runtime). Not separately witnessed: the initramfs piece has no
miss-refusal test of its own, and "no network attempt" is shown by an
unreachable mirror plus an empty cache rather than a socket assertion.

(b) Measured startup excludes download/build work. The cold-launch bench
reports acquisition as its own lane (`ArtifactMiss`, `MountMiss`) and rejects a
contaminated prepared sample: `prepared_cold_rejects_an_image_pull`,
`prepared_cold_rejects_a_build`, `prepared_cold_rejects_mount_materialization`,
`prepared_cold_rejects_a_warm_claim_by_flag_and_by_mode`,
`prepared_cold_rejects_a_launch_that_re_hashed_a_cached_artifact`,
`prepared_cold_reports_every_contaminating_kind`,
`prepared_lanes_refuse_an_archive_launch`,
`every_prepared_lane_is_held_to_the_ceiling_from_invocation`,
`acquisition_lanes_do_not_claim_the_prepared_boot_requirement`. `mvmctl doctor`
is a diagnostic report, not a timing path, and is not part of measured startup.

Verdict: **MET**, with the two unwitnessed details above. Full box text
(relocatable install, no host Nix/Docker, source-build prerequisites versus
release UX, prepared/cache-only launch) is now MET. The remaining PARTIAL in
"Streams" is #4794's proposal wording, which is a separate box.

## Linux evidence run 2026-11-01

Closes the Linux-only half of the two boxes the macOS run left PARTIAL
(claims-to-witnesses map; backend/feature combinations including WASM). Tree:
`d876633332dfc68c3fb4547dd81b9f3be3920543` (origin/main), fresh clone and
box-local `MVM_HOME` and target dir per host, both removed afterwards. Every
count below was read from the run's own output.

| Host | OS / kernel | systemd | Toolchain | Used for |
|---|---|---|---|---|
| A (x86_64, `/dev/kvm`) | Debian 12, 6.1.0-53-amd64 | 252 | rustc 1.97.1, nextest, QEMU, Firecracker v1.17.0 | the Linux-gated witnesses |
| B (x86_64, `/dev/kvm`) | Ubuntu 26.04, 7.0.0-22-generic | 259.5 | rustc 1.97.1, zig 0.13.0, cargo-zigbuild 0.23.0, wasmtime 46.0.1 | feature combinations, WASM, `just check::gated` |

Both ran as root over SSH, so a permission-denial test is vacuous there. Host B
needed `rustup target add` for `riscv32imac-unknown-none-elf` and
`wasm32-unknown-unknown` on the 1.97.1 toolchain (removed again afterwards);
`wasm32-wasip1` was already present. wasmtime was fetched from its release page
at the version `scripts/ci-linux-coverage.sh` pins.

### Witnesses that did not run on macOS (host A)

All commands from the clone, `CARGO_TARGET_DIR` and `MVM_HOME` in the scratch
directory.

| Witness set | Command | Result |
|---|---|---|
| Claim 1 seccomp, 7 named tests | `cargo nextest run -p mvm-agentd --test seccomp_apply` | 13 run, 13 PASS (the CI `seccomp-functional` lane's command, under nextest) |
| `seccomp_allows_listed_denies_unlisted` (`#[ignore]`) | `cargo test -p mvm-hostd --test seccomp_property -- --ignored` | 1 passed |
| `set_no_new_privs` (a function) | `cargo nextest run -p mvm-agentd --bin mvm-seccomp-apply` | 1 PASS, `set_no_new_privs_actually_sets_the_kernel_bit` |
| `virtiofs_mount_flags_keep_workspace_read_only` | `cargo nextest run -p mvm-builder-guest -E 'test(/virtiofs/)'` | 2 PASS |
| Claim 18 spawn scope, 2 named | `cargo test -p mvm-core --test spawn_scope_live -- --ignored --test-threads=1` | 3 passed (the two named and `a_stopped_service_manager_fails_the_launch_at_the_deadline`), 21.5 s |
| `an_unresponsive_manager_fails_the_launch_instead_of_hanging_it` | `cargo nextest run -p mvm-core --lib -E 'test(/spawn_scope/)'` | 54 run, 54 PASS |
| `a_grant_that_fails_to_apply_refuses_the_cli_boot` | `cargo nextest run -p mvm-client --features test-support -E 'test(/grants_report/)'` | 6 PASS |
| `a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited` | see below | 2 passed |
| `a_real_release_bundle_verifies_under_its_tag`, `self_update_refuses_a_checksum_manifest_signed_for_another_tag` | `cargo nextest run -p mvm-cli --features manifest-verify -E 'test(/update::/)'` | 58 PASS, 1 FAIL (below) |
| Installer scenario behind `fresh_install_*` | `cargo test -p mvm-conformance --test conformance --features bdd -- --name "Baked release bootstraps"` after `cargo build --bin mvmctl` | 1 scenario, 6 steps, all passed |

The live ceiling witness needs a VMM it can bound, so it was given QEMU with the
host kernel as a stand-in guest that holds its RAM:

```
MVM_LIVE_GUEST_MIB=512 MVM_LIVE_VMM_ARGV="qemu-system-x86_64 -machine microvm,accel=kvm -m 512 \
  -mem-prealloc -display none -serial null -nodefaults -kernel /boot/vmlinuz-6.1.0-53-amd64 \
  -append console=ttyS0" cargo test -p mvm-hostd --test spawn_ceiling_audit_live -- --ignored --nocapture --test-threads 1
```

Output: `a_scoped_vmm_reads_back_guest_ram_plus_the_overhead` read back
`memory: EnforcedCeiling { tier: Cgroup2MemoryMax, limit: Some(805306368) }` and
`tasks: ... Cgroup2PidsMax, limit: Some(1024)` for a 512 MiB guest (512 MiB plus
the 256 MiB margin), and `a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited`
reported `VMM ended with signal: 9 (SIGKILL) after 661.557834ms`. Without those two
variables the test panics on the missing variable (first attempt, exit 101), so it
is a harness input, not a defect. This is a kernel-as-guest stand-in, not a
Firecracker, libkrun or HVF guest.

One failure, outside the claim-20 witnesses:
`update::tests::extract_and_install_uses_sudo_for_a_host_owned_install_dir`
panicked `the sudo arm must be invoked`. Cause: the host ran as root, and root
writes through a `0555` directory, so `is_writable` is true and the sudo arm is
never selected. The test now probes `is_writable` after the chmod and returns
early when the directory is still writable, so it asserts the sudo arm wherever
that arm is reachable and does not depend on the euid.

Witnesses cited by a production function rather than a test, so no run by name
is possible: `acquire_from`, `admit_for_run`, `verify_audit_chain`,
`synthesize_plan`, `read_and_verify_bundle`, `verify_plan_bundle`,
`assert_vsock_only_device_model`, `verify_sealed_volume`, `apply_install_gate`,
`substitute_bound_credential`, `apply_base_image_gate`, `scan_inventory`,
`inventory_rootfs`. The tests of the modules that define them ran instead and all
passed (mvm-core `plan::synthesis|plan::bundle|deps_audit` 181; mvm-build
`published_image_set|app_deps_gate|base_image_gate|base_image_scan` 97; mvm-hostd
`plan_admission|audit_file|keyholder::substitution` 177; mvm-vmm `snapshot` 26;
mvm-fs `os_inventory` 19). That shows the module's tests pass, not that any named
test is the witness for the claim.

Tally of the 33 not run on macOS: 16 now ran by name and passed (8 for claim 1,
1 for claim 2, 5 for claim 18, 2 for claim 20), taking claims 1 and 18 to 16/16
and 32/32 by name. 17 did not run by name: 13 production functions above,
`set_no_new_privs` (its differently named test passed) and the three
`fresh_install_*` names, which are step functions of the scenario that passed.
By name that is 115 of 132.

### Backend and feature combinations, including WASM (host B)

| Step | Command | Result |
|---|---|---|
| no_std foundation, browser wasm | `cargo +1.97.1 build -p mvm-contract --target wasm32-unknown-unknown` | Finished (first attempt failed, target not installed; rerun after `rustup target add`) |
| bare-metal no_std | `cargo +1.97.1 build -p mvm-contract --lib --target riscv32imac-unknown-none-elf` | exit 0 |
| wasip1 under wasmtime 46.0.1 | `cargo +1.97.1 test -p mvm-contract --target wasm32-wasip1` | exit 0; lib 1239 passed, 0 failed, plus the integration targets |
| Feature clippy | the `lint-feature-clippy` command from `ci.yml`, features read from `release.yml` (`embed-host-bins` omitted, as in CI) | exit 0, `-D warnings`, 3 m 28 s |
| Release verifier absent | `cargo clippy --locked --all-targets -p mvm-core -p mvm-build -p mvm-client -- -D warnings` | exit 0 |
| `mvm-sdk` no default features | `cargo clippy --locked --all-targets -p mvm-sdk --no-default-features -- -D warnings` | exit 0 |
| wasmtime tier | `cargo test -p mvm-runtime --features wasm-backend wasm` | 61 passed, includes `a_fuel_only_grant_is_refused` and `an_unbounded_wall_clock_does_not_satisfy_a_fuel_grant` |
| wasmtime egress seam | `cargo test -p mvm-hostd --features wasm-backend --test wasm_egress_witness` | 2 passed |
| Release acquisition | `cargo check -p mvm-cli --features release-artifact-bootstrap[,manifest-verify] --lib`; `cargo test -p mvm-build --features release-channel --lib artifact_acquisition` | both checks exit 0; 4 passed |
| Linux-gated and feature-gated targets | `cargo-zigbuild check --target x86_64-unknown-linux-gnu --workspace --all-targets`; `cargo check -p mvm-conformance --all-targets --features bdd` (the body of `just check::gated`) | both Finished, exit 0 |

### Verdicts after this run

- Claims mapped to witnesses: **PARTIAL**, narrower. Every witness that is a
  test ran and passed except the one failure above (since fixed), and the
  ADR-001 `fn:` names that are tests now ran by name. Not met: 17 cited names
  are not tests, so the gate proves they exist and the module tests pass, not
  that they are meaningful witnesses. Claims 2 and 11 now also cite the tests
  that exercise the refusal (`set_no_new_privs_actually_sets_the_kernel_bit`,
  the `verify_detects_tampered_*` and `prod_rejects_*` tests).
- Backend and feature combinations including WASM: the feature-combination and
  WASM half is **MET** by the table above (this run plus the macOS run). The box
  as a whole stays **PARTIAL**: no HVF or libkrun native witness and no aarch64
  Linux run was made here, and Firecracker was exercised by the separate live
  KVM evidence (`live-kvm-acceptance-evidence-2026-11-01.md`), not by this run.
  Windows and WHP are future (ADR-009, #3553) and not claimed.

### Not measured

The 17 non-test names above; the
spawn-ceiling witnesses against a real Firecracker, libkrun or HVF guest;
anything on aarch64; `ebpf-telemetry` and `embed-host-bins` clippy (excluded by
CI's own lane); Windows and WHP. Host B runs systemd 259, which the live KVM
evidence found breaks the scoped Firecracker launch; no Firecracker boot was
attempted on it here.

## Per-box verdicts, 2026-11-01 (preserve and ADR-linked boxes of #4839)

Tree: `8be5161c7e` (origin/main) plus this change. Issue and PR states were read
with `gh` on 2026-11-01. MET here means a named test or CI gate that fails if the
invariant breaks, or a recorded disposition with a tracked owner; it does not
tick the box. This section supersedes the earlier per-box verdicts above where
they differ.

| Box (starts with) | Verdict | Evidence | Remaining item and who unblocks it |
|---|---|---|---|
| Map the current shipped claims | PARTIAL | `check-claim-catalog`, `check-witness-citations`, `check-conformance`, `check-dormant-controls`; 115 of 132 claim-witness pairs ran by name ("Linux evidence run") | 13 witnesses are production functions, not tests, so the gate shows they exist and not that they are meaningful. Needs a maintainer decision to replace each with a named test, or to accept the module tests as the witness |
| Preserve relocatable installation and the documented no-host-Nix/no-Docker prerequisites | MET | `install_sh`, `smoke_fresh_install`, `pin_installer_default` (121 tests); `check-no-host-nix`; `check-guest-images-no-builder-tools`; README Install separates release from source build. Prepared/cache-only: `a_download_mode_host_refuses_an_unprepared_sidecar` (now also asserts no connection reaches the mirror), `a_launch_with_an_unprepared_initramfs_refuses_naming_bootstrap_without_a_connection` (new: the real resolver, the initramfs piece, and a socket assertion), `required_overlay_cache_miss_names_explicit_bootstrap`, `launch_refuses_an_unprepared_published_runtime_without_acquiring_it`, and the `prepared_cold_rejects_*` bench guards | Both gaps the earlier verdict named (initramfs miss-refusal, socket-level no-network) are closed by those two tests. The overlay and OCI-runtime refusals still assert "no cache written" rather than a socket; that is the same code path and is not separately a gap in the box |
| Preserve the Linux-only image producer boundary | BLOCKED | Consumer half: `linux_only_schema_refuses_retired_runtime_source_fingerprints_including_null`, `linux_only_schema_refuses_every_retired_guest_runtime_role`, `check-image-lock`, `check-guest-images-no-builder-tools` | Producer half is in mvm-images; mvm-images#49 (drop the mvm input) is OPEN. Unblocked by landing it |
| Verify the staged image migration and release order | BLOCKED | #4100 CLOSED (source side landed, ADR-054). mvm-images#49 and #64 OPEN; #4764 OPEN | Needs a same-version signed release with the guest-runtime asset and installed-product boot evidence, then mvm-images publication; release owner and mvm-images owner |
| Keep image-set identity distinct from application identity | PARTIAL | `held_application_rechecks_archive_and_independent_key_without_enrollment`, `a_set_for_another_architecture_is_refused`, `a_set_mixing_architectures_is_refused`, `a_set_without_a_base_image_contract_is_checked_as_the_legacy_contract` | "Consolidate helpers only where semantics match" is a review, not a gate; no gate forbids a competing identity authority. A maintainer review of the two identity types would close it |
| Preserve one generated pack catalog | PARTIAL | `a_signed_image_descriptor_names_only_declared_in_pack_source_files`, `a_catalogued_application_installs_atomically_and_resolves_for_launch`, `bundle_origin_is_release_verified_only_for_enrolled_keys` (descriptor naming a key does not enroll it) | Catalog generation and exact-byte manifest hashes live in mvm-packs and were not inspected from here; mvm-packs owner |
| Preserve separate image and pack revocation authority | PARTIAL | `image_set_revocation` and `pack_revocation` are separate mvm-core modules; `an_applied_list_goes_stale_at_load`, `an_old_unexpired_list_cannot_undo_an_applied_image_set_revocation`, `the_authority_is_disjoint_from_every_other_compiled_identity` | No pack-revocation signer-identity test and no check that nothing deletes historical signed artifacts. Both are small tests in mvm-core, deferred rather than written here because the right witness for "no deletion" needs the maintainer to say which store holds the historical artifacts |
| Preserve atomic immutable publication | BLOCKED | `check-image-reproducibility` clean (local only) | The box says local checks are not a substitute; needs a published, admitted, booted artifact set. Publication authority and mvm-images release |
| Coordinate Studio PR#29 | BLOCKED | mvm-studio PR#29 is OPEN, checks green; not merged, no live witness | Studio owner merges and witnesses; nothing in this repository changes. This repository's side (typed `MvmClient` telemetry reads, #4873) is already merged |
| Preserve MVMD V1 independent contract boundaries | PARTIAL | mvmd carries `mvmd-types/src/billing.rs` and `mvmd-core/src/scheduler.rs`; mvm side: `binding_verification_rejects_tamper_identity_epoch_policy_time_and_assurance` | The contract tests live in the mvmd repository and were not enumerated; mvmd owner must name the witness for each of the seven clauses |
| Tracing/stream completeness | PARTIAL | #3419 CLOSED, PR#4379 MERGED; #3422-#3426 and #4184 OPEN. `check-stream-redaction-seam` clean; `a_full_queue_drops_the_span_and_counts_it_without_blocking`, `a_full_queue_sheds_output_with_counted_loss_instead_of_waiting`, `stopped_reader_consumer_bounds_bytes_and_counts_every_loss` | The open W3-W7 issues own completeness. `check-telemetry-inventory` reports 30 runtime gaps and says coverage is not certified; that count is the honest measure |
| Current security witnesses | BLOCKED | #2101, #4612, #4819 OPEN and visible. ADR-026 is `Proposed` and no claim row promotes it (`check-claim-catalog`). No-SSH: `ssh_flow_is_refused_even_when_listed`, `mandatory_deny_iptables_script_drops_ssh_port` | Scheduled-witness freshness cannot be shown while #4788 is OPEN and `check-claim-witness-freshness` reads workflow definitions only. One scheduled `security.yml` run (41272659459, 2026-11-01) was green; the one on 2026-10-31 (41168068368) failed. Unblocked by #4788 |
| Protocol and readiness (ADR-019) | PARTIAL | ADR-019 Accepted; negotiation before dispatch: `capability_negotiation` tests including `share_grant_on_wasm_is_refused_at_negotiation_naming_fuel`, `resource_usage_is_capability_negotiated_and_unary`; cancellation: `cancel_extension_is_identity_only_and_rejects_process_authority`, `extension_cancellation_round_trips_over_mock_io`; backpressure type: `test_proc_wait_event_backpressure_serde_roundtrip` | No single witness for readiness distinct from process-running, nor for typed backpressure end to end; #4414-#4416 and #4809 own them |
| Mailbox operational contract (ADR-057) | PARTIAL | Not in the requested set but kept consistent: accepted architecture, no claim promoted, #4622 and #4628-#4635 OPEN | Behavior cannot be evidenced until the implementation issues land |
| Evidence completeness (ADR-110) | PARTIAL | `build_inclusion_proof`/`verify_inclusion`, `inclusion_proof_rejects_unknown_field`, `check_inclusion`, `completeness_serializes_as_a_word_not_a_bool` | No witness for exactly-once accounting or for attested versus derivable completeness; #4415/#4416 |
| Owner-mediated application access (ADR-056/#4460) | MET | #4460 retitled on 2026-11-01 to "Implement owner-mediated application access (ADR-056 accepted; typed channel unimplemented)" and a comment records the reconciliation. ADR-056 and the contract both state the channel does not exist and promote nothing. Sealed-console refusal: `console_refused_on_sealed_image`, `interactive_terminal_under_sealed_prod_is_refused` | The reconcile half of the box is done. The typed channel stays unimplemented, deliberately: the box forbids a duplicate post-demo protocol implementation |
| GPU remoting (ADR-053/#3560) | PARTIAL | Compute over vsock, no passthrough: `check-single-network-path`; refusals `forged_streams_and_events_are_refused_without_queueing_work`, `an_oversized_frame_prefix_is_refused_without_a_huge_allocation`, `a_launch_past_the_param_cap_is_refused_without_touching_the_backend`; PR#4727 MERGED (bounded harness) | Native-hardware, fork and device-memory witnesses are retained gaps by the box's own wording; #3560 stays OPEN. Needs GPU hardware |
| Capture/authoring/function entrypoints (ADR-050/005) | PARTIAL | ADR-050 initial slice implemented (`cargo test -p mvm-capture`); closed #5 and merged PR#4838; the singular-entrypoint and string-environment compatibility now has an owner, #4926 (OPEN). The earlier verdict saying no issue existed is stale | #4230 and #4926 OPEN. Maintainer assigns #4926 |
| Browser/WASM capability tiers (ADR-024/049) | PARTIAL | WASM refusal and bound tests ran on a Linux host: `a_fuel_only_grant_is_refused`, `an_unbounded_wall_clock_does_not_satisfy_a_fuel_grant`; no claim row treats WASM as hardware isolation; ADR-049 is preview | Deferral of WebLinux and the local builder is carried by #4222, #4224, #4226, #4228 (all OPEN). No speculative implementation exists, which is what the box asks |
| Future Windows direction | MET | ADR-009 Status and Decision state the future libkrun/WHP direction in #3553, keep Linux/macOS tiers unchanged, rule out a new in-house WHP driver, and list the promotion gate (qualified boot witness, private-state ACLs, signing/integrity posture, named refusal and doctor agreement, capability evidence). #3553 OPEN | The reconcile is on `main`. Promotion itself is future and not claimed |
| Staged-state contradictions | PARTIAL | README Install names the macOS 13-25 libkrun tier as packaged with a live witness still open (matches ADR-028 staged and #4577 OPEN); ADR-054 Status and ADR-030 "Amended 2026-10-05" agree and state that publication and boot evidence is outstanding; ADR-046 is `Proposed` with ADR-035 still Accepted for streams. #4794 now carries a comment that its in-line preparation proposal must be a separate, excluded lane and that the refusal witnesses change deliberately | #4794 is a proposal, not a decision: the maintainer must accept or reject in-line preparation. Until then the measured prepared-launch semantics hold |
| Record reproducible cold/warm startup evidence | BLOCKED | `every_prepared_lane_is_held_to_the_ceiling_from_invocation` and the `prepared_cold_rejects_*` guards pin the budget definitions. 2026-11-02, Firecracker, Linux x86_64: `mvmctl bench --lane prepared-cold` refused the first warm-up for `artifact_hash`, `--lane warm-claim` refused a sample that reached the guest 1,248.3 ms after invocation (ceiling 300 ms); see "Firecracker startup attempt 2026-11-02". #4391 OPEN (HVF warm claims take about 3.2 s on the CI runner, so warm launches are refused) | Firecracker needs the cause of the per-launch artifact hash found and fixed (or shown to be specific to the contributor surface) so a lane sample can be produced, and the warm claim brought under 300 ms and then 50 ms. HVF needs invocation-to-ready runs on a quiet native Mac. The 2026-08-19 Firecracker row in `performance.md` is not a current measurement. Owner of #4391 and #4648, plus an operator with a quiet Mac |

Not changed by this section: the README's 300 ms warm refusal ceiling is still
not evidence for the 50 ms warm goal, and no verdict above edits an issue body
or ticks a box.

### Firecracker startup attempt 2026-11-02

Host: Hetzner `mvm-kvm`, AMD Ryzen 5 3600 (12 logical CPUs), Linux 6.1.0-53,
Firecracker v1.17.0, rotational ext4 (`ROTA=1`), shared with a CI runner. Load
average at the start of each command: 0.06, 0.35, 1.11, 1.41. Binary:
`cargo build --locked --profile release-min --features dev` at `56b56666f2`
(optimised, contributor surface, the surface a source checkout runs), with an
isolated `MVM_HOME`. Prepared with `mvmctl image dev ensure`, `mvmctl dev
runtime-overlay build` and `mvmctl bootstrap --production --kernel-source
download`; a plain `mvmctl run --no-detect -- /bin/true` then booted (1.3 s
including teardown). Everything created on the host was removed afterwards.

| Command | Result |
|---|---|
| `mvmctl bench --lane prepared-cold --runs 20 --warmup 2` (first attempt) | `warm-up launch 0 does not belong in this lane: lane prepared_cold forbids warm_claim, artifact_hash but the launch performed it`. The `warm_claim` part was my own earlier launch leaving a standby |
| Same, after killing the standby and with `MVM_RESIDENCY=cold` | `lane prepared_cold forbids artifact_hash but the launch performed it`. A plain launch had already run once, so the cache sidecars existed; no third attempt was made |
| `mvmctl pool warm`, then `mvmctl bench --lane warm-claim` | `lane warm_claim sample reached the guest 1248.3ms after invocation; every sample must be under 300.0ms` |
| 22 sequential `mvmctl run --no-detect -- /bin/true`, `MVM_RESIDENCY=cold`, first two discarded, wall clock of the whole command | n=20: min 856.8, p50 863.5, p95 1,654.6, max 1,660.3 ms (load 1.41). This is invocation to exit including teardown, not the lane's invocation-to-ready, and it is not a lane sample |

What it shows. The harness refuses rather than reports, which is its design: the
budgets and the work flags were left alone. `artifact_hash` means a launch read
and hashed artifact bytes after the cache was prepared. An `strace` of one launch
shows the per-machine runtime generation (`overlay.ext4`, `overlay.verity`,
`initramfs.cpio.gz`) being created under `runtime-evidence/` and then reopened
for reading, and `rootfs.ext4` being opened read-only; that is consistent with
the flag but is not proof, because the bytes hashed per file were not counted.
Whether a release-channel binary behaves the same was not tested. The seeded
2026-08-19 row in `performance.md` (171.5 ms dispatch window, 795 ms total, a
different CPU and commit) measured a different quantity, so the 863 ms above is
neither a confirmation nor a regression of it.

Missing: a lane-valid Firecracker sample on this commit, any warm sample under
300 ms, and every HVF number.

## Telemetry-affecting changes this campaign (box: tracing/telemetry review)

Method: all 33 merged PRs matching `#4839 in:title` were diffed
(`gh pr diff`) and filtered for `tracing::`, `span`, `otlp`, `observab`, `audit`,
`redact`, log macros and `emit`. Most hits are comment or contract-doc edits.
Only the PRs below change code in or beside a telemetry, audit or redaction path;
every other PR in the set (docs, comment-only, CLI alias, image-set pin, backend
selector, HVF boot, BDD) touches none.

| PR | Change | Behavior at risk | Post-merge evidence | Verdict |
| --- | --- | --- | --- | --- |
| 4935 | `tracing-subscriber` built without default `tracing-log` | Third-party `log::` records (rustls, mio) are no longer forwarded to the subscriber when `.init()` runs (`observability/logging.rs`) | No first-party `log::` macro, `LogTracer` or `tracing_log` use remains (`rg` over `crates/`, `src/`). First-party messages, spans, OTLP export, correlation ids and redaction all go through `tracing` and are untouched. The PR's dependency table records the risk as accepted | Retained for first-party; third-party `log` diagnostics intentionally dropped (documented) |
| 4937 | Local `sha256_hex` / `hex_lower` / `hex_encode` copies replaced by `mvm_contract::hash::sha256_hex` and `hex::encode` (incl. `snapshot_hmac`, `snapshot_sign`, attestation header, hostd `binary_integrity`) | Digest and hex text feeding signed or audited values | Both old and new emit lowercase two-digit hex of the same SHA-256 bytes; `sha256_hex_matches_the_standard_encoding` (mvm-contract) and the existing snapshot/attestation round-trip tests still compile against the new helper | Retained |
| 4963 | Audit evidence completeness requires each leaf exactly once | Mandatory signed-audit guarantee | Strengthened, not weakened: `a_leaf_listed_twice_in_place_of_another_fails_completeness_despite_equal_count` | Retained, tightened |
| 4964 | Deleted tautological tests: `filter_default_covers_mvm_targets_at_trace` (span_timing), `default_capacity_constant_is_documented_value` (event_bus), and a source-text scan in `input_gate.rs` | Redaction and bounded-queue invariants | `span_timing::DEFAULT_FILTER` still exists and is used by `logging.rs`. The input-gate scan asserted the plaintext-carrying `KnownSecret` type stays deleted: it does not exist anywhere in `crates/` or `xtask/`, and the only setter, `with_fingerprint`, takes a `SecretFingerprint` (compiler-enforced); `xtask check-stream-redaction-seam` is clean. The event-bus capacity constant is still used; queue-full behavior is covered by other tests | Retained |
| 4954 | hostd comment edits in `audit/merkle.rs`, `supervisor/audit_file.rs` | none (comments) | Diff has no code lines | Retained |

Named bounded-queue and loss witnesses, all still present on main:
`a_full_queue_drops_the_span_and_counts_it_without_blocking`
(`mvm-cli/src/observability/otlp/export.rs`),
`a_full_queue_sheds_output_with_counted_loss_instead_of_waiting`
(`mvm-agentd/src/telemetry_capture/stdio_tap.rs`),
`stopped_reader_consumer_bounds_bytes_and_counts_every_loss`
(`mvm-agentd/src/stream_pump/reader_tests.rs`).

Verdict: **MET for the review duty on this campaign's merged set**: no regression
found, so no fix PR. The open W3-W7 completeness issues and the telemetry
inventory's runtime gaps (see the tracing/stream section) are unchanged and
still own completeness. Later PRs need the same per-diff review.

## #4840 status on main (box: macOS fixture and owned-child performance)

Landed: PR 4854 (synthetic-checkout fixtures for the nine pair/default-image/
kernel unit consumers; bounded owned-child helper `test_boot_payload.rs`) and PR
4883 (observer-error and cleanup-failure branches).

| Acceptance item | State on main |
| --- | --- |
| Inventory of real-checkout reads | Done (issue comment) |
| Synthetic fixtures, no production bypass | Done; production compiled-root selection unchanged |
| Real-checkout identity/custody witnesses retained | Present: `mvm-build/src/image_source/tests/git_identity.rs` builds real git repos (staged, sparse, submodule, worktree, hostile-git cases); `tests/local_set.rs` covers checkout-root refusal |
| Bounded child: deadline, reaping, diagnostics | Done and tested: `expired_child_deadline_reports_termination_and_reaping`, `observer_error_is_returned_after_the_child_is_killed_and_reaped` (child blocked and running), `cleanup_failure_is_reported_not_swallowed`, `diagnostic_capture_is_bounded`. Scope: the test helper owns its direct child only; no process-tree or parent-SIGKILL guarantee is claimed |
| Immutable clean-main vs PR baseline, identical features | **Not done** |
| Before/after timing with identical commands | **Not done** |
| Native macOS full-workspace run within a budget | **Not done** |

Why the last three are open: they need a quiet native macOS host. This session's
host load average was 270 (64 users) at measurement time, so any timing taken
now would be noise and would not satisfy "identical-feature timing". A timing
claim here would be fabricated; it needs a dedicated run and cannot be produced
by editing code. Verdict: **PARTIAL**.

## Panic, ownership and cleanup sweep (box: ownership, allocation, errors, cancellation, cleanup, unsafe, panic paths)

Evidence commit: `origin/main` at `8be5161c7e`, 2026-11-01. Method: a
line-level scan of every non-test `.rs` file under `crates/` (test modules,
`#[cfg(test)]` items, `tests/`, `examples/`, `benches/`, `fuzz/`, files declared
only as test modules, and `mvm-conformance` excluded; comment lines excluded),
followed by reading each candidate. A count is a candidate count, not a defect
count. `await_holding_lock` and `await_holding_refcell_ref` are default-warn
clippy lints, so the existing `-D warnings` gate already holds the
guard-across-await line; they were not re-scanned by hand.

### Candidate counts per crate (production code only)

| Pattern | Before | After | Where it concentrates |
|---|---|---|---|
| `.unwrap()` | 102 | 97 | 96 of the 97 sit in diagnostic and test-support modules that are only compiled behind a test parent (`portable_boot_assets_diagnostic.rs` 41, `foreground_diagnostic.rs` 20, `legacy_*_runtime.rs` fixtures 22, `elf.rs` fixture 3) or in `build.rs` (4); the rest are length-checked `try_into` on fixed slices (`kernel_image.rs` 3, `snapshot_encryption.rs` 2) |
| `.expect(` | 536 | 536 | `mvm-hostd` 111, `mvm-agentd` 73, `mvm-core` 73, `mvm-contract` 55, `mvm-vmm` 51; spot-read, each names an invariant (poisoned-lock, static regex, infallible encode) |
| `panic!(` | 11 | 11 | `mvm-cli` 4, `mvm-sdk` 4 (documented `# Panics` in SDK macros), one each elsewhere |
| `unreachable!(` | 24 | 24 | exhaustive-match arms behind a prior validation |
| `std::process::exit` | 63 | 63 | 56 are in `[[bin]]` entry points; the 7 in library modules are deliberate (below) |
| `mem::forget` | 11 | 11 | custody and guard handoffs where the destructor must not run (`cold_channel`, `capture_custody`, `restore_image::self`) |
| `unsafe` keyword | 1085 | 1085 | `mvm-agentd` 172, `mvm-vmm` 136, GPU crates ~280, `mvm-runtime` 99, `libkrun-sys` 88 |
| `let _ =` on a removal, rename, kill, shutdown or teardown | 247 | 235 | best-effort teardown, see below |

Per-crate `.unwrap()` before and after: `mvm-build` 2 to 0, `mvm-compiler` 1 to
0, `mvm-cli` 5 to 4, `mvm-core` 3 to 2; every other crate unchanged.

### Judged benign, and why

- **`process::exit` in library modules.** `host_agent_idle` (idle shutdown of the
  host agent), `supervisor::claimed_child` (a claimed child that cannot be
  bounded must not keep running), `supervisor::wall_clock` (the wall-clock kill:
  the process owns the guest and the exit code is the contract; the exit file and
  helpers are released first by `record_and_release`), and
  `helper_contract::exit_with_probe_answer_if_requested` (documented to run first
  in a helper's `main`). Each runs in a process that owns exactly one VM or probe,
  so skipping destructors loses nothing the function has not already released.
- **Detached `tokio::spawn`.** The 32 spawn sites that drop their handle are
  accept loops, per-connection tasks and watchers whose lifetime is the process
  or the connection; none owns a resource that outlives its task.
- **`mem::forget`.** Each call hands a custody guard to a longer-lived owner or
  defuses a guard whose work the surrounding function already did.
- **Bulk `let _ = remove_file/remove_dir_all`.** About 200 of the 235 sites run
  on an error path (the original error is what the caller needs), inside `Drop`,
  or on a scratch file whose absence is the desired end state. Not changed.
- **Length-checked fixed-slice conversions** (`kernel_image::parse`,
  `snapshot_encryption` header probe): the preceding length check makes the
  conversion infallible. Left as is; rewriting them is churn, not a fix.
- **`run_sidecars::clear_prior_run`** ignores removal failure by documented
  design; the boot reports an unwritable state directory more clearly.

### Fixed

| Rank | Finding | Fix |
|---|---|---|
| 1 | libkrun and QEMU boot removed the stale pid file with `let _ =`, and boot confirmation is `pid_file.exists()`. A stale file that could not be removed passed for this boot's marker. | `run_sidecars::remove_stale_marker` tolerates only an absent file and refuses the boot otherwise; two tests. |
| 2 | The builder pipeline discarded `backend.teardown` after a successful build, so a builder left running was silent. | Logged through `env.log_warn`. |
| 3 | The transient-run Ctrl-C handler discarded both the install result (a second install in one process fails with `AlreadyExists`, leaving Ctrl-C unable to stop the VM early) and the `stop_transient` result. | Both logged. |
| 4 | Firecracker restore paths discarded `teardown_paused` on four failure branches, hiding a leaked paused VM. | One `warn_teardown_paused` helper logs it; the original error is still returned. |
| 5 | Idle-pool claim rollback discarded the `rename` back, hiding a stuck claimed directory. | Logged. |
| 6 | Five production `.unwrap()` on invariants the compiler could not see (`embed_toolchain`, `stage0` seed lift, `vm artifact` prefix resolve, TypeScript decorator site, manifest image ref). | Rewritten so the invariant is in the types: `unwrap_or`, `try_from` to a one-element array, `let ... else`, a bound pattern. |
| 7 | 16 undocumented `unsafe` blocks in the two crates on the privilege and C-ABI boundary. | `// SAFETY:` comments in `mvm-setpriv` (8) and `mvm-host-services` (8). |

### Unsafe inventory and SAFETY coverage

Blocks, `unsafe impl` and `unsafe fn` definitions, excluding bindgen's `sys.rs`.
"Undocumented" means no `SAFETY` or `# Safety` text within the 7 lines above to
2 below. About half of the undocumented count is not a block at all: `extern`
declarations and `unsafe extern "C" fn` type aliases (`mvm-gpu/src/native.rs` 35,
`libkrun_bindings.rs` 64) carry their contract in the C header, so the figure
that matters is blocks and impls.

| Crate | Sites | Undocumented before | Undocumented blocks/impls after this sweep |
|---|---|---|---|
| `mvm-agentd` | 170 | 22 | 18 |
| `mvm-vmm` | 135 | 16 | 13 |
| `mvm-gpu` | 101 | 43 | 3 |
| `mvm-gpu-cuda-shim` | 74 | 9 | 9 |
| `mvm-hostd` | 71 | 11 | 10 |
| `mvm-runtime` | 69 | 2 | 2 |
| `libkrun-sys` | 65 | 64 | 1 |
| `mvm-cli` | 33 | 15 | 15 |
| `mvm-setpriv` | 16 | 8 | 0 |
| `mvm-host-services` | 15 | 8 | 0 |
| `mvm-backends` | 17 | 4 | 3 |
| `mvm-build` | 8 | 4 | 4 |
| `mvm-gpu-nvml-shim` | 17 | 2 | 2 |
| other (`mvm-gpu-cudart-shim`, `mvm-hostlib`, `mvm-builder-guest`, `mvm-fs`, `runmvm-client`, `mvm-gpu-shim-core`, `mvm-core`) | 136 | 6 | 0 |
| Total | 927 | 214 | 80 |

### Remaining, and why

- 80 undocumented `unsafe` blocks, mostly one-line `libc` calls in `mvm-agentd`
  (`guest_mount.rs`, `guest_net.rs`), `mvm-cli` (`vm/console.rs`, `seccomp_audit.rs`),
  `mvm-vmm` (`host/*_spawn.rs`) and the CUDA shim. Left because enabling
  `clippy::undocumented_unsafe_blocks` workspace-wide needs all of them done in one
  change, and a half-documented crate would not hold the lint. Tracked by this
  box staying unticked.
- The ~100 `.unwrap()` in diagnostic and test-support modules are reachable only
  from test parents; moving them under an explicit `#[cfg(test)]` would make the
  next scan exact.
- No test can force `remove_file` to fail on the engine-start paths of the
  Firecracker and HVF drivers without a seam that does not exist; the
  logging-only fixes (ranks 2 to 5) carry no new tests.
