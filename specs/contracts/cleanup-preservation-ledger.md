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
panics `the sudo arm must be invoked` (`crates/mvm-cli/src/update.rs:2603`). The
hosts run as root, where the sudo arm is plausibly not taken, but this was not
confirmed by running the test as an unprivileged user. Treat it as open.

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
  test ran and passed except the one failure above, and the ADR-001 `fn:` names
  that are tests now ran by name. Not met: 17 cited names are not tests, so the
  gate proves they exist and the module tests pass, not that they are meaningful
  witnesses; the sudo-arm failure is undiagnosed.
- Backend and feature combinations including WASM: the feature-combination and
  WASM half is **MET** by the table above (this run plus the macOS run). The box
  as a whole stays **PARTIAL**: no HVF or libkrun native witness and no aarch64
  Linux run was made here, and Firecracker was exercised by the separate live
  KVM evidence (`live-kvm-acceptance-evidence-2026-11-01.md`), not by this run.
  Windows and WHP are future (ADR-009, #3553) and not claimed.

### Not measured

The 17 non-test names above; the sudo-arm test as an unprivileged user; the
spawn-ceiling witnesses against a real Firecracker, libkrun or HVF guest;
anything on aarch64; `ebpf-telemetry` and `embed-host-bins` clippy (excluded by
CI's own lane); Windows and WHP. Host B runs systemd 259, which the live KVM
evidence found breaks the scoped Firecracker launch; no Firecracker boot was
attempted on it here.
