# Firecracker canonical custody acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles [#4606](https://github.com/tinylabscom/mvm/issues/4606) (a bundle
carrying a canonical Linux proof was refused at launch) against the change that
landed Firecracker canonical kernel custody
([#4611](https://github.com/tinylabscom/mvm/pull/4611), merge commit
`3d2960ca658d5e2956947d67340f33e5249c8e68`, ancestor of the release head below)
and one later release run. Review follow-ups are tracked in
[#4612](https://github.com/tinylabscom/mvm/issues/4612). The issues own status.

## Recorded run

- Run: [39897038015](https://github.com/tinylabscom/mvm/actions/runs/39897038015), release workflow, tag `v0.24.1`, head `0af2242f3965f1f5cb008d8b035c8c6d8761ee0e`, ubuntu-24.04 runners, started 2026-10-23T03:49Z.
- Job: `120245944227`, `e2e-docs / Documented surface e2e (Linux, Firecracker, shard 0/2)`, run attempt 1, conclusion `success`. The log records `MVM_BDD_SHARD: 0/2`, `MVM_BUILDER_BACKEND: firecracker` and `HEAD is now at 0af2242 test(runtime): a retained Firecracker generation blocks the VM name (#4625)`. Its summary line is `205 scenarios (205 passed)` and `954 steps (954 passed)`.
- Scenario, `features/suites/s13_bundle_boot/verify_and_boot.feature` (tagged `@live @bundle_boot_live`), log lines from 2026-10-23T05:57Z:

```
Feature: s13_bundle_boot verify-and-boot
  Scenario: A signed OCI artifact boots as the positional source
   ✔  When I seal "docker.io/library/alpine:3.20" into a signed artifact in the live home
   ✔  And I boot the signed artifact in the live home with "-- /bin/echo bundle-boot-witness"
   ✔  Then the command exits with code 0
   ✔  And the output contains "bundle-boot-witness"
```

- The shard 1/2 job, `120245944351`, also finished 205 of 205. The same scenario failed on the earlier release run [39643290918](https://github.com/tinylabscom/mvm/actions/runs/39643290918) with `canonical kernel backend custody is pending integrated validation`.
- During the scenario the harness reported three leftover processes it then stopped: a `firecracker --api-sock .../fc.socket` process, its `sudo setsid` launcher and the idle reaper. That is the VMM the boot used.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| Firecracker canonical kernel custody binding is implemented | #4611 adds `process_identity` to the Firecracker driver (`crates/mvm-backends/src/driver/fc.rs`, `fc/stop.rs`), `supports_lifetime_custody` and `release_after_process_exit` in `crates/mvm-runtime/src/kernel_custody.rs`, and the process-table identity in `crates/mvm-vmm/src/host/process_identity.rs` and `process_liveness.rs`. The ADR-001 note "Canonical kernel custody on Firecracker — limits" records the mechanism | The Firecracker identity is a process-table identity (pid, start time, host boot id, a pid that serves this VM's `--api-sock`), not an authenticated instance-bound exit proof as on HVF. It is only as trustworthy as the host process table. A zombie counts as not exited. |
| Integrated custody and abort or confirmed-exit tests exist | Tests added by #4611: `firecracker_generation_is_released_only_for_the_recorded_exited_process`, `a_native_instance_record_cannot_be_released_by_process_exit`, `a_running_process_retains_the_generation_until_it_is_really_gone`, `lifetime_custody_is_limited_to_backends_with_exit_evidence`, `a_pid_naming_another_vms_firecracker_is_refused`, `the_same_process_has_not_exited`, `a_missing_recycled_or_pre_reboot_process_has_exited`, `an_unreadable_or_garbled_process_table_is_never_an_exit`. The merged `0af2242` also carries `test(runtime): a retained Firecracker generation blocks the VM name (#4625)` | These are unit-level tests of the release rule and the liveness probe. The Linux-only real-process test and the real `is_firecracker_for_socket` path have not been recorded against a live Firecracker as a named run (#4612). No test here drives a failed Firecracker start, `observe_booted` dispatch or a crash between boot and recording the identity (#4612). |
| The unconditional refusal and the HVF-only restriction are removed together | `crates/mvm-client/src/launch/bundle_runtime.rs` now gates on `supports_lifetime_custody(kind)` and refuses with `canonical kernel lifetime custody unsupported by this backend`; the ADR-001 note states the bundle launches on HVF and Linux Firecracker and every other backend refuses | No test named for this change asserts that libkrun and QEMU refuse a canonical bundle through `bundle_runtime` (#4612). The refusal for those backends rests on the capability function and its test, not on a launch-level test. |
| A canonical-bundle launch test sits beside `a_signed_archive_is_installed_and_becomes_its_bundle_address` | Not witnessed by a unit or integration test. That test is `crates/mvm-cli/src/commands/bundle/install.rs:435` and installs an archive; no test next to it launches a bundle that carries a canonical proof. The only launch of a canonical-proof bundle on Firecracker on record is the live scenario above | The live scenario is an end-to-end boot, not the in-process test the criterion names. Whether the scenario's sealed bundle carried the proof is not printed in the job log; it follows from the exporter, which always emits the member, and from the fact that the same scenario hit the proof refusal on run 39643290918. |
| The `s13_bundle_boot` live scenario is green in a recorded release or Extended CI run | Release run 39897038015, job 120245944227, scenario `A signed OCI artifact boots as the positional source`, all four steps passed on Firecracker, output contained `bundle-boot-witness` | One release run on one commit, one backend, one image (`alpine:3.20`). The Extended CI leg that the claims register cites is not green; see the next row. |
| The named claim witness `ci:bundle_boot_live` (MVM-SEC-25) passes | Not witnessed. The Extended CI job `BDD live bundle_boot_live (Linux, Firecracker)` failed in the scheduled run [39903020198](https://github.com/tinylabscom/mvm/actions/runs/39903020198) (job 120265459757, head `0af2242f39`) and in [39725207743](https://github.com/tinylabscom/mvm/actions/runs/39725207743) (job 119674382790, head `3ae4f85a08`). Both fail at the seal step, not at the boot: `guest runtime release: download failed for https://github.com/tinylabscom/mvm/releases/download/v0.24.1/mvm-guest-bins-v0.24.1.tar.gz: curl exited 22 ... 404` (v0.24.0 in the earlier run). The sibling legs `ci_live` and `tool_live` failed in the first of those runs as well | This is a separate defect from #4606: the nightly leg looks for a release guest-runtime asset that the tag does not publish. The release shard ran the same scenario green because it seals from a source-built runtime. Until the nightly leg is green, `model/claims.toml` MVM-SEC-25's description of a nightly boot witness is not backed by a recent green Extended CI run; the release shard is the only recorded green boot. |

## Still missing (from #4612)

- A launch-level test that `bundle_runtime` refuses libkrun and QEMU for a canonical bundle.
- A test that a failed Firecracker start retains the generation and blocks the VM name.
- A test that `observe_booted` dispatches to the Firecracker branch (needs the pinned-kernel owner fixture).
- A recovery path, or an earlier pid binding, for a crash between Firecracker boot and recording the process identity.
- A review of plan-admission equivalence with the HVF path, and of the standby and warm-claim `FcRunningVm` constructors against `process_identity`.
- The Linux-only real-process test and the real `is_firecracker_for_socket` path run against a live Firecracker.
- A check that Firecracker's held-descriptor boot accepts the canonical kernel format (ELF or arm64 Image). The recorded boot is consistent with it on x86_64 only.
