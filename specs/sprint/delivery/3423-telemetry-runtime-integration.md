# Telemetry runtime integration: signer and backend channels

Issues #3421 and #3423; the every-VM tracing epic #3419 remains open.

## Local implementation boundary

The host receiver retains a receive-only session rather than a host signing key.
It pins the registered guest before requesting a signature and verifies the
signature before confirming the handshake. A typed resident-signer operation
validates the telemetry namespace, canonical session ID, bounded public fields,
host identity and guest proof. The async client bounds connect/write/read with
one deadline and rejects wrong response IDs, keys, algorithms and signatures.
Cancellation closes its owned socket; the client runs on a collector worker,
never a producer callback. It does not establish runtime generation ownership.

Workload channel specifications now carry a dedicated host-dialed telemetry
endpoint independently of egress, broker and console grants. Firecracker,
libkrun, QEMU and HVF connection paths recognize the telemetry port while
continuing to refuse unrelated ports. HVF's supervisor explicitly forwards the
channel to the existing host-dial bridge. Live handoff authorizes telemetry with
a separate signed mask bit; saved restore derives a fresh child-local endpoint
without inheriting the parent's egress, broker or console access.

The existing HVF `console_data_sockets` / `console_sockets` fields are additional
host-dial listener lists and now also carry telemetry. Their names do not confer
console permission; the semantic service and signed handoff bit choose the port.

No guest listener, source adapter, VM-lifetime collector, generation registration
or detached retrieval is activated by these changes. A routed endpoint alone is
not evidence that any trace is captured, delivered or retained.

The no-egress launch path now calls identity-only provisioning instead of omitting
credentials. Cold boot reuses the existing private identity drive writer with a
fresh guest key and only the host public anchor. It creates no network endpoint,
egress CA or ingress authority. Warm claim requires the parent's registered public
key, persists that same public identity in child state, and does not mint a drive
for a guest whose restored memory already holds its key. Missing/malformed anchors
or parent records refuse launch. This addition's focused tests pass; it
does not yet establish collector registration or boot/generation ownership.

Standby capture is a separate launch path. It now provisions its own guest
identity before VMM boot, reusing the workload identity-disk composition helper
without starting a network endpoint or broker. The disk-parity regression must
compare workload disks while requiring distinct parent/workload identity paths.

The identity-stage policy pass reports all 69 repository gates clean, plus the
separate declared-backing gate. An earlier pass found the runner over its
production-line limit; standby provisioning and its error context now live in
the existing spawner module. Native regression runs exposed old disk-count
assumptions and an egress-spawner test double that omitted the identity drive.
The fixture now mirrors production identity delivery, and both standby parity
tests require distinct identity paths while preserving the shared disk stack.
Their final affected-crate rerun passes. Both restore BDD scenarios pass (ten
steps, no skipped scenarios) using a rebuilt CLI. The final Linux all-target
cross-check passes; full workspace validation remains pending.

## Validation observed

On the macOS host, with isolated worktree state and Rust 1.97.1:

- Seven resident-signer integration tests pass after backend integration,
  including encrypted record reception over mock guest I/O through the actual
  signer Unix socket, deadline cancellation, payload-safe refusals and valid
  guest proofs for rejected non-telemetry domains.
- The new no-grant channel regression failed before implementation because the
  workload spec contained zero telemetry endpoints.
- `cargo test -p mvm-vmm -p mvm-backends -p mvm-runtime --lib` passes:
  679, 203 and 975 tests respectively (1,857 total), with six existing runtime
  ignores. This includes no-egress and standby identity provisioning, missing
  credential refusal before boot, inheritance, write failures and disk isolation.
- Workspace all-target clippy passes with warnings denied. Linux all-target
  cross-compilation passes; it does not execute a Linux kernel or a microVM.
- Restore BDD assertions require a child-local telemetry endpoint and still
  refuse inherited console/egress/broker authority. Both scenarios pass (ten
  steps, none skipped). BDD-feature all-target clippy and the final Linux
  all-target cross-check pass. The full workspace rerun remains pending.

The refreshed dependency audit and `cargo deny check` pass with the existing
allowed `proc-macro-error2` advisory RUSTSEC-2026-0173. `cargo machete` retains
the same six pre-existing findings: `anyhow`/`tracing` in mvm-capture, `tar` in
mvm-client, `etherparse` in mvm-hostd, `tempfile` in mvm-runtime-fuzz-backend and
`am-fs-core` in third_party/am-fs-ext4. No manifest or lockfile changed.

The earlier full workspace run failed in the unmodified network-endpoint
readiness test. Reproduction showed that an immediately closing peer can fail
while setting its socket timeout on macOS, before the attempted read. The test
now accepts either fail-closed error path; production behavior is unchanged.
The affected VMM suite above passes after that correction. An intermediate
backend run also caught a changed diagnostic prefix; the final passing suite
includes the corrected diagnostic.

## Remaining acceptance

Finish broad validation of no-egress and standby identity provisioning.
Bind the collector's owned endpoint and fresh session to authoritative VM,
boot and generation state. Wire bounded source capture, automatic loss summaries,
VM-lifetime supervision, host retention and retrieval. Reset producer epochs and
discard inherited telemetry state on restore. Then run the real-backend witness:
boot, detach the CLI, emit traces, stall collection, retrieve host records with
explicit loss evidence, and prove the workload continued progressing.

No related runtime issue is closed by this component validation. Public delivery
and merge-queue verification for this integration are still pending.
