# Receipt-attached resource utilization

Backing: shipped-source
Validation: check-sprint-append

## What shipped

A microVM run's signed execution receipt now carries measured CPU, memory,
host-side state growth, and wall-clock consumption alongside the admitted
ceiling, so the two become comparable inside one artifact.

- `mvm_core::usage_capture`: `Metric`, a sum type with exactly three
  constructors — `measured(value, mechanism)`, `guest_reported(value)`, and
  `unavailable()` — so no code path can stamp a guest self-report as a host
  measurement. `UsageCapture` (`cpu_ms`, `peak_rss_mib`, `host_state_bytes`,
  `wall_ms`, `guest_peak_rss_kib`) plus a `workload.usage` sidecar
  reader/writer mirroring the existing `exit_capture` convention, and the
  pure `host_state_bytes` / `wall_ms` helpers the host computes about itself.
  `Mechanism` lives in `mvm-contract` and is re-exported here.
- `ResourceObservation::for_backend` in `mvm-contract`, declaring what each
  `BackendKind` can honestly report, and a rewritten
  `xtask check-backend-resource-controls` that walks every `for_backend`
  block in the file rather than the first one it finds — the original
  first-match lookup would have left a second exhaustive matrix uninspected
  behind a green gate.
- `mvm_vmm::host::process_usage`: `peak_rss_mib_self`, `process_cpu_ms_self`,
  `child_cpu_ms`, the host-side readings every in-process-VMM backend uses.
- `ExitRecord` and a `usage` label on the chain-signed `plan.exited` audit
  entry, and `extensions["mvm.usage"]` on every `plan.exited` receipt — with
  every metric present as `unavailable` when nothing was observed, so "no
  usage evidence" is attested rather than left as an absent key.
- `report_exit` (`crates/mvm-client/src/launch/mod.rs`) reads the
  `workload.usage` sidecar and fills in the two dimensions the host observes
  about itself — `host_state_bytes` and `wall_ms` — unconditionally, on every
  backend, regardless of what that backend's own matrix cell declares. Those
  two questions need no VMM cooperation to answer.
- libkrun: `mvm_hostd::supervisor::self_usage::record_self_usage`, taken via
  an `atexit` handler because libkrun calls `exit()` from inside its own run
  loop when the guest powers off, so no ordinary statement after entering
  that loop runs.
- HVF: each vCPU thread publishes its own CPU time before it exits; the sum
  is taken after every thread has joined, so the total covers guest
  execution across every vCPU rather than one of an SMP guest.
- Firecracker and QEMU: no CPU, no memory. Neither VMM is a process we
  reap — Firecracker launches session-detached and is orphaned to init
  before the launch call returns, and QEMU daemonizes itself — so there is
  no `getrusage` to collect and no process of ours whose resident size
  describes the guest. The matrix declares `None` for both dimensions on
  both backends.

## Step 1 finding: the Wasm host-state cell was verified, not assumed

The design spec originally declared `host_state: HostStateObservation::None`
for `Wasm`, `WebLinux`, and `Mock` alike, flagged as the conservative guess.
Checked directly rather than left as written:

- **Wasm does keep a real host-side state directory.**
  `WasmBackend::start_with_mode` (`crates/mvm-runtime/src/wasm_backend.rs`)
  unconditionally calls `mvm_core::config::vm_state_dir(&config.name)` and,
  through `prepare_wasm_activation`
  (`crates/mvm-runtime/src/wasm_activation.rs`), writes
  `wasm-activation/activation.json` under it before the module runs. That
  directory is not cleaned up when the synchronous run finishes — only a
  spawned egress endpoint's own subdirectory is reaped inline
  (`reap_network_endpoint`) — so it is still there when `report_exit` takes
  its reading. The matrix cell is now
  `HostStateObservation::StateDirTreeBytes` for `Wasm`, split out of the
  combined arm it previously shared with `WebLinux`/`Mock`, with a new test
  (`the_wasm_tier_observes_its_activation_state_directory`) pinning it.
- **WebLinux and Mock do not.** `WebLinux` runs in a browser with no host
  process at all — grepping `vm_state_dir` in
  `crates/mvm-runtime/src/web_linux_backend.rs` returns nothing. `Mock`'s
  test fixture points `vm_state_dir` at a hardcoded, deliberately
  nonexistent path (`crates/mvm-runtime/src/mock.rs:614`). Both cells were
  left at `None`.

The design spec's coverage table
(`specs/2026-08-28-receipt-attached-resource-utilization.md`) and the
implementation plan's now-stale snippet
(`specs/plans/2026-08-28-receipt-attached-resource-utilization-implementation.md`)
were both updated to record this.

## Per-backend coverage as built

| Backend | CPU | Memory | Host state | Wall |
|---|---|---|---|---|
| `Hvf`, `AppleContainer` | `hvf_summed_vcpu_clock` (macOS only) | `host_process_rss` | `state_dir_tree_bytes` | `host_launch_span` |
| `Libkrun` | `host_process_cpu` | `host_process_rss` | `state_dir_tree_bytes` | `host_launch_span` |
| `Firecracker`, `Qemu` | unavailable | unavailable | `state_dir_tree_bytes` | `host_launch_span` |
| `Wasm` | unavailable | unavailable | `state_dir_tree_bytes` | `host_launch_span` |
| `WebLinux`, `Mock` | unavailable | unavailable | unavailable | `host_launch_span` |

## Limits, stated plainly

- **Firecracker — the Linux production backend — reports no CPU and no
  memory in this version.** Neither VMM process is ever reaped by `mvmctl`,
  so there is no `getrusage` call site and no resident-size reading that
  describes the guest rather than the launcher. A cgroup-based reading is a
  possible later refinement (the design doc notes `cpu.stat` as an optional
  extension) but nothing wires it today.
- **A host crash before teardown loses the reading, exactly as it loses the
  exit code.** The `workload.usage` sidecar is written at known checkpoints
  (self-measurement at process exit for libkrun, HVF vCPU thread join, and
  `report_exit`'s own host-side computation), not continuously. A host that
  dies before those points leaves `report_exit` reading an absent sidecar,
  which decodes as all-`unavailable` — the same honest-degradation path a
  backend that never learned to write one takes, never a fabricated zero.
- **libkrun's SIGTERM path (`mvmctl stop`) produces no reading.** libkrun's
  own signal handler calls `libc::_exit(143)`
  (`crates/deps/libkrun-sys/src/start.rs:308`), which — by design — skips
  `atexit`, so `record_self_usage`'s hook never fires on that path. Only the
  guest-initiated poweroff, the wall-clock-timer kill (exit 124), and a VMM
  error return through `main` reach the `atexit` trampoline.
- **No macOS PR lane exists, so the real-hardware HVF measurement is not
  gated on pull requests.** This repository's only macOS coverage is the
  nightly `ci-full.yml` cron; the HVF `SummedClock` path is otherwise
  unit-tested against a mock clock (`controller.rs`'s `FixedClock` /
  `MockHandle`).

## Verification

- `cargo fmt --all -- --check`: exit 0.
- `cargo nextest run --workspace`: 12714 passed (2 leaky), 1 failed, 22
  skipped. The one failure —
  `mvm-vmm host::linux_env::tests::dev_vm_connects_via_libkrun_per_port_socket`
  — is the documented pre-existing macOS failure; this branch touches no
  file in its path (`crates/mvm-vmm/src/host/linux_env.rs` is byte-identical
  to the merge base).
- `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets --
  -D warnings`, `just check-gated`: see task-10 report for exact counts.
- `cargo run -p xtask -- check-backend-resource-controls`,
  `check-claim-catalog`, `check-core-runtime-free`,
  `check-single-network-path`, `check-sprint-append`: all exit 0.

**Coverage finding, not routed around.** Task 6's
`mvm-client::launch::tests::an_exit_records_the_host_state_size_even_when_the_backend_measured_nothing`
lives in a module gated `#![cfg(feature = "test-support")]`, which is off by
`mvm-client`'s own default features — a gate that predates this plan (the
whole `launch/tests.rs` module has carried that `cfg` since #2155). It does
**not** run under plain `cargo nextest run --workspace`: the workspace run
reports exactly 196 `mvm-client` tests, the same count as a `-p mvm-client`
build with no extra feature, and no `launch::tests::*` line appears anywhere
in the 12,715-test log. It does run in CI, through the dedicated
`test-support feature tests (mock backend)` step in `.github/workflows/ci.yml`
(`cargo nextest run --features test-support --lib -p mvm-backends -p
mvm-runtime -p mvm-client -p mvm-cli -p mvm-vmm`) — a separate job, not
`cargo nextest run --workspace`. Task 8's three
`supervisor::self_usage::tests::*` — `a_state_dir_that_cannot_be_written_does_not_panic_the_teardown`,
`the_supervisor_claims_only_the_two_dimensions_it_observes`,
`the_supervisor_records_its_own_consumption_as_the_machines` — do run under
the plain workspace command, confirmed by name in the nextest log, because
`self_usage` is an unconditional module in `mvm-hostd`'s library rather than
feature-gated.
