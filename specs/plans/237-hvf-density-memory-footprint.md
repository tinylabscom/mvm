# Plan 237 - HVF density memory footprint reduction

**Status:** IN PROGRESS (Phase 0 first PR implemented; clean baseline pending)
**Created:** 2026-07-09
**Goal:** reduce the resident host footprint of idle HVF OCI microVMs enough
to make 100 to 500 concurrent lightweight sandboxes a planned operating mode,
not an accidental stress test.

## Baseline

The live test used the current `cargo run -- machine run --image
docker.io/library/alpine:latest -- sleep 240` path on macOS with HVF. The guest
RAM reservation is already demand-zero and does not fully materialize just
because a VM has a configured memory size. The remaining density problem is
resident host process memory and per-VM helper count.

Measured component RSS:

| Shape | Count | RSS |
| --- | ---: | ---: |
| Foreground `mvmctl` parent | 1 per VM | ~30.3 MiB |
| `mvm-substitution-endpoint` | 1 per VM | ~15.5 to 16.5 MiB |
| `mvm-hvf-supervisor` | 1 per VM | ~45.4 to 45.5 MiB |
| Shared host-agent pair | 2 per tenant | ~18 MiB total |

Measured 25-VM wave:

| Component | Count | Total RSS |
| --- | ---: | ---: |
| `mvmctl` parents | 25 | 747.1 MiB |
| HVF supervisors | 25 | 1110.7 MiB |
| substitution endpoints | 25 | 388.8 MiB |
| shared host-agent pair | 2 | 18.0 MiB |
| counted total | 77 | 2264.6 MiB |

Current extrapolation:

| Shape | Approx per VM | 500 VM estimate |
| --- | ---: | ---: |
| Current debug/foreground path | ~90.6 MiB | ~45 GiB |
| Runtime path without parent `mvmctl` | ~60 MiB | ~30 GiB |
| No-net path without endpoint | ~45 MiB | ~22 to 25 GiB |

The old raw-HVF memory issue is already mostly solved: the 2026-07-07 density
follow-up moved guest RAM to demand-zero memory and file-backed kernel mapping,
dropping the idle supervisor from a hundreds-of-MiB shape to the current
~45 MiB floor. This plan targets the remaining process and helper overhead.

## Non-goals

- Do not weaken the host-authority or vsock-only security model to improve a
  density number.
- Do not reintroduce a guest NIC, gvproxy, TAP bridge, or guest-directed
  arbitrary upstream socket path.
- Do not share raw secret material through one global helper to save memory.
- Do not hide footprint by only changing configured guest RAM. The primary
  acceptance metric is resident host memory during live waves.
- Do not claim 500-VM support until 100-VM and larger staged waves have cleanup,
  latency, and page-pressure evidence.

## Targets

- `cargo run -- machine run --image alpine -- ps aux` works from a clean or
  repairable OCI cache and remains the basic smoke command.
- A 25-VM no-network Alpine sleep wave has no foreground `mvmctl` parent
  retained per VM.
- A 25-VM no-network Alpine sleep wave does not spawn
  `mvm-substitution-endpoint` per VM when there are no secrets and no admitted
  egress authorities.
- Runtime-only no-network idle footprint is at or below 45 MiB per VM plus the
  shared per-tenant host-agent pair.
- 100 no-network idle VMs can run and tear down cleanly on a suitably sized
  macOS host without process leaks.
- 500 no-network idle VMs are either live-proven or refused with an explicit
  capacity reason based on measured resident memory and host pressure.

## Phase 0 - Reproducible baseline and cache repair

**Goal:** make the test reproducible before optimizing the process model.

- [x] Land the guest rootfs rematerialization fix for `mvm-oci-init` by using
  the target libc ioctl request type instead of a host-width `c_ulong` request
  value. Keep the regression test that proves the loopback ioctl request values
  are representable for the musl target.
- [x] Add a cache repair or cache-only rematerialization path for stale OCI
  image records whose unpacked layers are still present but whose rootfs output
  is missing. The operator should not need to manually delete or reconstruct
  private cache state to run `machine run --image alpine -- ps aux`.
- [x] Add a checked-in density measurement harness under `scripts/` that runs
  isolated wave sizes from `MVM_HVF_DENSITY_WAVES`; the first-PR default is
  1, 5, 10, and 25 VMs, with 50 and 100 supported by override once the host is
  clean enough for larger waves.
- [x] The harness records process counts, per-component RSS, `vm_stat`, VM
  names, launch failures, and cleanup results into `/tmp/` or an explicit
  artifact directory outside the repository.
- [ ] Commit a baseline report under `specs/perf/plan-237/` only after the
  harness itself exists and the run was captured from a clean, documented host
  state.

**2026-07-10 first-PR implementation note**

- The shared guest network helper used by `mvm-oci-init` now casts ioctl
  request constants through the target `libc::Ioctl` type, with a regression
  test pinning target representability for `aarch64-unknown-linux-musl`.
- `machine run --image ...` can repair stale cached OCI image records by
  re-materializing the ext4 rootfs from the existing unpacked layer tree when
  the cached rootfs output is missing, without requiring the operator to delete
  private cache state.
- `scripts/measure-hvf-density.sh` captures reproducible HVF density artifacts
  outside the repository and preserves the current foreground process shape for
  Phase 0 measurement.
- Clean baseline publication remains open. The live host had unrelated HVF
  runtime processes and long-running build work, which triggers this plan's
  density-run stop condition. A warm-cache one-VM harness run completed with
  cleanup verified, but the full 1/5/10/25 harness run failed at wave 1 with
  `substitution endpoint closed stdout without a ready handshake` and no
  matching Plan 237 processes left after cleanup.

**2026-07-11 validation follow-up**

- Fresh worktree validation is green for the required target
  `mvm-oci-init` zigbuild, the full `mvm-guest` test suite, and the focused
  `mvm-cli` stale-cache/rematerialization tests.
- The live Alpine smoke command completed successfully from isolated `/tmp`
  state after seeding the isolated cache with the already-built workload
  kernel; the v0.17.0 release checksum asset was still missing, so an unseeded
  cold cache refused the hash-verified kernel download before boot.
- The density harness now fails fast when generated HVF agent socket paths
  would exceed the macOS Unix socket limit. This prevents a long artifact/data
  directory from spending minutes on prepull/build and then producing
  misleading guest-agent launch failures.
- The density harness also refuses active local build/runtime contamination by
  default, recording the matching processes before any prepull/build work. The
  guard can be bypassed with `MVM_HVF_DENSITY_ALLOW_BUSY_HOST=1`, but bypassed
  runs are not acceptable as clean baseline evidence.
- Clean baseline publication remains open. A long-path 1/5/10/25 attempt
  proved cleanup for waves 1, 5, 10, and the failed wave 25, but wave 25 had
  guest-agent socket path failures and could not be used as clean evidence. A
  short-path rerun was aborted before measurement because unrelated Rust builds
  started during prepull, again triggering the density-run stop condition. A
  follow-up attempt on the rebased branch was refused by the new preflight
  because unrelated `cargo`/`rustc`/`clang` work was still active on the host.

**Validation**

- `cargo zigbuild --release --target aarch64-unknown-linux-musl -p mvm-guest --bin mvm-oci-init`
- `cargo test -p mvm-guest`
- Targeted `mvm-cli` tests for cache repair and stale image records.
- Live smoke: `cargo run -- machine run --image docker.io/library/alpine:latest -- ps aux`
- Live density: 1, 5, 10, and 25 VM waves with cleanup verified.

## Phase 1 - Remove retained foreground CLI parents

**Goal:** make the long-lived density shape look like runtime infrastructure,
not one resident `mvmctl` process per VM.

Current foreground `machine run` retains a parent `mvmctl` process while the
guest command runs. That is useful for interactive or attached transient
commands, but it costs about 30 MiB per idle VM in the density test.

- [ ] Audit `crates/mvm-cli/src/commands/machine/runtime.rs` and
  `crates/mvm-cli/src/commands/vm/up.rs` for the exact lifecycle split between
  foreground transient runs, persistent starts, `--detach`, and `--up-json`.
- [ ] Make the documented long-lived density path use a detached persistent
  machine lifecycle: start, record machine state, return the CLI process, and
  let `machine stop` own teardown.
- [ ] If `machine run -d --image ... -- <cmd>` is intended to be the density
  surface, update `run_persistent_post_start` so the CLI exits after the
  persistent boot and command dispatch contract is complete.
- [ ] If detached command execution cannot be made semantically clean without a
  separate guest-side process supervisor, document that high-density runs use
  `machine create`, `machine start`, `machine exec`, and `machine stop` rather
  than foreground `machine run`.
- [ ] Add parser and lifecycle tests proving `--detach` and `--up-json` do not
  retain the parent process on the persistent path.
- [ ] Update the CLI reference if any command semantics or recommended density
  workflow changes.

**Validation**

- Targeted `mvm-cli` machine lifecycle tests.
- Live 25-VM no-network wave where `pgrep -fl mvmctl` shows no per-VM retained
  parent after startup settles.
- New per-VM target after this phase: about 60 MiB before endpoint work.

## Phase 2 - Skip per-VM endpoint for deny-all/no-secret workloads

**Goal:** avoid spending about 15 to 16 MiB per VM on a substitution endpoint
when the admitted plan has no egress or secret authority to enforce.

`crates/mvm-backend/src/hvf_backend.rs` currently starts
`mvm-substitution-endpoint` for HVF workloads as the egress gate. That is the
right fail-closed shape for admitted egress and secret flows, but a deny-all
Alpine sleep workload does not need an endpoint if the supervisor and guest
receive no relay socket and no egress token.

- [ ] Introduce one explicit endpoint-admission decision in the HVF backend:
  spawn the endpoint only when admitted network policy, destination-bound
  secret egress, or another host authority requires it.
- [ ] Keep endpoint-on as the conservative default for any ambiguous policy
  state. Only the fully deny-all/no-secret/no-network shape may skip it.
- [ ] Thread the no-endpoint state through the HVF supervisor config so the
  guest cannot dial a stale relay socket or infer an egress authority.
- [ ] Add backend unit tests covering the decision matrix:
  deny-all/no-secret skips endpoint; admitted egress spawns endpoint; secret
  authority spawns endpoint; ambiguous policy spawns endpoint.
- [ ] Add a live negative smoke proving a no-endpoint guest cannot make an
  outbound connection through the host-vsock proxy path.
- [ ] Keep `crates/mvm-backend/src/substitution_spawn.rs` as the only spawn and
  reap implementation for endpoint-enabled cases.

**Validation**

- `cargo test -p mvm-backend hvf` focused tests for endpoint admission.
- Live `machine run --image alpine -- ps aux` still succeeds without network.
- Live no-network 25-VM wave shows zero `mvm-substitution-endpoint` processes
  for those VMs.
- Live admitted-egress smoke still shows the endpoint and proves policy-gated
  egress works.
- New per-VM target after this phase: about 45 MiB runtime-only.

## Phase 3 - Release-profile and supervisor floor audit

**Goal:** determine whether the remaining ~45 MiB supervisor RSS is real HVF
runtime floor or avoidable eager allocation.

- [ ] Run the same density harness against release-built `mvmctl`,
  `mvm-hvf-supervisor`, `mvm-substitution-endpoint`, and the host-agent helper
  pair.
- [ ] Record debug vs release deltas for 1, 10, 25, and 100 no-network VMs.
- [ ] Profile one and ten idle supervisors with `vmmap`, `sample`, thread
  counts, mapped file inventory, and allocator statistics where available.
- [ ] Inspect for duplicated per-VM buffers, excessive thread stacks, eager
  Tokio runtimes, copied kernel/rootfs data, and avoidable logging or tracing
  state.
- [ ] Apply only profile-backed reductions. If the supervisor floor is mostly
  HVF mappings and essential runtime state, record it as the admission floor
  rather than guessing at micro-optimizations.
- [ ] Consider release settings such as stripping symbols, LTO, or panic abort
  only after measuring binary and RSS impact and documenting debugging tradeoffs.

**Validation**

- Release 25-VM and 100-VM wave reports under `specs/perf/plan-237/`.
- Component RSS table for debug and release binaries.
- Any supervisor code change has focused tests plus live before/after numbers.

## Phase 4 - Capacity model and product guardrails

**Goal:** make the product honest about how many VMs a host can run.

- [ ] Add or update a memory budget model that uses measured resident classes:
  foreground/transient, detached no-network, detached admitted-egress, and
  shared per-tenant host-agent overhead.
- [ ] Add a user-facing preflight or doctor surface that estimates whether a
  requested VM count is safe on the current host.
- [ ] Refuse or warn before large waves when host free memory, compressor
  pressure, pageouts, or configured safety margin make the request unsafe.
- [ ] Report the exact reason when 500 VMs are not admitted, for example:
  requested count, estimated resident memory, available headroom, and the
  footprint class used.
- [ ] Document the density operating modes and the difference between
  configured guest memory and resident host memory.

**Validation**

- Unit tests for the memory budget model and boundary decisions.
- CLI tests for preflight output and refusal messages.
- Live 100-VM admitted run or honest refusal based on the model.
- Optional 250 and 500 VM runs only after 100 is stable and cleanup is leak-free.

## Stop conditions for live density runs

- Any VM launch failure that leaves a supervisor, endpoint, host-agent
  registration, socket, or machine state behind.
- Sustained pageouts or compressor growth that would make the host unreliable.
- Per-VM RSS exceeding the phase target by more than 10 percent after the wave
  has settled.
- More than one unrelated worktree or long-running build active on the same
  host during the measurement.
- A denied-egress test unexpectedly succeeds.

## First PR sequence

1. Rootfs rematerialization and measurement harness only. No process-model
   optimization in this PR.
2. Detached persistent lifecycle so density runs do not retain one foreground
   `mvmctl` parent per VM.
3. Deny-all/no-secret endpoint admission so no-network VMs skip
   `mvm-substitution-endpoint` while admitted-egress VMs still spawn it.
4. Release-profile and supervisor floor reductions backed by `vmmap` and wave
   data.
5. Capacity preflight and documentation for 100, 250, and 500 VM operating
   modes.

## Completion criteria

- The basic smoke command `cargo run -- machine run --image alpine -- ps aux`
  works without manual cache surgery.
- A no-network 25-VM wave settles at or below 45 MiB runtime-only RSS per VM
  plus the shared host-agent pair.
- A no-network 100-VM wave starts, idles, and tears down without leaked
  processes or state.
- Admitted-egress and secret-authority workloads still spawn the endpoint and
  pass their security tests.
- 500 VMs are either live-proven on an appropriately sized host or refused by
  an explicit measured capacity model.
- CLI reference and density documentation match the shipped behavior.
