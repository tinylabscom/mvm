# Receipt-attached resource utilization

Status: design, approved for planning
Date: 2026-08-28

## Problem

An `ExecutionReceipt` records what a workload was *authorized* to do and how
it ended, but nothing about what it *consumed*. A verifier can prove a run was
admitted under a signed plan, that its egress was default-deny, and that it
exited with code 0 — and still cannot answer "how much CPU, memory, or disk did
this microVM use". Preview claim 18 bounds consumption at admission and, where
a mechanism exists, at spawn; there is no attested record of the consumption
itself, so the admitted ceiling and the actual usage cannot be compared inside
a single artifact.

The measurement primitives largely exist. They are scattered across crates,
serve unrelated purposes, and none of them reaches a receipt:

| Dimension | What exists today | Where |
|---|---|---|
| CPU | `QuotaAchievement { measured_cpu, measured_wall, periods }`, produced only when a CPU grant exists on HVF | `crates/mvm-vmm/src/quota/controller.rs:19` |
| CPU | `SummedClock::consumed()` over vCPU thread clocks, usable standalone | `crates/mvm-vmm/src/quota/clock.rs` |
| CPU | systemd transient scope created for a share grant; `cpu.max` read back for the enforced tier, `cpu.stat` never read | `crates/mvm-core/src/cpu_scope.rs` |
| Memory | `MemoryCharge { observed_restore_rss_mib, observed_idle_rss_mib, observed_peak_rss_mib, dirty_private_mib }`, consumed only by warm-pool packing | `crates/mvm-core/src/memory_budget.rs:13` |
| Disk | `disk_usage::tree_bytes` | `crates/mvm-core/src/disk_usage.rs` |
| Guest-side | `duration_ms` + `peak_rss_kib` via `getrusage`, per exec | `crates/mvm-agentd/src/bin/mvm-guest-agent/interactive.rs:196` |
| GPU | nothing | — |

## Decisions

1. **Usage lives in the signed receipt payload**, not in an unsigned sidecar.
   Host-attested, content-addressed, chain-linked, offline-verifiable. The cost
   is accepted: these become wire-stable fields, and a measurement that cannot
   be taken must be represented honestly rather than omitted.
2. **Terminal totals only, on `plan.exited`.** No periodic usage receipt and no
   capture at checkpoint or fork boundaries in this version. A running VM has no
   usage receipt; a host crash before teardown loses the numbers, exactly as it
   loses the exit code today.
3. **Explicit per-field provenance.** A metric the host could not observe is
   recorded as unobservable, never as absent and never as zero.
4. **Only host-side observations may be stamped `measured`.** The guest is
   untrusted, so a guest self-report carries a distinct source label that no
   consumer can conflate with a host observation.
5. **No ADR-001 claim number.** This is evidence, not enforcement. The claims
   ledger and Preview claim 18's row are untouched. The feature strengthens
   Preview 18 indirectly by making the admitted ceiling and the measured
   consumption comparable within one signed artifact.

## Why this is not an extension

The optional-extension architecture is directly relevant, and it argues against
building usage measurement on top of itself.

`mvm.extension-pack/v1` mounts a signed executable read-only into the **guest**
and dispatches it through `run-extension` guest verbs. A guest-side extension
measuring its own VM produces a self-report by construction — the weakest form
of this feature, and precisely what decision 4 exists to keep separable.

The MVEX provider boundary (`crates/mvm-hostd/src/bin/mvm-extension-provider.rs`,
`crates/mvm-contract/src/protocol/extension_controller.rs`) points the other
way: it is MVM serving an external controller that asks MVM to run admitted
work. Usage capture is not a service offered to a caller; it is an observation
MVM makes about its own VMM process at teardown, when no caller is present.

Decisively, the assurance bridge already settled this question. Per
`specs/sprint/delivery/assurance-generic-extension-bridge.md`: the typed host
broker is the observer evidence source, and "neither the extension nor its
candidate response can set the observation or references"; cleanup evidence
"likewise cannot be asserted by the extension or controller". The rule is that
an extension may produce a *candidate* while only MVM produces *evidence*.
Usage integers in a signed receipt are evidence.

A mechanical constraint underlies the principle: summed vCPU time needs the
`VcpuHandle`s that live in-process in the supervisor, cgroup usage needs the
scope unit MVM created, and RSS needs the VMM pid. Handing those to a
third-party binary hands over the process moat that `mvm-hostd`'s separate
`[[bin]]`s exist to maintain.

The legitimate external surface is downstream consumption — rating, billing,
chargeback, capacity planning — as pure functions over already-signed receipts,
requiring no new privilege and unable to corrupt the evidence. Emitting clean
signed integers is what makes that surface possible.

### Named future extension point: GPU

Vendor GPU telemetry is the one dimension where a provider boundary earns its
place, because linking vendor libraries into `mvmctl`'s closure is undesirable.
The shape is fixed now and built later: the provider supplies a *reading*, MVM
stamps the provenance, and the reading carries a fourth source value
`provider_reported`, held distinct from `measured`. The `mechanism` field
defined below is what allows this to be added without a schema break. Nothing
in this version emits a GPU field; a schema slot that nothing writes reads as
capability and is not created.

## Architecture

### A control is not an observation

`ResourceControls::for_backend`
(`crates/mvm-contract/src/protocol/resource_controls.rs:71`) answers whether a
backend can *bound* a dimension. Usage needs a second, different question:
whether it can *observe* one. The two do not coincide — Firecracker on macOS
has `CpuControl::None` yet its VMM process RSS is observable, and HVF can
measure CPU with no quota grant at all.

This adds a sibling `ResourceObservation::for_backend(kind)` in the same
module, under the same exhaustive-match discipline, gated by the same xtask
check that forbids a wildcard arm.

### Data flow

Every observation is host-side; the guest can forge none of it.

1. **During the run**, the process owning the VM accumulates observations.
   - *HVF / AppleContainer*: `SummedClock::new(clocks).consumed()`. Today the
     clock is constructed only inside the `cpu_millicores.and_then(...)` arm at
     `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs:2013`, so CPU is
     measured only when a grant exists. The clock is hoisted out of that arm:
     the controller stays grant-gated, the measurement stops being.
   - *Libkrun*: the VMM is in-process in `mvm-libkrun-supervisor`, so the
     supervisor reads its own `/proc/self/stat` on Linux or Mach task info on
     macOS.
   - *Firecracker / Qemu*: the VMM is a child process; `wait4`/`getrusage` on
     that child before reaping.
   - *Memory, all native tiers*: host RSS high-water of the VMM process — on
     the in-process tiers, of the supervisor itself. The same measurement
     `memory_budget::MemoryCharge` already consumes. The kernel keeps the
     high-water mark, so this needs no sampling during the run: `VmHWM` from
     `/proc/<pid>/status` on Linux, `resident_size_max` from
     `mach_task_basic_info` on macOS.
   - *Host state bytes*: `disk_usage::tree_bytes(vm_state_dir)` at teardown.
   - *Wall*: the span between launch and teardown as the host observed it.
     Available on every native tier because it needs no cooperation from the
     VMM. It duplicates what `started_at` and `ended_at` already carry, and is
     recorded anyway so that `mvm.usage` is uniform and self-contained rather
     than requiring a consumer to mix provenance-carrying and bare fields.
2. **At teardown**, the owner writes `<vm_state_dir>/workload.usage`, a direct
   sibling of `workload.exit`. A new `mvm_core::usage_capture` module mirrors
   `mvm_core::exit_capture` — shared file-name constant, path function, reader,
   and writer — so the HVF supervisor, the libkrun supervisor, and the
   in-process Firecracker driver all write it identically. Best-effort, exactly
   as `exit_capture` is: a failure leaves no file.
3. **`report_exit`** (`crates/mvm-client/src/launch/mod.rs:971`) reads it
   immediately after the existing `exit_capture::read_captured` call. This is
   the only production `plan.exited` emission site.
4. **`emit_exited_with_capture`**
   (`crates/mvm-hostd/src/audit/emitter.rs:1062`) writes `usage.*` label pairs
   into the chain-signed `plan.exited` entry.
5. **`audit_entry_to_receipt`**
   (`crates/mvm-hostd/src/audit/receipt_export.rs:54`) folds those labels into
   `extensions["mvm.usage"]`.

Receipts are derived from audit entries rather than emitted directly, so the
numbers are attested twice: once by the audit chain's signature and once by the
receipt's.

### Signature change

`emit_exited_with_capture(plan, exit_code, backend)` reaches four positional
arguments with usage added, and will grow again when GPU lands. Per the
repository's params-struct rule it takes an `ExitRecord { exit_code, backend,
usage }` instead.

## Receipt schema

Integers only, ASCII only: `validate_value_space`
(`crates/mvm-core/src/receipt.rs:329`) rejects floats and non-ASCII strings, so
there are no percentages, no ratios, and no fractional seconds anywhere in this
extension.

```json
"extensions": {
  "mvm.usage": {
    "cpu_ms":             { "value": 4210,     "source": "measured", "mechanism": "hvf_summed_vcpu_clock" },
    "peak_rss_mib":       { "value": 312,      "source": "measured", "mechanism": "host_process_rss" },
    "host_state_bytes":   { "value": 91234304, "source": "measured", "mechanism": "state_dir_tree_bytes" },
    "wall_ms":            { "value": 61004,    "source": "measured", "mechanism": "host_launch_span" },
    "guest_peak_rss_kib": { "value": 204800,   "source": "guest_reported" }
  }
}
```

**Encoding rules.**

- The metric key is *always present*. Its presence means the metric was
  considered.
- `value` is present only when `source` is `measured`. An unobservable metric
  is written `{ "source": "unavailable" }`, with no number to misread.
- `mechanism` accompanies every `measured` value and names *how* it was
  observed. This is load-bearing rather than decorative: a guest-vCPU time and
  a VMM-process total are different quantities, and without the mechanism they
  would be silently incomparable under one `cpu_ms` key.
- `guest_reported` exists solely for the guest agent's `getrusage`
  `peak_rss_kib` and carries no `mechanism`. It is a distinct source from
  `measured` so that no consumer can conflate an untrusted self-report with a
  host observation.
- `host_state_bytes` is named for what it measures — host-side state-directory
  growth, which is overlay and copy-on-write growth — so it cannot be read as
  guest filesystem consumption.
- No separate schema version. The receipt carries `schema_version`, extensions
  are namespaced, and unknown keys are preserved by verifiers.

**Illegal states are unrepresentable.** The metric type exposes only
`Metric::measured(value, mechanism)`, `Metric::guest_reported(value)`, and
`Metric::unavailable()`. No code path can stamp a guest self-report as
`measured`.

## Per-backend observation coverage

CPU is measurable on every native tier without cgroups. `bind_cpu_grant` leaves
the spawn untouched when no share grant is present
(`crates/mvm-core/src/cpu_scope.rs:780`), so on Linux no grant means no
transient scope and therefore no cgroup to read. `/proc/self/stat` and
`getrusage` need no systemd, no session bus, and no grant. Cgroup `cpu.stat` is
therefore an optional later refinement, not the foundation.

| Backend | CPU | Memory | Host state | Wall |
|---|---|---|---|---|
| `Hvf`, `AppleContainer` | `hvf_summed_vcpu_clock` — guest vCPU time only, excluding host-side device emulation | `host_process_rss` | `state_dir_tree_bytes` | `host_launch_span` |
| `Libkrun` | `host_process_cpu` — process total: guest execution plus VMM overhead, vsock pumping, device emulation | `host_process_rss` | `state_dir_tree_bytes` | `host_launch_span` |
| `Firecracker`, `Qemu` | `host_child_rusage` — process total, same caveat | `host_process_rss` | `state_dir_tree_bytes` | `host_launch_span` |
| `Wasm`, `WebLinux`, `Mock` | unavailable | unavailable | unavailable | `host_launch_span` |

Wall is `host_launch_span` on every tier including the non-VM ones, because it
measures the host's own observation of the run rather than anything the backend
reports. Note that it is *not* the supervisor's wall-clock enforcement timer:
that timer exists only on libkrun and HVF, bounds the run, and is a control
rather than an observation.

Wasm reports no CPU because its fuel counter is declared and unwired; claiming
a fuel-derived `cpu_ms` would assert a measurement that does not happen.
WebLinux runs in a browser with no host VMM process to observe.

## Testing and gates

- **`usage_capture` roundtrip**, mirroring `exit_capture`'s tests: an absent
  file and a malformed file both yield all-`unavailable`, never zero.
- **A run that captured nothing still emits `mvm.usage`** with every metric
  `unavailable`, so "this run produced no usage evidence" is attested rather
  than inferred from an absent key. This is the capture-fidelity idiom
  `emit_exited_with_capture` already applies to a missing exit code.
- **Value-space guard**: a float inside `mvm.usage` is rejected by
  `validate_value_space`, pinning the no-percentages rule against a later
  `cpu_percent` field that would break every verifier.
- **Tamper detection**: flipping a usage integer breaks `verify_id` and the
  receipt signature.
- **Source separation**: no constructor exists that stamps a guest-reported
  value as `measured`.
- **Exhaustiveness gate**: `xtask/src/check_backend_resource_controls.rs` is
  extended to forbid a wildcard arm in `ResourceObservation::for_backend`, so a
  new `BackendKind` is a gate failure until it answers what it can observe.

**Coverage limit, stated rather than discovered.** The HVF `SummedClock` path
can only be unit-tested against a mock clock; `controller.rs` already provides
`FixedClock` and `MockHandle` for this. This repository has no macOS PR lane —
its only macOS coverage is the nightly extended workflow — so real-hardware HVF
measurement is not gated on pull requests.

## Out of scope

- Periodic or sampled usage receipts.
- Usage capture at checkpoint, restore, or fork boundaries, and any decision
  about how a warm-forked child's consumption is attributed to its parent.
- Any GPU field.
- Cgroup `cpu.stat` refinement on Linux.
- A CLI surface for reading usage back; receipts are already exportable and
  offline-verifiable.
- Billing, rating, or chargeback, which belong downstream of the signed
  receipt.
