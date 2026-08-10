# Plan 308 — Workload grants: one declaration, per-backend enforcement

**Status: OPEN — no workstream started**

## Why

A workload's permitted resource and reach is expressible today, but through
four unrelated mechanisms that share no vocabulary, disagree on units, and
enforce unevenly. One of the three dimensions users ask for first — CPU — is
not enforced at all.

The concrete state:

| Dimension | Declared where | Enforced |
| --- | --- | --- |
| Outbound destinations | `NetworkPolicy` | Yes — `EgressGate`, L4 host+port, every workload backend |
| Guest RAM | `Resources.mem_mib` | Yes, by construction — the VMM fixes guest RAM at creation |
| CPU | `Resources.cpus` (vCPU count) | **No** — vCPU count bounds parallelism, not share of host CPU |
| Wall clock | `Resources.timeouts.exec_secs` | **No** — synthesized into every signed plan, no enforcement site exists |
| Host services | `ExecutionPlan.services` | Yes — binding-gated broker dispatch |
| Host oversubscription | nowhere | **No** — nothing refuses the eleventh 4 GiB VM on a 32 GiB host |

`exec_secs` is the sharpest instance of the general problem. Its doc comment
in `crates/mvm-contract/src/plan/types.rs` reads "0 = unbounded (only
permitted for sleep-waking instances; supervisor enforces)". Searching the
tree for `exec_secs` returns synthesis, test fixtures, and nothing else.
It is a signed field asserting an enforcement that does not exist.

Four types also disagree about what a resource is:

| Where | Shape |
| --- | --- |
| Workload IR (`ir/workload.rs:722`) | `Resources { cpu_cores: u16, memory_mb: u32, rootfs_size_mb: u32 }` |
| Signed plan (`plan/types.rs:373`) | `Resources { cpus: u32, mem_mib: u64, disk_mib: u64, timeouts }` |
| Client DTO (`client/dto.rs:55`) | `MachineSpec { name, image, cpus, memory_mib, env }` |
| CLI | `MachineSpec { cpus: u32, memory: String }` |

The DTO row is why the in-process library path cannot express an outbound
allowlist: `MvmClient::run_machine` takes a `MachineSpec` with no network
field. The SDKs' `.allow_host()` works only because every SDK — Rust,
Python, TypeScript — is an argv builder that shells out to `mvmctl`.

## What already exists, and is therefore not redone here

- `VmBackend::negotiate(&RequiredCapabilities) -> Result<(), Vec<CapabilityGap>>`
  (`crates/mvm-core/src/protocol/vm_backend.rs:349`, landed #2248) — a typed
  refusal that names a substitute or names why there is none.
- `CapabilityAlternative` / `resolve` over `(capability, backend)`
  (`crates/mvm-contract/src/protocol/capability_negotiation.rs`) — a closed
  enum resolved by an exhaustive match, so a new capability or backend must
  be answered explicitly.
- `MvmClient::backend_capabilities() -> BackendCapabilityReport` (#2259) —
  the library's capability-discovery surface.
- `EgressGate::from_network_policy` — fails closed to default-deny on any
  projection error.
- `egress_enforcement_label` (`commands/shared/resolve.rs:192`) — the
  precedent for recording what a substrate *actually* enforced, so a receipt
  never overstates a requested policy.
- `xtask gen-ir-parity` / `check-ir-parity` — executes a shared declaration
  through the Python and TypeScript SDKs and rejects cross-language drift.

## The model

### `Grants`

A workload's permission set, in `mvm-contract` (`no_std` + alloc, because it
sits inside the signed `ExecutionPlan` payload).

Named `Grants`, not `Capabilities`: `VmCapabilities` already means "what a
VMM backend supports", and `capability` additionally collides with Linux
`capabilities(7)`, which this project drops via bounding-set.

Two tiers of dimension, and the distinction is the plan's spine:

**Already governed — `Grants` becomes the declaration, existing types remain
the enforcement.** `egress` (→ `NetworkPolicy`), `host_services` (→
`ExecutionPlan.services`), `filesystem` (→ `Mount`/`Volume`), `syscalls` (→
seccomp tier), `guest_verbs` (→ agent grants).

**Ungoverned — the new enforcement work.** `cpu`, `wall_clock`, and
host-level admission budget.

`memory.max` and `pids.max` are deliberately excluded. A microVM is already
a resource sandbox in a way a container is not: guest RAM is fixed at VM
creation on every workload backend, so a guest cannot address more, and
processes inside the guest are the guest kernel's problem, bounded by that
same fixed RAM. A host-side pid cap would bound VMM threads, roughly the
vCPU count, which is already bounded. The residual exposure is VMM
host-side overhead beyond guest RAM — modest, and not worth new
privileged-adjacent code plus OOM-kill semantics that convert a
memory-hungry workload into an opaque VMM crash. If fleet telemetry later
shows overhead mattering, `memory.max` slots into the same cgroup writer.

The wasm tier is the exception, and WS5 treats it accordingly: a wasm linear
memory grows on demand, so it has none of the fixed-allocation property a
microVM gets for free. `StoreLimits` is what gives the wasm tier the bound
the VM tiers already have — not an extra control the VM tiers are missing.

### CPU is two units, not one

`CpuGrant` is an enum, because the backends do not share a unit:

- `Share(f32)` — cores-equivalent, mapped to cgroup v2 `cpu.max` as
  `<quota_us> <period_us>`.
- `Fuel(u64)` — a deterministic wasmtime instruction budget.

These are not inter-convertible and no conversion is offered. A `Share`
grant on the wasm backend resolves through `negotiate()` to a
`CapabilityGap` naming `Fuel` as the substitute, via a new
`CapabilityAlternative` variant. Deterministic fuel is reproducible across
hosts in a way no VM-tier CPU bound is; the docs must say so, because users
will assume the VM tier is the stronger one.

### Precedence

Highest first: CLI flag → explicit JSON → manifest (`Mvmfile.toml`) →
`~/.mvm/config` defaults → built-in default. One resolver function, replacing
the per-field `or_else` chains in `into_spec`.

Resolution happens **before** plan synthesis, so the resolved `Grants` is
inside the signature. Enforcement happens **below** the signature, in the
supervisor.

Two defaults that are decisions rather than accidents:

- **Absent CPU grant = no cap**, not deny-by-default. Deny-by-default on a
  resource dimension means zero CPU, which is incoherent. Egress keeps its
  deny-all default; claim 10 is unchanged.
- **`--prod` requires an explicit `wall_clock` grant**, and refuses any grant
  that is *present but unenforceable* on the resolved backend. It does not
  mandate a `cpu` grant: macOS cannot enforce CPU share, so requiring one
  would make `--prod` unbootable on that tier rather than merely uncapped.
  `wall_clock` is the mandated dimension because it is the one enforceable
  everywhere. This mirrors `--prod`'s existing refusal of mutable OCI
  references.

Cross-tenant budgets stay in mvmd. This plan bounds one VM; fleet-wide quota
is orchestration, consistent with the `--prod` gate living there.

### Per-backend mechanism

| Dimension | Firecracker / libkrun / QEMU (Linux) | HVF (macOS) | wasm (wasmtime) |
| --- | --- | --- | --- |
| CPU | cgroup v2 `cpu.max` on the per-VM supervisor process | none — declared vCPU count | `consume_fuel` + `Store::set_fuel` |
| Memory | fixed guest RAM by construction | fixed guest RAM by construction | `StoreLimits` memory cap |
| Wall clock | supervisor timer | supervisor timer | `epoch_interruption` + deadline |
| Egress | `EgressGate` over vsock | `EgressGate` over vsock | `mvm:egress` host import |

libkrun and HVF are in-process VMMs, but each runs under its own per-VM
supervisor binary (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`), so a
cgroup on that process is correctly per-VM.

macOS has no cgroup equivalent. Thread QoS affects scheduling *priority*,
not quota — a hint, not a limit — so it is not claimed. The tier is
`declared:vcpu-count`, stated plainly.

The wasm backend today constructs `Engine::default()` and `Store::new(...)`
and reports `cpus: 0, memory_mib: 0`. Fuel, epoch interruption, and
`StoreLimits` are all available and all off. Its egress is meanwhile the
best-behaved of any backend: the `mvm:egress` host import already fails
closed with `NoEndpointConfigured`. This is the tier where enforcement is
cheapest and most rigorous, not the one where it is hardest.

## Workstreams

- [ ] **WS1 — The `Grants` type and one resolver.**
      `Grants` in `mvm-contract`, serde + `schemars` behind the existing
      `schema` feature. Added to `ExecutionPlan` as
      `Option<Grants>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`
      — the `environment` field's comment states why: the field is inside
      the signed payload, so emitting `null` invalidates every existing
      signature and frozen vector. One resolver implementing the precedence
      chain above. No enforcement change; `Grants` projects down to the
      existing `NetworkPolicy` / `Resources` / `services` types.

- [ ] **WS2 — Projection is single and fails closed.**
      `network_policy` is *derived* from `Grants`, never supplied alongside
      it; admission re-derives and refuses on disagreement, the same shape as
      the existing `l3_network` / `network_mode` refusal. Any projection
      error yields deny-all, matching `EgressGate::from_network_policy`. New
      `xtask check-single-grants-projection` asserts exactly one
      Grants→`NetworkPolicy` projection function exists, in the spirit of
      `check-uniform-vsock-egress`.

- [ ] **WS3 — The backend seam.**
      `VmCapabilities` gains a `resource_controls` field declaring which
      `CpuGrant` variants and which dimensions a backend can serve.
      `VmBackend` gains `apply_grants(&self, id: &VmId, grants: &Grants) ->
      Result<EnforcedGrants>`, defaulting to the `declared` tier so `mock`
      and any future backend are honest rather than silently ignoring
      grants. `EnforcedGrants` is the **read-back** result — cgroup file
      re-read, fuel confirmed set — and is what feeds the receipt label. A
      new `CapabilityAlternative` variant carries the `Share`→`Fuel`
      substitution. New `xtask check-backend-resource-controls` asserts every
      `BackendKind` declares its controls explicitly.

- [ ] **WS4 — Linux CPU quota, wall clock, admission budget.**
      cgroup v2 `cpu.max` via unprivileged user delegation under
      `user@$UID.service` — no `sudo`. Cgroup leaf name derives from the
      validated machine ID, never a user-supplied string; the delegated
      subtree is opened once `O_DIRECTORY` with `openat`-relative writes.
      Supervisor-side `exec_secs` timer whose kill is emitted to the audit
      chain, so an enforced timeout is distinguishable from a crash.
      Admission-time host budget summing committed CPU and memory across
      running machines from the existing inventory, refusing a boot that
      would oversubscribe past a headroom configured in `~/.mvm/config`
      through the existing `user_config` key mechanism.

- [ ] **WS5 — wasm enforcement.**
      `Config::consume_fuel` + `Store::set_fuel` for `CpuGrant::Fuel`;
      `StoreLimits` wired into the `Store` for memory; `epoch_interruption`
      + deadline for wall clock. `VmInfo` stops reporting `cpus: 0,
      memory_mib: 0` and reports the enforced grant. Accepts fuel-accounting
      overhead as the cost of a deterministic bound.

- [ ] **WS6 — The four surfaces.**
      Manifest: `[grants]` table extending `ManifestMachineWorkflow`.
      JSON: `--grants-file`, schema emission through the existing
      `emit_workload_schema` path, `machine inspect --json` round-tripping
      the resolved set. CLI: existing flags preserved as sugar resolving into
      `Grants`, plus `--cpu-limit` (host share — distinct from `--cpus`,
      which is vCPU count and guest-visible topology) and `--timeout`.
      Library: `grants` field on the `MachineSpec` DTO and its builder, so
      `MvmClient::run_machine` needs no `mvmctl` on `PATH`; `resource_controls`
      added to `BackendCapabilityReport`. SDKs: grants added to the
      `check-ir-parity` fixture, so a grant added to Rust but not Python
      fails the build.

## Security analysis

Net positive. Guest→host resource exhaustion is not in ADR-001's
out-of-scope list (which names a malicious host, multi-tenant guests, and
hardware key attestation), so it is implicitly in scope and currently
unaddressed. Three risks are introduced and each is closed above:

1. **A second egress gate.** The claim-10 architecture rests on `EgressGate`
   being the sole decision point — `check-uniform-vsock-egress` exists so a
   backend cannot grow a second one. If `Grants.egress` and
   `plan.network_policy` were independently settable they could disagree,
   and reading the wrong one is a policy bypass. Closed by WS2: derived, not
   supplied; refuse on disagreement; fail closed; gated to one projection.

2. **Silent downgrade to an unenforced tier.** A user asking for a 1.5-core
   cap on a host without cgroup delegation must not boot uncapped with a
   clean-looking receipt. Closed by WS3's read-back tier (the label derives
   from reading the cgroup file, never from what was attempted) and by
   `--prod` refusing an unenforceable grant. Dev may downgrade, loudly.

3. **New privileged-adjacent surface.** cgroup writes. Closed by WS4's
   validated-ID leaf naming (no path traversal into a sibling subtree),
   `openat`-relative writes (TOCTOU), and unprivileged user delegation.

Claims 8, 10, 11, and 12 are untouched.

Risk 2 is the same disease plan 306 WS3 treats for a different surface
("refuse where we currently degrade silently"). The two should share a
refusal vocabulary rather than grow two; whichever lands second adopts the
first's.

## Witnesses

Per the ledger rule, the ADR-001 row lands as a `Preview` claim first,
following the claim 16/17 precedent, and promotes once the live witness has
run on real hardware.

- [ ] `grants_projection_fails_closed` — a malformed grant yields deny-all,
      not permissive.
- [ ] `xtask check-single-grants-projection` — exactly one projection.
- [ ] `xtask check-backend-resource-controls` — every backend answers.
- [ ] `cpu_limit_tier_read_back_from_cgroup` — the receipt tier derives from
      reading the cgroup file, not from the attempted write.
- [ ] `prod_refuses_unenforceable_grant`.
- [ ] `admission_refuses_oversubscribed_host`.
- [ ] `exec_secs_timeout_kills_and_audits` — retires the currently
      unwitnessed "supervisor enforces" comment.
- [ ] `wasm_fuel_grant_halts_runaway_module`.
- [ ] `share_grant_on_wasm_names_fuel_substitute`.
- [ ] `check-ir-parity` fixture extended with grants.
- [ ] Live CPU-quota witness on the KVM box: an in-guest spinner measured
      against its quota. A test asserting cgroup file contents proves the
      write, not the limit.

## Out of scope

- Cross-tenant and fleet-wide budgets — mvmd.
- Disk IOPS and bandwidth grants — needs the io controller plus device
  mapping; no demand yet.
- `memory.max` / `pids.max` — reasoned above.
- Routing the CLI through the `mvm-client` facade. The CLI uses `AnyBackend`
  directly; that refactor is independent, and this plan deliberately does not
  block on it.
- Absorbing `NetworkPolicy` / `services` so `Grants` is their sole
  representation. That is the phase after this one, each absorption carrying
  its own witness migration.
