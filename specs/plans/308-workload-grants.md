# Plan 308 — Workload grants: one declaration, per-backend enforcement

**Status: IN FLIGHT — WS1, WS1b, WS2, WS3 complete; WS4 partial (CPU bound + prod gate landed, admission budget outstanding); WS5b partial (child ⊆ parent enforced and chain-anchored, `apply_grants` on restore outstanding); WS5, WS6, WS6b outstanding.**

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

- `Share { millicores: u32 }` — thousandths of one host core (1500 = 1.5
  cores), rendered as systemd's `CPUQuota=150%`. Integer, not a float: the
  grant lands in a signed, content-addressed payload, and float
  canonicalization is not stable across serializers.
- `Fuel { instructions: u64 }` — a deterministic wasmtime instruction budget.

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

### A grant and a ceiling are different objects

A grant says what a workload asks for. Nothing in the model above says what
it is *allowed* to ask for, and a validly-signed plan carrying
`cpu.Share(64.0)` would be admitted precisely because it is validly signed.
For single-user mvm that is correct — the user owns the host. For fleet it is
privilege escalation: a tenant who can sign their own plan can grant itself
the machine.

So `GrantCeiling` is a separate type with a separate trust root. The grant is
signed by whoever launches the workload; the ceiling is resolved at admission
from host or fleet configuration, never from the plan, and admission refuses
a grant exceeding it. **No surface in the precedence chain can raise a
ceiling** — the chain resolves grants only. mvm ships a host-local ceiling
(defaulting to the host's own capacity); mvmd supplies a per-tenant one.

This also settles the direction of the precedence chain: a lower-precedence
surface may be *loosened* by a higher one — the manifest is a project default
and the CLI belongs to the developer running it — because the ceiling, not
the manifest, is what actually bounds the outcome.

### Per-backend mechanism

| Dimension | Firecracker / libkrun / QEMU **on Linux** | HVF, and libkrun **on macOS** | wasm (wasmtime) |
| --- | --- | --- | --- |
| CPU | cgroup v2 `cpu.max` on the VM's own process | none — declared vCPU count | `consume_fuel` + `Store::set_fuel` |
| Memory | fixed guest RAM by construction | fixed guest RAM by construction | `StoreLimits` memory cap |
| Wall clock | supervisor timer | supervisor timer | `epoch_interruption` + deadline |
| Egress | `EgressGate` over vsock | `EgressGate` over vsock | `mvm:egress` host import |

**The CPU row is host-conditional, not backend-conditional.** libkrun is the
macOS 13-25 workload default as well as a Linux backend, so its CPU answer
depends on where it is running: a cgroup quota on Linux, nothing on macOS.
Keying that answer off the backend alone would declare a quota mechanism that
does not exist on a Mac, and a share grant would then be accepted at
negotiation and fail only at apply time — the failure this table exists to
prevent. HVF is macOS-only and so is unconditionally `None`.

libkrun and HVF are in-process VMMs, but each runs under its own per-VM
supervisor binary (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`); Firecracker
and QEMU are spawned as direct child processes. Either way the process is
per-VM, which is what makes a cgroup on it correctly scoped.

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

- [x] **WS1 — The `Grants` type and one resolver.**
      `Grants` in `mvm-contract`, serde + `schemars` behind the existing
      `schema` feature. Added to `ExecutionPlan` as
      `Option<Grants>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`
      — the `environment` field's comment states why: the field is inside
      the signed payload, so emitting `null` invalidates every existing
      signature and frozen vector. One resolver implementing the precedence
      chain above. No enforcement change; `Grants` projects down to the
      existing `NetworkPolicy` / `Resources` / `services` types.

      Two fail-open traps to close in the type itself. `#[serde(deny_unknown_fields)]`
      on `Grants` and every nested type, applied to the `--grants-file` JSON
      surface as well: a security control that a spelling mistake silently
      disables (`cpu_limt: 1.5` parsing to "no cap") is worse than one that
      does not exist, and this is already the project rule for host↔guest
      types. And `wall_clock` must not inherit `TimeoutSpec`'s magic zero —
      `exec_secs: 0` currently means *unbounded*, so a user writing
      `timeout = 0` to mean "no time allowed" gets no limit. The grant carries
      an explicit `Unbounded` variant; the projection to `exec_secs` is where
      the legacy encoding is reconstructed, and nowhere else.

- [x] **WS1b — `GrantCeiling`.**
      A separate type resolved at admission from host config (mvm) or fleet
      policy (mvmd), never from the plan. Admission refuses a grant exceeding
      it, naming the dimension and both values. Not reachable from the
      precedence chain — a gate asserts no surface resolver writes a ceiling.
      mvm's host-local default derives from the host's own CPU count and RAM,
      so the out-of-the-box behaviour is "you may not grant more than the
      machine has", which is also what makes WS4's budget meaningful.

- [x] **WS2 — Projection is single and fails closed.**
      `network_policy` is *derived* from `Grants`, never supplied alongside
      it; admission re-derives and refuses on disagreement, the same shape as
      the existing `l3_network` / `network_mode` refusal. Any projection
      error yields deny-all, matching `EgressGate::from_network_policy`. New
      `xtask check-single-grants-projection` asserts exactly one
      Grants→`NetworkPolicy` projection function exists, in the spirit of
      `check-uniform-vsock-egress`.

- [x] **WS3 — The backend seam.**
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

- [x] **WS4.0 — Delegation spike. COMPLETE — verdict: switch to a systemd transient scope.**
      The `cpu` controller is historically *not* delegated to user sessions
      by default, while `memory` and `pids` generally are. Since "no `sudo`"
      is a hard constraint, the primary enforcement mechanism for the primary
      gap may not exist unprivileged on a default distro. Validate on the KVM
      box before committing to the approach: is `cpu` present in
      `cgroup.controllers` of the user slice, and does writing `cpu.max` in a
      delegated leaf take effect? If not, the fallback is a systemd transient
      scope over the session bus, which is a different design and must be
      chosen here rather than discovered during implementation.

- [~] **WS4 (CPU + prod gate done; admission budget NOT built) — Linux CPU quota, wall clock, admission budget.**
      **Redesigned after the WS4.0 spike** — see
      `specs/plans/308-cgroup-delegation-findings.md`. Writing a cgroup leaf
      directly does not work unprivileged, and not for the reason this plan
      first assumed: the `cpu` controller *is* delegated and `cpu.max` *is*
      writable, but cgroup v2 **migration** additionally requires write access
      to the common ancestor of the process's current and destination cgroups,
      and a login session's `session-N.scope` is `Delegate=no`. So a process
      launched from any ordinary shell cannot move itself into the delegated
      subtree.

      The mechanism is instead a systemd transient scope:
      `systemd-run --user --scope -p CPUQuota=<n>%`, which works because the
      user's own `systemd --user` manager performs the placement from inside
      the delegated tree. Measured on the spike box at 1.495 cores against a
      1.5-core target, with `nr_throttled` confirming live kernel throttling.
      The scope name derives from the validated machine ID, never a
      user-supplied string.

      **The process is born into its scope, not moved into it** — and the new
      mechanism gives this for free rather than by hand. systemd creates the
      scope and then spawns the payload inside it, so there is no interval in
      which the workload runs uncapped. The original design needed `clone3`
      with `CLONE_INTO_CGROUP` to achieve the same property.

      Fail honestly when the mechanism is absent: `systemd-run` may be missing,
      and a user session bus may not exist in a headless daemon context —
      delegation hangs off that session. Detect both and report the `Declared`
      tier rather than failing the boot, except under `--prod`, which refuses
      an unenforceable grant.

      Supervisor-side `exec_secs` timer whose kill is emitted to the audit
      chain, so an enforced timeout is distinguishable from a crash.

      Admission-time host budget refusing a boot that would oversubscribe
      past a headroom configured in `~/.mvm/config` through the existing
      `user_config` key mechanism. **The budget is computed from live process
      liveness, not from inventory records alone**: a crashed VM whose record
      was never reaped would otherwise consume its share forever and refuse
      every subsequent boot — turning the safety check into a permanent
      lockout. Reuse the shared pid-marker liveness probe the fork path
      already relies on rather than adding a second notion of "running".
      Budget accounting is against each VM's configured memory *maximum*, not
      its current commitment: the balloon controller
      (`supervisor/balloon_runtime.rs`) moves commitment at runtime under host
      pressure, so accounting against the live figure would drift against the
      ceiling admission actually granted.

- [ ] **WS5 — wasm enforcement.**
      `Config::consume_fuel` + `Store::set_fuel` for `CpuGrant::Fuel`;
      `StoreLimits` wired into the `Store` for memory; `epoch_interruption`
      + deadline for wall clock. `VmInfo` stops reporting `cpus: 0,
      memory_mib: 0` and reports the enforced grant. Accepts fuel-accounting
      overhead as the cost of a deterministic bound.

      Fuel and epoch are **jointly** required, not alternatives for separate
      dimensions. A module blocked inside a host call consumes no fuel, so a
      module that parks in `mvm:egress` is bounded by neither a fuel grant nor
      anything else. Epoch interruption is what preempts it, and the
      `mvm:egress` host call needs its own timeout so the wasm tier cannot be
      stalled indefinitely by a slow or hostile endpoint. A fuel-only wasm
      grant must be rejected at admission rather than accepted as partial
      enforcement.

- [~] **WS5b — Grants across snapshot, fork, and restore.**
      Today's child-plan validation (`crates/mvm-runtime/src/checkpoint/mod.rs`)
      checks signature length, signer id, `verify_plan_id`, tenant match, and
      the validity window. It does not compare the child's resources against
      the parent's. The bypass that opens once grants are the control surface:
      admit under tight grants, snapshot, restore the child under loose ones.

      Grants join what checkpoint lineage chain-anchors, restore re-applies
      them through the same `apply_grants` seam as a cold boot, and admission
      refuses a child whose grants are not a subset of its parent's. Same
      family as the restored-child authorization gap that disarmed the plan
      255 pool, so the two should be reviewed together.

      LANDED: `mvm_contract::grants::subset::grants_are_subset` — CPU/wall
      clock treat absence as *unbounded* (so a child dropping a bound has
      widened), egress treats it as deny-all (so dropping it has narrowed),
      and mismatched CPU units are refused rather than converted.
      `CheckpointMeta.grants` is inside `CheckpointDigestInput`, so a parent
      record edited to widen its own grant stops matching the digest the
      signed chain recorded and is refused before the comparison runs. Capture
      seals the VM's admitted grants; a vm_full fork checks the child plan's
      set against the parent's in `validate_child_fork_plan` and records the
      child's own (narrower) set; an fs_quick fork inherits the parent's.
      STILL OPEN: restore does not re-apply the grants through `apply_grants`
      the way a cold boot does — the child cannot be *admitted* wider, but
      nothing re-arms the host-side control on the restored VM.

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

- [ ] **WS6b — Observability, migration, docs.**
      `mvmctl doctor` reports resolved grants and achieved tiers alongside the
      live posture it already prints — the place a user finds out their CPU
      cap is `declared` rather than enforced. `machine inspect` / `ls` show
      enforced-vs-declared per dimension. Persisted `MachineSpec`s on disk
      predate grants: `#[serde(default)]` plus a `machine reconfigure` path,
      so an existing machine does not fail to load. The CLI reference
      (`public/src/content/docs/reference/cli-commands.md`) is held by
      `check-machine-doc-guards`, so new flags fail the build undocumented —
      budget for it rather than discovering it in CI. A `features/suites/`
      BDD suite for the grant scenarios, where claim scenarios live.

## Security analysis

Net positive. Guest→host resource exhaustion is not in ADR-001's
out-of-scope list (which names a malicious host, multi-tenant guests, and
hardware key attestation), so it is implicitly in scope and currently
unaddressed. Making grants the control surface nonetheless introduces risks
that did not exist while the dimensions were ungoverned. Each is closed above:

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

4. **A self-granted ceiling.** A plan signer who is also the grant author can
   grant itself the machine. Closed by WS1b: the ceiling has a separate trust
   root, is resolved at admission from host or fleet config rather than from
   the plan, and is unreachable from every surface in the precedence chain.

5. **An uncapped startup window.** A cgroup applied after the VMM is already
   running bounds nothing during the interval that matters most for a
   workload built to burn CPU immediately. Closed by WS4's born-into-cgroup
   requirement.

6. **Restore as a grant-laundering path.** Snapshot under tight grants,
   restore under loose ones — the child-plan check does not compare a child's
   resources to its parent's. Closed by WS5b: grants are chain-anchored into
   lineage, re-applied on restore, and a child's grants must be a subset of
   its parent's.

7. **Fail-open by typo or by magic zero.** An unknown field silently
   discarding a cap, and `exec_secs: 0` already meaning *unbounded*, both turn
   a security control off through an ordinary mistake. Closed in WS1 by
   `deny_unknown_fields` across the type and the JSON surface, and by an
   explicit `Unbounded` variant instead of a magic zero.

8. **The safety check as a lockout.** An admission budget computed from
   unreaped inventory records refuses every boot forever once a VM crashes
   without cleanup — availability failure caused by the control itself.
   Closed by WS4 computing the budget from live process liveness.

Claims 8, 10, 11, and 12 are untouched.

Deliberately **not** addressed: CPU-quota enforcement makes cross-VM covert
timing channels marginally easier to drive, since a bounded workload can
modulate a signal its co-resident can observe. ADR-001 places multi-tenant
guests out of scope and one guest is one workload, so co-residency channels
stay out of scope here too — but the reasoning is recorded rather than left
as an unnoticed consequence of adding the control.

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
- [ ] `admission_refuses_grant_exceeding_ceiling`.
- [ ] `no_surface_resolver_writes_a_ceiling` — the precedence chain resolves
      grants only.
- [ ] `restored_child_grants_must_be_subset_of_parent` — the restore
      laundering path.
- [ ] `vmm_is_born_into_its_cgroup` — asserts the cap is live at the
      workload's first instruction, not merely applied eventually. A test
      that reads `cpu.max` after startup passes on the racy implementation
      too, so this one has to observe the pid's cgroup membership at exec.
- [ ] `unknown_grant_field_is_refused_not_ignored` — over both the plan type
      and the `--grants-file` JSON surface.
- [ ] `wall_clock_zero_is_not_unbounded`.
- [ ] `fuel_only_wasm_grant_is_refused` — fuel without epoch bounds nothing
      for a module parked in a host call.
- [ ] `budget_ignores_dead_machines` — an unreaped record does not refuse
      every subsequent boot.
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
