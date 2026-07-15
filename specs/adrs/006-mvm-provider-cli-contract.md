# 0048 — MVM Provider CLI Contract

- **Status:** Proposed
- **Date:** 2026-05-07
- **Applies to:** `mvm`
- **Related:** `mvmd/specs/adrs/0047-provider-architecture.md`
- **Decision owner:** MVM maintainers

## Context

`mvm` and `mvmd` have different responsibilities.

`mvm` is the operator-facing command line interface and local developer workflow surface. It should make secure VM and microVM operations understandable, scriptable, and easy to inspect.

`mvmd` is the daemon and control-plane runtime. It owns provider lifecycle, host capability discovery, placement, reconciliation, telemetry, resource accounting, tenant policy, sleep/wake behavior, and audit trails.

The provider architecture ADR belongs canonically in `mvmd` because providers are long-running runtime integrations, not merely command-line features. However, `mvm` still needs an ADR that defines how the CLI discovers, invokes, inspects, and constrains providers without taking ownership of orchestration logic.

This ADR defines the `mvm` side of the provider boundary.

## Decision

`mvm` will support providers through a stable CLI and client contract, but it will not implement provider orchestration directly.

`mvm` will discover and interact with providers through `mvmd` when a daemon is available. For local development, `mvm` may support explicitly marked local shims, but those shims must preserve the same contract shape used by `mvmd`.

The first provider families exposed through the CLI are:

1. `linux` — general Linux VM/microVM provider.
2. `mlx` — Apple Silicon MLX/Metal-backed provider exposed through host-side capability services.

The provider implementation crate is expected to live with `mvmd`, not `mvm`, unless both projects are unified into a single workspace.

Canonical provider crate location:

```text
mvmd/
  crates/
    mvmd-provider-api/
    mvm-providers/
      src/
        lib.rs
        registry.rs
        capabilities.rs
        linux.rs
        mlx.rs
```

`mvm` should depend on a thin client crate or protocol schema, not directly on provider implementation internals.

Preferred `mvm` shape:

```text
mvm/
  crates/
    mvm-cli/
    mvm-client/
    mvm-contracts/
```

## Invariants

1. `mvm` does not own provider lifecycle.
2. `mvm` does not decide final placement.
3. `mvm` does not hold long-running provider state.
4. `mvm` does not directly expose unrestricted host devices to guests.
5. `mvm` treats providers as capability-backed execution targets.
6. `mvm` commands must be scriptable and deterministic.
7. `mvm` must clearly distinguish daemon-backed execution from local development shims.
8. `mvm` must never silently downgrade security boundaries.
9. `mvm` must surface provider health, capability, and audit information from `mvmd`.
10. `mvm` must preserve a stable contract even if provider implementations change.

## CLI Contract

`mvm` will expose provider operations through a small set of commands.

Example command surface:

```text
mvm providers list
mvm providers inspect <provider>
mvm providers health <provider>
mvm providers capabilities <provider>
mvm providers test <provider>

mvm run --provider linux --image <image>
mvm run --provider mlx --model <model> --capability inference

mvm vm create --provider linux --image <image>
mvm vm start <id>
mvm vm stop <id>
mvm vm status <id>

mvm infer --provider mlx --model <model> --input <file>
```

The exact command names may evolve, but the CLI must preserve these conceptual operations:

- list available providers
- inspect provider metadata
- inspect provider capabilities
- validate provider health
- request a provider-backed execution
- inspect the resulting run or VM state
- retrieve audit and telemetry references

## Provider Identity

Every provider exposed through `mvm` must have a stable identity.

Example provider identity shape:

```json
{
  "name": "mlx",
  "kind": "accelerator",
  "runtime": "host-service",
  "platforms": ["macos-aarch64"],
  "status": "available",
  "managed_by": "mvmd"
}
```

Provider names are stable user-facing identifiers. Implementation crate names, internal modules, and daemon plugin IDs may change without changing the CLI-facing provider name.

Initial provider names:

```text
linux
mlx
```

Future provider names may include:

```text
firecracker
libkrun
apple-vz
libkrun
cloud-hypervisor
containerd
incus
remote
```

(`lima` was named here in an earlier draft as a candidate provider;
removed per ADR-004, which drops Lima from mvm entirely.)

## Capability Model

`mvm` does not assume all providers can perform all operations. It asks `mvmd` for provider capabilities and presents them to the user.

Example capabilities:

```text
vm.boot
vm.stop
vm.snapshot
vm.restore
vm.sleep
vm.wake
net.tap
net.nat
storage.block
storage.virtiofs
accelerator.inference
accelerator.mlx
accelerator.vulkan
telemetry.stream
audit.events
```

The `mlx` provider must be treated as an accelerator capability provider, not as a general-purpose Linux VM provider.

The `linux` provider must be treated as a VM or microVM execution provider. It may optionally request accelerator capabilities, but it should not assume they are present.

## Linux Provider Contract

The `linux` provider represents general Linux guest execution.

Minimum capabilities:

```text
vm.boot
vm.stop
vm.status
storage.block
net.nat
telemetry.basic
audit.events
```

Optional capabilities:

```text
vm.snapshot
vm.restore
vm.sleep
vm.wake
net.tap
storage.virtiofs
telemetry.stream
accelerator.vulkan
accelerator.inference
```

The CLI should allow Linux provider selection through:

```text
mvm run --provider linux --image ./guest.img
```

or:

```text
mvm vm create --provider linux --image ./guest.img
```

The CLI must not expose backend-specific assumptions unless explicitly requested. For example, a user should not need to know whether the Linux provider is backed by Apple Virtualization.framework, Firecracker, libkrun, libkrun, Incus, or another runtime unless they ask for implementation details.

## MLX Provider Contract

The `mlx` provider represents Apple Silicon host-side MLX/Metal-backed inference capability.

The `mlx` provider does not imply direct Metal passthrough into a Linux guest.

The expected architecture is:

```text
Linux microVM or local client
  -> mvm / mvm-agent
  -> mvmd
  -> mvm-providers::mlx
  -> host-native MLX / Metal / model runtime
```

Minimum capabilities:

```text
accelerator.inference
accelerator.mlx
model.load
model.unload
telemetry.basic
audit.events
```

Optional capabilities:

```text
telemetry.stream
model.registry
model.cache
openai.compatible_api
batching
rate_limit
tenant_quota
```

The CLI may expose MLX-backed inference through:

```text
mvm infer --provider mlx --model <model> --input <file>
```

or through a VM capability request:

```text
mvm run --provider linux --with-capability accelerator.mlx --image <image>
```

In the second case, the Linux guest receives a constrained service endpoint, not unrestricted GPU access.

## Daemon-Backed vs Local Shim Mode

`mvm` may support two execution modes:

```text
daemon-backed: mvm talks to mvmd
local-shim:    mvm runs a constrained local implementation for development
```

Daemon-backed mode is the default production path.

Local shim mode must be explicit:

```text
mvm --local providers list
mvm --local run --provider linux --image ./guest.img
```

or configured with an explicit development profile.

The CLI must clearly show when it is not using `mvmd`:

```text
Provider mode: local-shim
Security mode: development-only
Managed by: mvm
```

Local shims must not be documented as production isolation boundaries.

## Provider Discovery

`mvm` discovers providers by querying `mvmd`.

Expected flow:

```text
mvm providers list
  -> mvm-client queries mvmd
  -> mvmd returns provider registry snapshot
  -> mvm renders stable user-facing provider information
```

Provider discovery response should include:

```text
- provider name
- provider kind
- provider status
- supported capabilities
- host platform constraints
- health summary
- whether the provider is daemon-managed or local-shim
- audit/telemetry availability
```

The CLI should support structured output:

```text
mvm providers list --output json
mvm providers inspect mlx --output json
```

## Error Handling

Provider errors must be user-actionable.

Bad:

```text
provider failed
```

Good:

```text
provider mlx is unavailable: host is not Apple Silicon or MLX runtime is not installed
```

Good:

```text
provider linux cannot satisfy requested capability accelerator.mlx on this host
```

Good:

```text
mvmd is unavailable; rerun with --local for development-only local shims
```

The CLI must distinguish:

```text
- provider not found
- provider unavailable
- provider unhealthy
- capability unsupported
- capability denied by policy
- host resource exhausted
- tenant quota exceeded
- daemon unreachable
- local shim unavailable
```

## Security Requirements

`mvm` must not allow CLI convenience to bypass provider policy.

Security requirements:

1. Provider access is capability-scoped.
2. Accelerator access is never equivalent to raw device passthrough unless explicitly modeled and approved.
3. Guest-to-host service endpoints must be explicit and auditable.
4. Secrets must not be passed to providers through command-line arguments when avoidable.
5. Provider requests must include tenant, run, and audit context when daemon-backed.
6. Local shim mode must be visibly marked as development-only.
7. The CLI must not obscure policy denials from `mvmd`.
8. The CLI must not retry denied provider operations as a different provider unless explicitly requested.

## Telemetry and Audit

`mvm` should present provider telemetry and audit references, but `mvmd` owns the source of truth.

Example:

```text
mvm vm status <id>
```

may show:

```text
VM: tenant-a/run-0182
Provider: linux
Host: macbook-pro-local
State: running
Capabilities: vm.boot, net.nat, storage.block
Telemetry: available
Audit: audit://runs/0182
```

For MLX:

```text
mvm infer --provider mlx --model qwen --input prompt.txt
```

may show:

```text
Run: infer-0921
Provider: mlx
Model: qwen
Runtime: host-native-mlx
Tokens/sec: 42.1
Audit: audit://runs/infer-0921
```

## Repository Placement

This ADR belongs in the `mvm` repository because it defines the CLI and client behavior.

Recommended path:

```text
mvm/specs/adrs/0048-provider-cli-contract.md
```

The canonical provider architecture ADR belongs in `mvmd`:

```text
mvmd/specs/adrs/0047-provider-architecture.md
```

The provider implementation crate should live in `mvmd` unless the projects share one workspace:

```text
mvmd/crates/mvm-providers/
```

`mvm` may contain only shared contracts and clients:

```text
mvm/crates/mvm-contracts/
mvm/crates/mvm-client/
mvm/crates/mvm-cli/
```

## Consequences

### Positive

- Keeps `mvm` simple and scriptable.
- Keeps provider lifecycle and placement in `mvmd`.
- Avoids duplicating provider orchestration logic across CLI and daemon.
- Allows local development shims without pretending they are production runtimes.
- Makes `linux` and `mlx` providers visible to users through a stable interface.
- Preserves a clean path for future providers.

### Negative

- Requires `mvmd` for production-grade provider behavior.
- Requires a stable client/protocol contract between `mvm` and `mvmd`.
- Local-only users may need an explicit development mode.
- Some provider errors will require daemon-side context to explain fully.

### Neutral

- `mvm` may still support local experimentation.
- Provider implementation details may evolve without changing the CLI contract.
- The initial provider set is intentionally small.

## Non-Goals

This ADR does not define:

- the full `mvmd` provider registry implementation
- provider placement algorithms
- host reconciliation loops
- Firecracker-specific configuration
- Apple Virtualization.framework implementation details
- direct Metal passthrough to Linux guests
- MLX model serving internals
- tenant billing or pricing
- a public marketplace for providers

## Implementation Notes

Initial implementation should prioritize:

1. `mvm providers list`
2. `mvm providers inspect <provider>`
3. structured JSON output
4. daemon-backed provider discovery through `mvm-client`
5. explicit local shim mode
6. initial `linux` and `mlx` provider visibility
7. actionable provider errors

Suggested contract types:

```rust
pub struct ProviderSummary {
    pub name: ProviderName,
    pub kind: ProviderKind,
    pub status: ProviderStatus,
    pub managed_by: ProviderManager,
    pub capabilities: Vec<Capability>,
    pub platform_constraints: Vec<PlatformConstraint>,
}

pub enum ProviderKind {
    Vm,
    MicroVm,
    Accelerator,
    HostService,
    Remote,
}

pub enum ProviderManager {
    Mvmd,
    LocalShim,
}

pub enum ProviderStatus {
    Available,
    Unavailable,
    Degraded,
    Unhealthy,
}
```

The CLI should avoid importing concrete provider implementations. It should depend on contracts and clients only.

## Acceptance Criteria

This ADR is satisfied when:

- `mvm` has a provider CLI surface.
- `mvm providers list` can show `linux` and `mlx`.
- `mvm providers inspect linux` shows VM capabilities.
- `mvm providers inspect mlx` shows accelerator capabilities.
- JSON output is supported for provider commands.
- daemon-backed and local-shim modes are visibly distinct.
- provider errors are actionable.
- provider orchestration remains in `mvmd`.
- `mvm` does not directly depend on `mvm-providers` implementation internals.

## Final Decision

Place this ADR in `mvm` as the CLI/provider contract ADR.

Keep `0047-provider-architecture.md` in `mvmd` as the canonical provider runtime ADR.

`mvm` speaks to providers.

`mvmd` owns providers.

## Disambiguation: two layers, both called "providers"

The mvm tree has *two* concerns that share the word "provider":

1. **Public Provider** (this ADR) — user-facing identity selectable from
   the CLI: `linux`, `mlx`, eventually `firecracker`, `apple-vz`, etc.
   Owned by `mvmd` (per the canonical ADR `0047-provider-architecture.md`
   in mvmd). `mvm` only speaks the contract.

2. **Internal `mvm-providers` crate** — the FFI / SDK shim layer that
   wraps low-level virtualization frameworks. Today it contains:
   - `mvm_providers::libkrun`        — Red Hat libkrun C library bindings
   - `mvm_providers::apple_container` — Apple Virtualization.framework
     via objc2 + Swift bridge

   Future modules: `cloud_hypervisor`, `windows_wfp`, etc. This crate
   is consumed by `mvm-backend` (the `VmBackend` impls), which is
   consumed by `mvm` (lifecycle orchestration).

The two share a name but address different layers. Public Providers
are what end users select; the internal `mvm-providers` crate is
how mvm-backend reaches the underlying VMM. A user typing
`mvm run --provider linux` resolves to whichever internal backend
the host can run; the FFI shim layer is an implementation detail.

This ADR's body remains unchanged — it is still the contract for the
public Provider concept. The internal crate's purpose is documented
in its own README + lib.rs module docs.
