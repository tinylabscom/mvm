# ADR-006: `mvm` never grows tenant or fleet orchestration

## Status

Accepted

## Context

`mvm` is the operator-facing local CLI and local developer workflow
surface: boot, stop, inspect, and build microVMs on the host it runs on.
`mvmd`, in a separate repository, is the daemon and control-plane runtime:
it owns tenant lifecycle, placement, reconciliation, resource accounting,
policy, and fleet-wide audit trails across many hosts and many tenants.

The risk this boundary exists to prevent is scope creep in the wrong
direction: every convenience that would make `mvm` "a little more
daemon-like" (background tenant state, cross-host placement, a resident
registry of remote capabilities) either duplicates logic that already has
a canonical home in `mvmd` or creates a second, drifting implementation of
the same responsibility. `mvm` needs a way to talk to a remote control
plane when one exists, without ever becoming one.

## Decision

**`mvm`'s CLI surface carries no tenant, placement, or fleet-provider-
registry commands.** There is no `mvm providers list`, no named
accelerator or remote-execution provider concept, and no CLI verb that
asks a daemon to place a workload on someone else's host. Every command
under `mvm-cli/src/commands/` operates on this host's own microVMs.

**Backend selection is `VmBackend` + a flag, never a provider registry.**
Which hypervisor runs a workload is decided by the `VmBackend` trait and
its catalog-driven dispatch (`--hypervisor`/`MVM_BACKEND`, auto-detect —
see the `VmBackend` ADR). `mvm` does not layer a second "provider"
abstraction with its own identity, capability list, and health model on
top of that trait; one selection mechanism is the whole story.

**When `mvm` needs to reach a remote control plane, it does so through
one client contract: `MvmClient`.** The trait and its DTOs live in
`mvm-core` behind a `client` feature so the contract itself carries no
runtime dependency; `mvm-client` re-exports it and supplies two
implementations selected by `connect(Target)`:

- `Target::Local` → `LocalBackend`, driving this host's microVMs
  in-process through the same admitted-boot path the CLI uses.
- `Target::Gateway { base_url, token }` → `GatewayBackend`, a REST client
  reachable only when the crate's `remote` feature is enabled.

A caller asks for "local" or "a gateway" and gets a `Box<dyn MvmClient>`
back; it does not pick apart the transport, and there is no third,
CLI-specific path to the same operations. `mvm-sdk` and any studio/gateway
consumer program against this one trait rather than reimplementing
lifecycle calls.

**`mvm` may contain one open-source `mvmd` deployment client, but no provider
registry, tenant scheduler, or fleet control plane.** `mvmctl deploy` is allowed
as a client operation that submits a signed deployment intent, artifact
references, and policy to an authenticated `mvmd` origin. The client does not
choose a production host or hypervisor; `mvmd` owns placement, backend
selection, and launch authority (ADR-037). This is a narrow exception to the
"no tenant/fleet orchestration" boundary, not a general provider abstraction.

**`mvm` does not model accelerators, GPUs, or remote inference targets as
providers.** No such capability, identity, or health surface exists in
the current tree. If host-side accelerator access is ever exposed, it is
designed fresh against `MvmClient` and `VmBackend` as they exist then —
not retrofitted onto a provider vocabulary that predates both.

## Consequences

- `mvm` stays a single-host, scriptable tool: every command is
  deterministic against local state, and there is nothing to explain
  about "which daemon answered this."
- A remote control plane is reachable by one trait with two backends
  rather than by a bespoke provider client; adding a third transport
  (a different remote protocol, a mock for tests) is one more `MvmClient`
  impl, not a new abstraction layer.
- Any future accelerator, remote-execution, or multi-host capability that
  wants a CLI presence must justify itself against this boundary before
  it lands — the default answer is that fleet-facing concerns belong in
  `mvmd`, and `mvm` exposes only what drives its own host.
