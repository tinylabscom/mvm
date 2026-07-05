# `machine reconfigure` — design

**Date:** 2026-07-05
**Status:** Design approved; implementation plan pending.
**Scope:** Add a `machine reconfigure` verb that changes a narrow set of
config fields on a named machine and relaunches it under a fresh signed
`ExecutionPlan`, preserving the machine's identity — exposed both as a
CLI verb and as an operation on the `MvmClient` facade (local + remote).

## Problem

Network policy (and other launch config) is **launch-time-only and
enforced host-side** — it is baked into the signed `ExecutionPlan` at
admission and cannot be mutated on a running guest. This is correct: it
is what makes claim 10 (default-deny egress) and the chain-signed audit
log trustworthy. A compromised guest must not be able to widen its own
policy.

The consequence is that changing egress rules or resources on an
existing named machine today means manually re-issuing the full
`machine run` invocation (re-typing image/flake, cpus, memory, volumes,
network flags). That is friction, and it is error-prone — it is easy to
drop a `--volume` or a `--allow-host` and silently launch a differently
configured workload under the same name.

## Goal

A single convenience verb that changes a couple of fields and relaunches
**keeping the same identity** (name + volumes), where:

- new config ⇒ new signed `ExecutionPlan` ⇒ fresh VM (the honest model),
- the security posture is unchanged (no live policy mutation; every
  change goes through normal admission and the audit chain),
- the user does not have to re-type the whole launch spec.

This is the "convenience wrapper — same identity, fresh VM" model
(option A from brainstorming). It is explicitly **not** a
state-preserving / warm reconfigure (rejected — see below).

## Key enabling finding

The machinery this feature needs already exists.

- A named/persistent machine's full run-spec is persisted as JSON at
  `~/.mvm/machines/<name>/machine.json`, deserialized into `MachineSpec`
  (`crates/mvm-cli/src/commands/machine/mod.rs:635`). It already carries
  the fields in scope: `net`, `allow_host`, `cpus`, `memory`,
  `mem_initial` (plus image/manifest, volumes, profile, etc.).
- `machine start <name>` already reconstructs the launch: it reads
  `MachineSpec` (`mod.rs:1896`), resolves the image/manifest, and
  **synthesizes a brand-new signed `ExecutionPlan`** from the stored
  config before boot (`admit_plan_for_boot` → new
  `~/.mvm/vms/<name>/plan.json`).

So "read persisted spec → re-synthesize a fresh signed plan → boot" is
not new work — it runs on every `machine start`. `machine reconfigure`
is a thin wrapper over the existing spec read/write + `stop`/`start`
verbs.

Accessors already in place and reused as the storage seam:
`load_machine_spec`, `save_machine_spec`, `overwrite_machine_spec`
(`mod.rs:1603`–`1647`).

## CLI

```
mvmctl machine reconfigure <name> [--net] [--allow-host H:P]... \
                                  [--cpus N] [--memory SZ] [--mem-initial SZ]
```

In scope for reconfiguration: `net`, `allow_host`, `cpus`, `memory`,
`mem_initial` — the fields `MachineSpec` already models and that people
genuinely tune between runs (network + resources).

## Behavior

1. **Load** `MachineSpec` from `~/.mvm/machines/<name>/machine.json` via
   `load_machine_spec`. Unknown machine → clear error.
2. **Patch semantics.** Apply only the flags the user passed; every
   other field is inherited untouched. `machine reconfigure web
   --allow-host api.stripe.com:443` keeps the same image, cpus, memory,
   and volumes and only swaps the egress allowlist.
3. **Persist.** Atomically overwrite `machine.json` via
   `overwrite_machine_spec`. No `schema_version` bump (no new fields;
   consistent with the repo's "no schema-version-bump ceremony" stance).
4. **Apply.**
   - If the machine is **running** → **auto stop + start**, and be loud
     about it: `reconfiguring web: stopping… starting…`. The existing
     `machine start` path re-synthesizes a fresh signed `ExecutionPlan`
     from the updated spec — reused as-is, no new admission code.
   - If the machine is **stopped** → persist only; the change takes
     effect on the next `machine start`. State the change is staged.
5. **Identity preserved.** Managed `--volume` host shares survive the
   relaunch (durable data lives in host shares, not guest memory), so
   "same machine" holds across the reconfigure.

## Client facade (`MvmClient`)

The operation must also land on the `MvmClient` facade
(`crates/mvm-client/src/client.rs`) so programmatic and remote/cloud
callers can reconfigure a machine, not only the CLI.

Honest context: the facade is a real but **secondary** surface — the CLI
machine verbs call the backend directly today and do **not** route
through `MvmClient` (parallel paths). "Lands in the client" therefore
means adding the operation to the facade surface and both its impls; it
does not mean rewiring the CLI onto the facade (out of scope).

The facade carries its own thin intent DTOs (`memory_mib: u32`, `cpus`,
`env` — no host paths), distinct from the CLI's `MachineSpec`. The
reconfigure op follows that convention.

1. **Trait method** (`client.rs`):
   ```rust
   async fn reconfigure_machine(
       &self, id: &MachineId, cfg: ReconfigureRequest,
   ) -> Result<MachineState>;
   ```
2. **DTO** (`dto.rs`, `#[serde(deny_unknown_fields)]`) — all-optional =
   patch semantics:
   ```rust
   pub struct ReconfigureRequest {
       pub net: Option<bool>,
       pub allow_host: Option<Vec<String>>,
       pub cpus: Option<u32>,
       pub memory_mib: Option<u32>,
   }
   ```
   **Facade scope is the common four.** `mem_initial` is deliberately
   **not** on the facade DTO: the facade doesn't model it at launch
   either (its `MachineSpec` has no `mem_initial`), so exposing it only
   on reconfigure would be lopsided. It stays a CLI-only field. Adding
   it later is a non-breaking `Option` field behind the same DTO if a
   facade caller ever needs it.
3. **`LocalBackend`** (`mvm-client-local`): **delegating shell-out** — it
   invokes `mvmctl machine reconfigure <name> …`, exactly as it already
   does for the other verbs. The CLI verb stays the single source of
   truth for the patch/relaunch logic; the facade does not duplicate it.
4. **`GatewayBackend`** (`gateway.rs`): client-side
   `POST /api/v1/sandboxes/{id}/reconfigure` carrying the
   `ReconfigureRequest` body, using the existing `endpoint()` /
   `authed()` helpers and fail-closed transport rules.

**Repo boundary.** The *client side* of the remote path lands in this
repo (the `GatewayBackend` method). The matching **server handler lives
in mvmd** (separate repo). This plan delivers the client method plus a
coordination note for the mvmd `POST …/reconfigure` endpoint; it does
not implement the server handler.

## Testing

- **Patch merge (unit):** each in-scope field overrides in isolation
  while all others are preserved; passing no flags is a no-op merge.
- **Spec round-trip:** `overwrite_machine_spec` then `load_machine_spec`
  returns the patched spec byte-faithfully; unrelated fields intact.
- **Apply orchestration:** running → stop+start invoked in order
  (mockable via the existing verbs); stopped → persist-only, no
  stop/start call.
- **Error path:** reconfigure of an unknown machine name fails cleanly.
- **CLI:** arg-parse / help-text coverage in `tests/cli.rs`.
- **Facade DTO:** `ReconfigureRequest` serde round-trip +
  `deny_unknown_fields` rejection of unexpected fields.
- **Facade impls:** `LocalBackend::reconfigure_machine` builds the
  correct `mvmctl machine reconfigure` argv from a request (only set
  fields become flags); `GatewayBackend::reconfigure_machine` targets
  the `…/reconfigure` endpoint with the serialized body (mockable HTTP).

## Rejected alternatives

### Embedded SQL (sqlite / redb / sled) for machine state

**Rejected. Keep JSON files.**

Considered because a DB offers multi-record transactions, cross-cutting
queries ("which machines have `net=true`?"), mature locking, and a
migration framework. None of these pay off at mvm's scale, and each is
outweighed:

- **Scale/queries.** A developer has ~1–50 local machines; `readdir` +
  parse of tiny JSON files is sub-millisecond. There is no relational
  model and no non-key query pattern to index.
- **Concurrency.** Effectively one writer (the interactive user, plus a
  TTL reaper). Not a contention profile that warrants a DB engine.
- **Migrations are explicitly unwanted.** Repo stance: nothing is in
  production, no schema-version-bump ceremony, new fields land as
  `#[serde(default)]`.
- **Blast radius & debuggability.** One `machine.json` per directory
  isolates corruption to a single machine and stays `cat`/`jq`/`git
  diff`-inspectable and hand-editable. A single DB file is one
  corruption point for all machines — and that exact failure
  (`file is not a database`) has already bitten this repo's Nix cache.
- **Architectural fit.** All existing state (`plan.json`, `meta.json`,
  chain-signed audit `jsonl`) is file + atomic-rename through
  `mvm-core::config`; `mvm-core` is deliberately dep-light. A DB in the
  config layer creates two storage paradigms for no payoff.

**Not locking in:** all machine state flows through
`load_machine_spec` / `save_machine_spec` / `overwrite_machine_spec`, a
repository seam. If directory-of-JSON ever genuinely hurts, the backing
store can change behind those three functions with callers untouched.
The place that might actually justify a datastore is the multi-tenant
fleet control plane — which lives in the separate `mvmd` repo, not this
single-host CLI.

### State-preserving / warm reconfigure

**Rejected (option B from brainstorming).** Keeping the running
workload's memory/process state alive across a config change is far
harder and, for a security-critical field like network policy, is the
wrong model: it would re-admit a new policy onto a guest that already
ran under the old one. New config = new plan = new VM is the honest,
auditable model.

### Network presets in reconfigure

**Deferred.** `MachineSpec` models egress as `net: bool` + `allow_host`
only; it has no `--network-preset` (registries/dev/agent/unrestricted)
field. B-scope is fully satisfied without presets. Adding preset support
would mean a new `MachineSpec` field and a run/reconfigure consistency
question (does `machine run` even persist presets?), so it is left out.
Can be added later behind the same spec seam if wanted.

## Out of scope

State-preserving/warm reconfigure; network presets; changing
volumes/flake/image (those remain a full `machine run` — at some point
changing the image is *replacing* the workload, not reconfiguring it);
`mem_initial` on the facade DTO (CLI-only); rewiring the CLI machine
verbs to route through `MvmClient` (they stay direct-to-backend); the
mvmd server-side `POST …/reconfigure` handler (separate repo — this plan
lands only the client side + a coordination note).
