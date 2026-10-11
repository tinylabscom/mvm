# ADR-056: Client operations never shell out

Backing: preview
Validation: none

## Status

Accepted by the owner. Delivery:
[#3730](https://github.com/tinylabscom/mvm/issues/3730) (PS-21), tracked by
[#3731](https://github.com/tinylabscom/mvm/issues/3731).

This decision strengthens the library-first consumption boundary in
[ADR-022](022-target-architecture.md#4-consumption-topology--library-thin-cli-one-client-trait).
It is binding for implementation, not a claim that existing code complies.

## Context

Calling a library is not sufficient if that library invokes a command-line
tool to perform the operation. Moving an existing subprocess call from the CLI
into `mvm-client` preserves the external executable dependency, ambient process
environment, output-parsing protocol, and separate failure modes. It does not
complete an in-process client operation.

During PS-21 the owner explicitly required no subprocess execution, including
existing behavior being extracted, preparation, signing, and test fixtures.
Existing shell-outs are migration work, not grandfathered exceptions.

## Decision

**Never shell out to implement a client operation. Use in-process APIs.**

This applies to the entire implementation reached by `mvm-client`, whether
called by the CLI, hostlib, a language SDK, or another embedder. It covers
preparation and acquisition, verification and signing, image and archive
handling, repository inspection, process inspection, maintenance, and lifecycle
orchestration. Frontends must not perform the forbidden subprocess step before
or after calling the library.

The prohibition is semantic, not a search for one spelling:

- No `std::process::Command`, `tokio::process::Command`, shell invocation,
  interpreter invocation, direct fork/exec/spawn, or platform equivalent to
  implement these operations.
- No replacement process wrapper, FFI escape hatch, callback, lower-level
  library, helper executable, or SDK transport that merely hides the spawn.
- No invoking tools such as `git`, `curl`, `tar`, `cosign`, `codesign`, or `ps`
  in place of a library or native API.
- No moving the same utility invocation into a guest, service, or remote
  command runner to evade this requirement.
- No subprocess test fixtures for these operations. Use in-process fixtures,
  real library-created artifacts, and narrowly injected process observations,
  clocks, or syscall outcomes where necessary.

Use typed library calls and native platform APIs for the underlying capability.
Keep native bindings behind the repository's existing platform/FFI boundaries.
Preserve the authoritative verification, custody, admission, audit, and
filesystem-safety rules; removing a subprocess must not weaken them.

This decision does not remove the product's purpose of executing admitted
workloads inside isolated microVMs. It does not authorize host execution of
workload code, and it creates no exception for a host helper or launcher.
Where the current implementation requires such a subprocess, the operation
needs architectural replacement rather than a mechanical move or a renamed
spawn function.

### macOS signing happens before process load

Installation and explicit preparation sign executable artifacts in-process
before they are used. Inspection must establish both operating-system signature
validity and the required boolean entitlements for every architecture, not the
presence of a key in XML text.

A running process cannot acquire launch-time entitlements by rewriting its
executable. Runtime self-signing followed by re-exec is therefore not a valid
repair path. Check the loaded process's entitlement state, report a preparation
or restart requirement honestly when necessary, and never implement that restart
with another spawn/exec mechanism. Pre-signing is not an exception to the
host-helper or launcher prohibition above.

## Migration and acceptance

PS-21 includes removal of existing subprocess behavior in the paths it moves,
including transitive implementation dependencies and their regression fixtures.
Review must follow the actual operation, not just its public wrapper or crate.

A missing in-process capability is unfinished work. Do not silently retain a
shell-out, make it an opt-in fallback, skip its tests, or claim parity by
replacing a working operation with an unconditional refusal. Any proposed
change to supported behavior requires a separate explicit product decision.
No exception is granted by this ADR.

Validation must cover:

1. Detection of subprocess APIs, aliases, wrappers, and indirect delegates
   across the migrated operation, including tests.
2. Functional parity through public client and hostlib/SDK entry points.
3. Real in-process success and refusal fixtures for integrity, authorization,
   key custody, audit, and cleanup behavior.
4. No executable discovery or process-launch dependency hidden behind a
   successful library call.

The existing no-CLI-shellout check alone is insufficient: it prevents SDKs
from launching the CLI, but does not establish that client internals never
launch other executables. The broader enforcement and migration remain part
of PS-21; `Validation: none` records that this ADR does not yet have a complete
automated witness.

## Consequences

The CLI remains argument parsing, input/output adaptation, and presentation;
hostlib and SDKs reach the same implementation without external utility
dependencies. Tests exercise library contracts rather than local executable
availability.

Some existing extraction work must be redesigned instead of copied. Native
platform integrations and missing library capabilities may make the work
larger. That cost does not justify a subprocess fallback or premature PS-21
completion.
