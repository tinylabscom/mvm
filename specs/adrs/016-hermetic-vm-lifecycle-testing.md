# ADR-016: Hermetic testing for VM-lifecycle audit emissions

## Status

Accepted.

## Context

Every state-changing CLI verb must emit exactly one `LocalAuditKind`
record per attempt — including on its no-op and failure branches — and
that guarantee is worthless untested. A live, drive-and-assert test for
each verb needs a fixture that matches what the verb actually reaches
through: a snapshot I/O socket, a vsock RPC to the in-guest agent, a
whole Nix build, the public GitHub network, or a `sudo`-gated system
path. Exercising the real substrate for all of these in CI is either
infeasible (no KVM runner for every lane) or actively dangerous to run
on a developer's own machine (destroying real system paths).

## Decision

Every verb cluster gets its own hermetic fixture substrate instead of
talking to its real backend:

- **Base VM lifecycle** (start/stop/set-ttl) routes through
  `--hypervisor mock`, which selects `MockBackend`
  (`crates/mvm-backend/src/mock.rs`) — an in-memory, in-process
  `VmBackend` implementation that records lifecycle calls and touches no
  host state.
- **Pause/resume** route through the `SnapshotIO` trait; `--hypervisor
  mock` swaps in `CannedIO`, which writes deterministic stub
  vmstate/mem files instead of talking to a real Firecracker control
  socket.
- **Guest-agent-bound verbs** (filesystem and process RPCs) go through
  `MockGuestAgent` (`crates/mvm-backend/src/mock_guest_agent.rs`), an
  in-process stand-in that speaks the same vsock protocol shape as the
  real in-guest agent.
- **Network-bound verbs** (self-update) redirect via an env-var override
  (`MVM_UPDATE_API_URL`) to a loopback HTTP fixture instead of the real
  GitHub releases API.
- **System-destructive verbs** (`uninstall`) redirect via a path-prefix
  override (`MVM_UNINSTALL_PATH_PREFIX`), so the positive path runs
  end-to-end against a sandboxed prefix instead of `/var/lib/mvm` and
  `/usr/local/bin/mvmctl`, with no `sudo` prompt.

Every live test drives the real, compiled `mvmctl` binary as a
subprocess (`assert_cmd`), with `HOME` / `MVM_DATA_DIR` / `MVM_STATE_DIR`
/ `MVM_CACHE_DIR` pointed at a per-test `tempfile::tempdir()`, and
asserts on the resulting audit log. Subprocess, not in-process, because
the audit emitter resolves its output path from the environment at call
time; running the command in-process would need either a process-global
env mutex (which kills test parallelism) or in-process path-injection
plumbing. A subprocess gets its own environment for free, which is
naturally hermetic under `cargo test`'s default thread-per-test
parallelism.

Every override above is either a real, operator-facing surface (`mock`
is a legitimate, if niche, `--hypervisor` choice — selected only by
explicit request, never by auto-detection) or an env var / `#[cfg(test)]`-
gated alternate path. No flag exists solely because a test needed it.

## Consequences

Every state-changing verb — including the ones that reach through a Nix
build, a vsock RPC, a snapshot socket, or the public network — has a
live, drive-and-assert test with no external dependency: no KVM, no Nix,
no libkrun, no real GitHub, no `sudo`. `tests/audit_emissions_live.rs` is
the single, growing catalog of this coverage.

The fixture substrate itself — `MockBackend`, `CannedIO`,
`MockGuestAgent`, and the env-var redirects — is surface that has to stay
honest. A mock that silently drifts from its real backend's behavior
would let a test pass while the real path is broken; it carries no
independent verification against the real backend beyond code review.

This covers the per-attempt `LocalAudit` stream only. The separate,
per-tenant chain-signed audit emitter (`plan.admitted` / `plan.launched`
/ `plan.failed`) is a different subsystem with its own coverage and is
not what these tests pin.
