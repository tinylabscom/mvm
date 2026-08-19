# MvmClient-backed MCP server

Backing: shipped-source
Validation: check-sprint-append

## Goal

Restore a local stdio MCP surface as a thin adapter over `dyn MvmClient`,
derive its tool catalog from the selected client's reported operations, and
prove the protocol against `MockBackend` without booting a VM.

## Work

- [x] Add a serialized, builder-constructed client-operation capability set
      to `BackendCapabilityReport` and report it honestly from local, gateway,
      and mock clients.
- [x] Add the dependency-light `mvm-mcp` crate with bounded newline-delimited
      JSON-RPC, current MCP discovery/tool methods, and legacy initialize
      compatibility.
- [x] Route every advertised tool directly through `dyn MvmClient`, with
      strict inputs, bounded outputs, structured errors, and no lifecycle or
      admission policy in the adapter.
- [x] Prove discovery, capability projection, successful calls, invalid
      requests, backend failures, and bounds against `MockBackend` only.
- [x] Restore `mvmctl ops mcp stdio`, its CLI/audit coverage, and a named
      no-boot roundtrip consumer.
- [x] Supersede withdrawn ADR-002 with the new client-facade decision and sync
      the sprint and refactor trackers.
- [x] Pass formatting, workspace tests/checks, all-target clippy, and gated
      target checks.
- [x] Open the issue-closing pull request, enable auto-merge, and record the
      merge-queue handoff.

## Validation evidence

- `cargo test -p mvm-mcp --all-targets`: 10 protocol tests pass and the stdio
  example builds.
- `just bdd`: 209 scenarios pass and one pre-existing scenario is skipped; the
  MCP help scenario passes.
- `just check-gated`, `cargo check --workspace`, and
  `cargo clippy --workspace -- -D warnings` pass on the macOS host.
- `cargo test --workspace` passes on the rebased commit, including all
  doctests. An earlier cold run hit a transient Cargo metadata failure during
  the final rustdoc invocation; the affected target and the exact-commit full
  rerun both pass.
- The static ARM64 Linux MCP example runs the named no-boot stdio consumer in
  the libkrun builder and completes discovery, catalog, and facade-capability
  calls. Full Linux clippy remains delegated to CI because the shared builder's
  persistent Nix disk is reformatted on every boot and cold jobs exceed its
  fixed 30-minute execution deadline.
- PR #2737 closes issue #2647 and is handed to the required-check merge queue.
