# ADR-050: `mvm capture` — Project-Environment Capture Frontend

Backing: shipped-source
Validation: `cargo test -p mvm-capture` and capture CLI integration tests

## Status

Accepted — initial slice implemented.

## Context

`mvm` already compiles SDK-authored or manually-written workload definitions
into a canonical IR and renders them through the existing Nix pipeline. Users
frequently need to move an existing Linux project into that pipeline: they
know the project builds and runs on a given host, but they do not yet have an
MVM definition. We need a frontend that inspects the project and host,
produces a reviewable artifact, and lowers it into the same IR the rest of
`mvm` already consumes.

This is intentionally **not** whole-machine cloning. The goal is to capture
the environment required to build and run a project, not to reproduce every
file, user, service, or hardware detail of the source machine.

## Decision

Add a new `mvm capture` capability to the CLI and a new `mvm-capture` crate
that implements the isolated host-inspection component.

### Architecture

```text
Linux project and selected commands
                ↓
        raw Capture Report IR   (mvm-capture)
                ↓
 deterministic resolution and policy (mvm-capture)
                ↓
       existing MVM environment IR   (mvm_contract::ir)
                ↓
         existing Nix renderer       (mvm_sdk::compile)
                ↓
 clean build, boot, and command verification
```

The host-inspection logic lives in `crates/mvm-capture/`. It is gated by
platform so the crate compiles on macOS and Windows as a safe stub, while
Linux-specific collectors run only on Linux. The CLI group in
`crates/mvm-cli/src/commands/capture/` orchestrates the three user-facing
commands: `capture project`, `capture resolve`, and `capture verify`.

### Two representations

1. **Capture Report (`CaptureReportV1`)**: a versioned, evidence-oriented
   JSON document that records what was observed. It contains observations,
   platform facts, unresolved items, and warnings. It deliberately separates
   observations from policy decisions.

2. **Canonical MVM IR (`mvm_contract::ir::Workload`)**: produced by
   deterministic resolution from the report. This is the same IR used by the
   SDK and the Nix renderer; no second environment model is introduced.

### Why not part of `mvmd`

Capture is a build-time, user-driven developer tool. It runs on the host,
reads arbitrary project directories, and performs no admission decisions.
`mvmd` is the production launch/runtime authority; capture does not belong on
that path and must not affect microVM startup time or security posture.

### Why raw observations and canonical IR are separate

Observations are untrusted host input. Keeping them separate from the desired-
state IR lets reviewers inspect the evidence before trusting the resolved
workload, and lets resolution be deterministic, auditable, and replayable from
a stored report.

### Why project-scoped capture precedes whole-host capture

Project-scoped capture bounds the blast radius: it inspects only the named
directory, respects ignore files, and refuses to execute discovered scripts.
Whole-host capture would require broader privileges and a larger security
review; project capture is the smallest unit that delivers end-to-end value.

### Why verification is required before claiming reproducibility

A resolved workload is only a declaration. The rendered Nix must build, the
microVM must boot, and the explicit verification command must replay
successfully before `mvm capture verify` can report success. This first slice
renders the Nix artifacts and records the verification command; full
boot-and-replay verification runs in environments with the required builder VM
backend.

## Consequences

- `mvm-capture` adds a small dependency surface: it reuses `mvm-contract`,
  `serde`, `sha2`, and a few workspace utilities.
- Linux-specific collectors (`dpkg`, `which`, executable metadata) are
  isolated; non-Linux builds remain green.
- Secret values are never serialized: `.env` files are classified as secret
  and their content hashes and paths are redacted from the report.
- Native package names (e.g. Debian packages) are kept as unresolved items
  rather than guessed into `nixpkgs` attributes.

## Related

- `specs/plans/2026-08-20-mvm-capture.md`
- `crates/mvm-capture/`
- `crates/mvm-cli/src/commands/capture/`
- `tests/fixtures/capture/rust-hello/`
