# mvm-capture

`mvm-capture` is the read-only project inspection frontend behind
`mvm capture`. It collects evidence about an existing application environment,
verifies the observations, and resolves them into the canonical mvm workload IR
consumed by the normal build pipeline.

## Who uses it

`mvm-cli` owns the user-facing command and calls this crate. `mvm-capture`
depends on `mvm-contract` for the output workload and on `mvm-sdk` in tests to
check compatibility with the authoring surface. No runtime or VMM crate depends
on capture results directly; they receive the resolved workload through the
ordinary build path.

## How it works

1. `collect` identifies project files, packages, ELF dependencies, and optional
   trace evidence using platform-specific collectors.
2. Observations are stored in the versioned `CaptureReportV1` rather than being
   immediately converted into build instructions.
3. `verify` checks report consistency and the evidence needed by each finding.
4. `resolve` converts the verified report into `mvm_contract::ir::Workload`.
5. The existing SDK compiler and Nix renderer process that workload exactly as
   if it had been authored manually.

Collection is read-only by default and never executes discovered files.
Tracing runs only a command the user explicitly supplied. Linux-specific ELF
and process collectors are runtime-gated; portable collection returns clear
unsupported evidence rather than pretending it inspected Linux state.

## Main modules

| Module | Responsibility |
|---|---|
| `collect::project` | Project structure and entrypoint evidence |
| `collect::package` | Language/package-manager observations |
| `collect::elf` | Native binary and shared-library inspection |
| `collect::trace` | Explicit-command runtime evidence |
| `report` | Versioned, serializable capture record |
| `verify` | Evidence and consistency validation |
| `resolve` | Capture report to canonical workload IR |

## Developing

Run `cargo test -p mvm-capture`. Collector changes need fixture tests for both
recognized and ambiguous projects, and failure paths must return evidence-rich
errors without executing or mutating the inspected tree.
