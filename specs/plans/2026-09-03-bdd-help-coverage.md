# Preserve alternative CLI help coverage

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE**

## Goal

Keep the BDD contract that exercises both alternative help entry points for
every CLI command and nested subcommand, while removing the serial subprocess
bottleneck that made the scenario disproportionately slow.

## Delivery

- [x] Retain both `mvmctl <path> -h` and `mvmctl help <path>` for every command
      path exposed by the generated command tree.
- [x] Divide command paths across a bounded number of scoped workers, with
      sequential subprocess execution inside each worker.
- [x] Aggregate every width and wrapping violation instead of failing after
      the first worker result.
- [x] Compile and lint the feature-gated conformance target with warnings
      denied.
- [x] Run the complete hermetic BDD suite with the scenario enabled.

## Validation

- `cargo check -p mvm-conformance --test conformance --features bdd`
- `cargo clippy -p mvm-conformance --test conformance --features bdd -- -D warnings`
- `just bdd`: 248 scenarios, 247 passed, 1 capability skip; 942 steps,
  941 passed, 1 skipped.

