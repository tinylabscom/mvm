# Stopped-machine log failures identify missing state

## Problem

`machine logs` exposed the low-level no-capture error when a stopped or removed
machine had no state directory. The message listed internal capture paths but did
not explain that the machine might never have booted or might already have been
removed.

## Delivered behavior

When no output source exists, the CLI checks the established machine-state path.
If that directory is absent, it names the path, explains the two likely lifecycle
states, and directs the operator to `machine ls`. Other no-capture cases retain
their source-by-source diagnostic.

## Validation

- focused `mvm-cli` log tests cover the missing-state error and operator guidance;
- the existing no-capture regression now verifies the lifecycle-aware message;
- workspace CI remains the merge gate for formatting, Clippy, and full tests.
