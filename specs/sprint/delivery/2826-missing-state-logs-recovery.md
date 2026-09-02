# Missing machine state includes a concrete recovery command

## Problem

The missing-state log diagnostic explained that a machine could have been
removed or never booted, but stopped short of giving the operator a command to
verify that lifecycle state.

## Delivered behavior

The error now directs the operator to `machine ls` to verify that the named
machine still exists. The recovery command stays adjacent to the missing-state
cause, while retained-state failures continue to direct operators to
`machine inspect`.

## Validation

- 39 focused `mvm-cli` log tests pass;
- the missing-state regression asserts the concrete `machine ls` guidance;
- workspace CI remains the merge gate for formatting, Clippy, and full tests.
