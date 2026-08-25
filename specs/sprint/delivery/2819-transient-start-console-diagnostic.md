# Transient start failures preserve the guest console diagnostic

## Problem

A transient machine whose backend failed during startup lost its state directory
before the CLI emitted the guest console. Operators therefore saw only the host
startup error, while the guest boot or init failure that explained it was removed.

## Delivered behavior

The transient boot failure path emits the bounded guest console diagnostic before
removing the machine state directory. Cleanup still runs and the original startup
error remains the command result; the diagnostic only restores the evidence that
would otherwise be discarded.

## Validation

- the focused startup error path is present before state-directory cleanup;
- workspace all-target Clippy passes with warnings denied;
- the repository action workflow lint passes.
