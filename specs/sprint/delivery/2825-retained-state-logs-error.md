# Retained machine state gets a distinct log diagnostic

## Problem

A machine with a surviving state directory but no live broker, transcript, or
console capture received the same guidance as a removed or never-booted machine.
That obscured the useful fact that persisted state was still available for
inspection.

## Delivered behavior

The no-capture path now identifies the retained state directory, lists every
missing capture source, explains the interrupted-boot or manual-cleanup cases,
and directs the operator to `machine inspect` for the named machine.

## Validation

- 39 focused `mvm-cli` log tests pass;
- the retained-state regression checks the state path, all missing sources, the
  likely cause, and the exact inspection command;
- workspace CI remains the merge gate for formatting, Clippy, and full tests.
