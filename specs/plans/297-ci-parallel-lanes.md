# Plan 297 — Parallel pull-request CI lanes

**Status:** Complete

## Goal

Reduce pull-request and merge-queue critical-path time by running independent
lint and Linux-only test coverage concurrently, while preserving the existing
required check names and every required coverage surface.

## Work

- [x] Split compiler lint, policy checks, and feature-gated coverage into
      independent Linux jobs.
- [x] Split the workspace test lane from no-std, filesystem, and conformance
      coverage.
- [x] Preserve `Lint (fmt + clippy + policy)` and `Test` as conclusive
      aggregate checks for branch protection and merge-queue admission.
- [x] Keep the PR workflow free of branch-scoped Cargo target caches and avoid
      repeating the workspace-wide `test-support` suite.
- [x] Put Linux-only coverage in one reusable script so the moved checks have
      one source of truth.
- [x] Validate workflow syntax, structural guards, focused tests, and the
      workspace compile/test gates.

## Guardrails

- No required check is renamed, skipped, or replaced by an unconditional green
  compatibility job.
- The Nix merge-queue check remains required and continues to run only on
  `merge_group` and manual dispatch.
- The parallel lanes do not share mutable Cargo target directories or upload
  large branch-scoped build caches.
