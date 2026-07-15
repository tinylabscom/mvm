---
title: "ADR-010: Code-quality enforcement — `forbid(unsafe_code)`, lint deny list, file-size cap, builder structs"
status: Proposed
date: 2026-05-07
related: ADR-001 (security posture), plan 60-mvm-libkrun-migration
---

## Status

Proposed. CI gating lands in Phase 0.

## Context

The user's code-quality bar for this migration:

> Code that's documented, broken into small files, idiomatic Rust, builder-pattern instead of long arg lists (no `#[allow(clippy::too_many_arguments)]` ever), tests everywhere (unit, integration, fuzz, smoke), no AI-smell.

A good bar, but only if it's enforced in CI. Otherwise it drifts. This ADR codifies the lint set and file-size discipline so PRs that violate the bar fail before review.

## Decision

The following are CI-enforced, repo-wide, with no `#[allow(...)]` exceptions. Any exception requires its own ADR.

### Workspace lints (in root `Cargo.toml`)

```toml
[workspace.lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
too_many_arguments = "deny"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
```

Crates that genuinely need `unsafe` (FFI to libkrun/libkrun, vsock ioctls, `mlock`) flip `unsafe_code = "allow"` only at the **module** scope (`#![allow(unsafe_code)]` at the top of `unsafe-bridge.rs`), and the module's name + scope is reviewed by the type-design-analyzer agent.

### File-size soft cap

400 LOC. Soft cap because a generated file (e.g., `_types.rs` from a Rust→Python stub generator) may exceed it. Hard exceptions go in `tools/lint/file-size-overrides.txt`. CI prints a warning (not failure) when a file crosses 400 LOC.

### Builder pattern instead of long arg lists

Functions taking >5 arguments use a struct + `bon`-derived builder. Crate dep: `bon = "3"`. Eliminates `clippy::too_many_arguments` cleanly.

### Test discipline

- Unit tests live next to code (`#[cfg(test)] mod tests { ... }`).
- Integration tests in `tests/`.
- Fuzz harnesses in `crates/mvm-guest/fuzz/` (existing convention).
- CI lint forbids `unwrap()` and `expect()` outside `tests/` and `examples/`.
- CI lint forbids `println!` / `eprintln!` outside `mvm-cli/src/output.rs` (the one CLI output module).

### Doc discipline

- All `pub` items have doc comments (the `missing_docs = "warn"` lint catches drift).
- `cargo doc --workspace --no-deps -D warnings` runs in CI; broken doc links fail the build.

### Forbidden patterns

- `#[allow(clippy::too_many_arguments)]` — banned outright. No exceptions.
- `Display` / `Debug` derivation on secret-bearing types (`secrecy::SecretBox<T>` and types containing one). Custom CI lint enforces.
- `==` comparison on cryptographic types (use `subtle::ConstantTimeEq`). Custom CI lint.
- Bare `tokio::spawn` (must use `mvm_core::trace::spawn_traced` to propagate trace context). Custom CI lint.

## Consequences

**Positive**:
- Code-quality bar is mechanical, not aspirational.
- AI-generated code that drifts toward verbose patterns gets caught.
- New contributors learn the conventions from CI feedback, not from code review back-and-forth.

**Negative**:
- `bon` adds a build dependency. Acceptable — it's small, popular, and well-maintained.
- Some PRs will fail CI for trivial reasons (e.g., a 401-LOC file crosses the soft cap warning). Explicit warning, not failure, mitigates this.

**Neutral**:
- The lint deny list will grow. Each addition gets a one-line entry in this ADR's "Decision" section.

## Alternatives considered

- **Style-only review**: rejected. Doesn't scale; drift accumulates.
- **`rustfmt` only**: rejected. Formatting ≠ quality; the lint set is the actual bar.
- **Strict file-size hard cap**: rejected. Generated code legitimately exceeds; hard cap creates churn.

## Threat model impact

- `forbid(unsafe_code)` reduces the attack surface for memory-safety bugs in non-FFI code.
- `subtle::ConstantTimeEq` enforcement closes timing side-channels on cryptographic comparisons.
- Trace-context propagation (`spawn_traced`) ensures every action is auditable, even from background tasks.

## Compliance impact

- SOC 2: positive — code-quality controls map to "Change Management" trust services criterion.
- All others: neutral.
