# ADR-010: Code-quality enforcement — mechanical, not aspirational

## Status

Accepted.

## Context

A code-quality bar that lives only in review conventions drifts. Two
kinds of rule need mechanical enforcement so a violating PR fails before
review, not during it: a small set of workspace-wide lint rules, and a
larger set of architecture-specific invariants unique to this codebase
(no spec references leaking into code comments, no `Display`/`Debug` on
a secret-bearing type, no shell-out to host Nix, exactly two root
feature surfaces, and more) that no off-the-shelf lint can express.

## Decision

### Workspace lint

```toml
[workspace.lints.clippy]
too_many_arguments = "deny"
```

`#[allow(clippy::too_many_arguments)]` is banned outright in hand-written
code — no exceptions. A function that trips the lint gets refactored into
a config/params struct instead. The one standing exception is
bindgen-generated FFI (`crates/deps/libkrun-sys/src/sys.rs`), which is
generated, not hand-written.

### `unsafe_code` — opt-in `forbid`, not a workspace-wide ban

There is no workspace-wide `unsafe_code = "deny"`. Instead, the two
crates that parse untrusted bytes into structures where a memory-safety
bug would be worst — `mvm-ext4` (the deterministic ext4 image writer) and
`mvm-oci` (OCI layer unpacking) — declare `#![forbid(unsafe_code)]` at
the crate root. Crates that genuinely need `unsafe` (FFI bindings, vsock
ioctls, and similar host-integration work) use it directly, scoped to
the block that needs it, with no lint ceremony required.

### Architectural invariants as dedicated `xtask` checks

Every architecture-specific rule is a small, independently testable Rust
module under `xtask/src/check_*.rs`, each wired as its own named step in
`ci.yml`'s `lint` job — so a violation fails a specific, greppable check
name instead of a generic warning. Representative examples: no spec
references in source comments, no `Display`/`Debug` derive on a
secret-named type, no shell-out to host Nix, no forbidden dependency
family, exactly two root feature surfaces (`host`/`user`), the claims
ledger and trust-gradient tables stay in sync with the code that backs
them, `mvm-core`'s default build stays free of an async runtime, and the
`mvmctl` default dependency closure stays within budget. Adding a new
architectural rule means adding a new `xtask` check, not amending a
shared config file — `ci.yml`'s `lint` job is the actual index of what's
enforced.

### `cargo fmt` and `cargo clippy`

`cargo fmt -- --check` and `cargo clippy --all-targets -- -D warnings`
gate every push through `ci.yml`'s `lint` job, and run locally on every
commit via `.githooks/pre-commit` (`cargo fmt --all`, auto-fixing and
re-staging, then `cargo clippy --workspace --all-targets -- -D warnings`,
skippable per-commit via `MVM_SKIP_CLIPPY=1` for fast iteration — CI
still gates the merge).

## Consequences

The bar is mechanical and centralized: one clippy invocation catches
argument-count drift, and a new architectural rule is a new, nameable
`xtask` check rather than a review-thread convention that has to be
re-litigated on every PR.

Growing the invariant set means growing `xtask`, one module per rule —
there is no single manifest enumerating every check; `ci.yml`'s `lint`
job step list is the source of truth for what's currently gated.

No file-size cap, no doc-comment coverage gate, and no `unwrap`/`println`
ban exist today. Code quality here is enforced narrowly — argument
count, unsafe-free parsing in the two highest-risk crates, and a growing
set of named architectural invariants — rather than broadly through
style or coverage metrics. A broader bar is a deliberate, separate
`xtask` check the day someone decides to add it, not an implicit
aspiration.
