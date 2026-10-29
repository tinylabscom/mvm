set working-directory := "../.."

# Show available subcommands
[private]
default:
    @just --list lints

# ── Model / Conformance gates ────────────────────────────────────────────
# R1: the model is the single source.

# Verify model/*.toml, the generated docs/CONFORMANCE.md, and the honesty/deferral gates
model:
    cargo run -p xtask -- check-conformance
    cargo run -p xtask -- check-honesty
    cargo run -p xtask -- check-deferrals

# Regenerate everything the model owns: docs/CONFORMANCE.md.
model-write:
    cargo run -p xtask -- check-conformance --write

# R2: verify no open/some-true claim is asserted as established in docs.
honesty:
    cargo run -p xtask -- check-honesty

# Verify no deferral marker (`TODO`, `FIXME`, `unimplemented!`) is left in the tree.
deferrals:
    cargo run -p xtask -- check-deferrals

# ── Lint & Format ────────────────────────────────────────────────────────

# Format all code
fmt:
    cargo fmt --all

# Check formatting (no changes)
fmt-check:
    cargo fmt --all -- --check

# Run clippy with warnings as errors
clippy:
    ./scripts/cargo.sh clippy --workspace --all-targets -- -D warnings

# Compile the cucumber conformance target. It sits behind the `bdd` feature to
# stay out of `cargo nextest run --workspace` (nextest lists tests via `--list`,
# which a `harness = false` target cannot answer), and `--all-targets` above
# honors `required-features`, so nothing else builds it — a struct change
# elsewhere in the workspace can break it unnoticed.

# Run clippy over the cucumber conformance target (`--features bdd`)
clippy-bdd:
    ./scripts/cargo.sh clippy -p mvm-conformance --tests --features bdd -- -D warnings
