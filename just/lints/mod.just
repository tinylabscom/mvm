# ── Model / Conformance gates ────────────────────────────────────────────
# R1: the model is the single source. Verify model/*.toml, the generated

# CONFORMANCE.md, and the honesty/deferral meta-gates.
model:
    cargo run -p xtask -- check-conformance
    cargo run -p xtask -- check-honesty
    cargo run -p xtask -- check-deferrals

# Regenerate everything the model owns: CONFORMANCE.md.
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
    ./scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings

# Compile the cucumber conformance target. It sits behind the `bdd` feature to
# stay out of `cargo nextest run --workspace` (nextest lists tests via `--list`,
# which a `harness = false` target cannot answer), and `--all-targets` above
# honors `required-features`, so nothing else builds it — a struct change

# elsewhere in the workspace can break it unnoticed.
clippy-bdd:
    ./scripts/cargo-stable.sh clippy -p mvm-conformance --tests --features bdd -- -D warnings
# ── Claim mutation testing ───────────────────────────────────────────────
# Verify the committed mutation surface still matches the claims ledger.

# Milliseconds, needs no cargo-mutants — this is the part CI runs per PR.
mutation-surface:
    cargo run -p xtask -- check-mutation-witnesses

# Mutate the claim surface and ratchet survivors against the baseline.
# HOURS: this is the nightly lane's command, not an inner-loop check.
# Needs cargo-nextest and the exact cargo-mutants pinned under
# [workspace.metadata.mvm.toolchain] in Cargo.toml — the run refuses any other,
# because accepted misses are matched on the text that version renders.
#
# No isolation wrapper here on purpose. `--run` executes security code with
# its check removed, so it must not reach a real mvm state root — and that
# confinement lives where cargo-mutants is actually spawned, so every
# caller gets it rather than each one carrying its own copy. This recipe

# had no wrapper at all until that landed, which is the failure mode.
mutation-witnesses:
    cargo run -p xtask -- check-mutation-witnesses --run

# Re-pin the surface after a witness legitimately moved. Cheap, and keeps
# the stated reasons on existing accepted misses. Add --run to also

# re-record the misses themselves (hours, and it discards those reasons).
mutation-repin:
    cargo run -p xtask -- check-mutation-witnesses --write-baseline
