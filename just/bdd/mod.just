set working-directory := "../.."

# Show available subcommands
[private]
default:
    @just --list bdd

# BDD conformance suite (cucumber-rs): builds mvmctl and the TypeScript SDK,
# checks generated SDK artifacts, then runs every Gherkin scenario under
# features/suites/ against it. Scenarios tagged `@wip` describe
# not-yet-implemented coverage and are filtered out by the runner.

# Run the hermetic BDD conformance suite
run:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/e2e-phase-timings.sh
    bdd_phase_summary() {
        local status=$?
        e2e_phase_summary "BDD phase timings" "$status" || true
        exit "$status"
    }
    trap bdd_phase_summary EXIT
    e2e_phase mvmctl-build
    # `user` pulls the sigstore/aws-lc verifier. Keep that native dependency on
    # the standard compiler/linker path: Cranelift leaves its symbols unresolved
    # on Linux, while the rest of this hermetic suite can retain the fast path.
    cargo build --bin mvmctl --features user
    e2e_phase schema-emitters
    ./scripts/cargo-fast.sh build -p xtask
    # The schema emitters `check-stubs` runs, built here rather than through
    # `cargo run` from inside a scenario. `cargo run` takes cargo's package
    # lock, which is global to the machine, so a suite that shells out mid-run
    # serialises against every other cargo process on the host — including ones
    # in unrelated worktrees. That is what made concurrent suites look hung.
    ./scripts/cargo-fast.sh build -p mvm-sdk --features schema --bin emit_workload_schema --bin emit_runtime_schema
    ./scripts/cargo-fast.sh build -p mvm-agentd --features schema --bin emit_protocol_schema
    ./scripts/cargo-fast.sh build -p mvm-core --features schema --bin emit_broker_schema
    ./scripts/cargo-fast.sh build -p mvm-sdk --bin emit_sdk_env --bin emit_sdk_errors --bin emit_sdk_ctors
    e2e_phase typescript-preparation
    just sdk::install-typescript
    just sdk::build-typescript
    # Cargo compiles the runner here as well as executing it.
    e2e_phase conformance-compile-and-run
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd

# KVM-backed live witnesses, selected independently so a second cold boot does
# not consume the existing lifecycle lane's timeout budget.

# Run one tagged subset of live BDD scenarios on a KVM host
live-ci TAG="ci_live":
    # `embed-host-bins` because these scenarios boot real microVMs: `MVM_BDD_LIVE=1`
    # admits the `@live` set, which reaches the builder VM. Without the payload
    # mvmctl refuses at bootstrap. The hermetic `just bdd::run` lane skips those
    # scenarios and so deliberately does not pay the cross-compile.
    #
    # A launch boots only what its home already holds, so the live home is
    # prepared from bytes built here: the workload kernel below, and the host
    # helpers mvmctl spawns per VM, built beside it so no launch compiles one.
    cargo build --bin mvmctl --features user,embed-host-bins
    cargo build -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper --bin mvm-network-endpoint
    "${CARGO_TARGET_DIR:-target}/debug/mvmctl" kernel build --which workload --source download
    @allowed_skips=outside-selected-tag; \
    if [ "${MVM_BDD_ALLOW_RUNTIME_CANDIDATE_SKIP:-false}" = true ] && [ -z "${MVM_E2E_RUNTIME_CANDIDATE_DIR:-}" ]; then allowed_skips="$allowed_skips,needs-runtime-candidate"; fi; \
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" \
    MVM_BDD_LIVE=1 \
    MVM_BDD_ONLY_TAG={{ TAG }} \
    MVM_BDD_STRICT_SKIPS=1 \
    MVM_BDD_ALLOWED_SKIPS="$allowed_skips" \
    cargo test -p mvm-conformance --test conformance --features bdd

# Nightly KVM witness for the one scenario that runs a warm claim end to end:
# warm a parent, claim it, and require the child's run to be anchored in the
# audit chain. Kept out of the merge queue because it prepares its kernel and
# image in a fresh home, which would add minutes to every merge. The run must report
# exactly that scenario passing, so a tag or gate change that quietly skips it
# fails this recipe instead of passing it.

# A warm claim must report startup strictly below 300 ms, and only an
# optimized binary can witness a latency contract: a debug mvmctl spends
# seconds before the claim begins. `release-witness` is `release` without LTO,
# which keeps the extra compile within the lane's budget.

# Run the warm-claim BDD scenario end to end on a KVM host
live-warm-claim:
    #!/usr/bin/env bash
    set -euo pipefail
    profile=release-witness
    cargo build --profile "$profile" --bin mvmctl --features user,embed-host-bins
    # The helpers the live home is checked for must sit beside this mvmctl.
    cargo build --profile "$profile" -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper --bin mvm-network-endpoint
    "${CARGO_TARGET_DIR:-target}/$profile/mvmctl" kernel build --which workload --source download
    log="$(mktemp)"
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/$profile/mvmctl" MVM_BDD_LIVE=1 MVM_BDD_WARM_CLAIM=1 \
      MVM_BDD_ONLY_TAG=warm_claim cargo test -p mvm-conformance --test conformance --features bdd 2>&1 | tee "$log"
    if ! grep -q '1 scenario (1 passed)' "$log"; then
      echo "the warm-claim scenario did not run and pass exactly once" >&2
      exit 1
    fi
