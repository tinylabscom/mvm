set working-directory := "../.."

# BDD conformance suite (cucumber-rs): builds mvmctl and the TypeScript SDK,
# checks generated SDK artifacts, then runs every Gherkin scenario under
# features/suites/ against it. Scenarios tagged `@wip` describe

# not-yet-implemented coverage and are filtered out by the runner.
run:
    # `user` pulls the sigstore/aws-lc verifier. Keep that native dependency on
    # the standard compiler/linker path: Cranelift leaves its symbols unresolved
    # on Linux, while the rest of this hermetic suite can retain the fast path.
    cargo build --bin mvmctl --features user
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
    just sdk::install-typescript
    just sdk::build-typescript
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd

# KVM-backed merge-queue witness for the cheap documented machine lifecycle.
# The tag selector keeps registry/build-heavy live scenarios in their dedicated

# witness lanes while proving that the public commands operate a real guest.
live-ci:
    # `embed-host-bins` because these scenarios boot real microVMs: `MVM_BDD_LIVE=1`
    # admits the `@live` set, which reaches the builder VM. Without the payload
    # mvmctl refuses at bootstrap. The hermetic `just bdd::run` lane skips those
    # scenarios and so deliberately does not pay the cross-compile.
    cargo build --bin mvmctl --features user,embed-host-bins
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" MVM_BDD_LIVE=1 MVM_BDD_ONLY_TAG=ci_live cargo test -p mvm-conformance --test conformance --features bdd

# Nightly KVM witness for the one scenario that runs a warm claim end to end:
# warm a parent, claim it, and require the child's run to be anchored in the
# audit chain. Kept out of the merge queue because it acquires its image from a
# fresh home, which would add minutes to every merge. The run must report
# exactly that scenario passing, so a tag or gate change that quietly skips it
# fails this recipe instead of passing it.
live-warm-claim:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --bin mvmctl --features user,embed-host-bins
    log="$(mktemp)"
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" MVM_BDD_LIVE=1 MVM_BDD_WARM_CLAIM=1 \
      MVM_BDD_ONLY_TAG=warm_claim cargo test -p mvm-conformance --test conformance --features bdd 2>&1 | tee "$log"
    if ! grep -q '1 scenario (1 passed)' "$log"; then
      echo "the warm-claim scenario did not run and pass exactly once" >&2
      exit 1
    fi
