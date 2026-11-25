# mvm — Firecracker MicroVM Development Tool
# https://github.com/casey/just
#
# One file, one recipe per job. A variant is the recipe's first argument
# (`just test scoped mvm-core`, `just check gated`), never a second recipe, and
# a recipe that only makes sense with a variant prints its variants when run
# bare. Every multi-line body is a shebang script: without one each line runs
# in its own shell, and no shell can parse half of a `case`.

set dotenv-load := false
set positional-arguments := true

# Show the recipes
default:
    @just --list


# The native per-VM helpers are separate bin targets, so a workspace build
# covers them.
#
#   embed [cargo args]        an mvmctl that carries the Linux host binaries the
#       builder VM needs, plus the per-VM helpers beside it. Not required to
#       boot a VM: an mvmctl built without them builds them itself the first
#       time it needs a builder VM. It and a plain `cargo build` write the same
#       `target/<profile>/mvmctl` under different feature sets, so alternating
#       the two relinks mvmctl; that is why this is not part of bare `build`.
#       Bare, it writes `target/debug/mvmctl` — pass `--release` if the mvmctl
#       you invoke is the release one, or that binary is left untouched.
#   release                   the release workflow's feature set
#       (`MVMCTL_RELEASE_FEATURES`). `release-channel` is deliberately absent:
#       it would resolve artifacts from the published channel, not this checkout.
#   supervisors [cargo args]  the per-VM helper bins, into `target/<profile>/`
#       where `aux_bin::resolve` looks. Pass `--release` for a release mvmctl:
#       the resolver searches `target/release` before `target/debug`, so a
#       release mvmctl with no release helper falls through to a stale debug one.
#   libkrun-supervisor [cargo args]  kept out of `supervisors` so standard
#       builds never probe for libkrun.h or enable native libkrun linkage.
#   kernel                    the dm-verity-capable workload kernel, into the
#       local mvm cache. MVM_KERNEL_SOURCE=download uses the hash-verified
#       release artifact; =auto prefers it and compiles when there is none.
#   overlay [args]            the version-matched read-only runtime overlay
#       (`--force`, `--source build`).
#   sdk [python|typescript]   the publishable SDK artifacts, no Rust build.

# Build the workspace, or: embed, release, supervisors, libkrun-supervisor, kernel, overlay, sdk
build WHAT="" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    what="${1:-}"
    [ "$#" -eq 0 ] || shift
    # Make rust-objcopy able to load libLLVM, or the strip step aborts and every
    # binary linked here is emitted unstripped.
    objcopy_env() { source "{{justfile_directory()}}/scripts/macos-objcopy-env.sh" "{{justfile_directory()}}"; }
    # `mvmctl` and these `[[bin]]` targets live in different packages, so
    # building one does not build the others. The same profile arguments go to
    # each so the adjacent-executable lookup finds the matching helper.
    supervisors() {
      objcopy_env
      ./scripts/cargo.sh build -p mvm-hostd --bins "$@"
      ./scripts/cargo.sh build -p mvm-gpu --bin mvm-gpu-endpoint "$@"
    }
    case "$what" in
      "") ./scripts/cargo.sh build --workspace ;;
      embed)
        supervisors "$@"
        FEATURES="${MVM_EMBED_FEATURES:-embed-host-bins}"
        ./scripts/cargo.sh build --features "$FEATURES" "$@"
        ;;
      release) cargo build --release --features host,user,release-artifact-bootstrap,embed-host-bins ;;
      supervisors) supervisors "$@" ;;
      libkrun-supervisor)
        objcopy_env
        ./scripts/cargo.sh build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys "$@"
        ;;
      kernel) cargo run -- kernel build --which workload ;;
      overlay) bin/dev dev runtime-overlay build "$@" ;;
      sdk)
        lang="${1:-all}"
        case "$lang" in
          all|python|typescript) ;;
          *) echo "unknown SDK language: $lang (expected all, python, or typescript)" >&2; exit 1 ;;
        esac
        [ "$lang" = typescript ] || uv build crates/mvm-sdk/sdks/python --out-dir crates/mvm-sdk/sdks/python/dist
        [ "$lang" = python ] || npm --prefix crates/mvm-sdk/sdks/typescript run build
        ;;
      *)
        echo "unknown build target: $what" >&2
        echo "usage: just build [embed|release|supervisors|libkrun-supervisor|kernel|overlay|sdk] [args]" >&2
        exit 1
        ;;
    esac


# `--all-targets` is narrower than it sounds: it skips any target behind
# `required-features`, and on macOS it cannot compile `cfg(target_os = "linux")`
# files at all.
#
#   linux [TARGET]     every crate's lib for Linux (glibc) via zig, no Docker.
#       Lib-only: linking the libkrun-sys bins needs target libkrun. musl is not
#       the default — libc's ioctl request arg is c_int there vs c_ulong on
#       glibc, so the COW FICLONE path only type-checks against glibc.
#   gated [TARGET]     what bare `check` cannot see: Linux-gated *test* files
#       (`linux` is --lib only) and targets behind `required-features`
#       (mvm-conformance's cucumber runner). Both surface otherwise only in CI,
#       in "Build workspace tests". `cargo-zigbuild check` is the binary's own
#       subcommand; `cargo zigbuild check` errors on the argument. A cold run
#       costs ~8 min, which is why it is not in `ci`: run it before pushing
#       anything that changes a shared type's shape.
#   embedded [TARGET]  bare-metal no_std proof for mvm-contract. A `-none-elf`
#       target has only core + alloc, stricter than the wasm32 gate.
#   ebpf               the host-side eBPF object for vsock egress telemetry.
#       Needs nightly Rust and `cargo install bpf-linker`.
#   toolchain          ordinary builds use the pinned stable compiler.
#
# `linux` and `gated` need `just setup toolchain`.

# Type-check the workspace, or: gated, linux, embedded, ebpf, toolchain
check WHAT="" TARGET="":
    #!/usr/bin/env bash
    set -euo pipefail
    linux="${2:-x86_64-unknown-linux-gnu}"
    case "${1:-}" in
      "") ./scripts/cargo.sh check --workspace --all-targets ;;
      linux) ./scripts/cargo.sh zigbuild --target "$linux" --workspace --lib --all-features ;;
      gated)
        ./scripts/cargo.sh --direct cargo-zigbuild check --target "$linux" --workspace --all-targets
        ./scripts/cargo.sh check -p mvm-conformance --all-targets --features bdd
        ;;
      embedded)
        target="${2:-riscv32imac-unknown-none-elf}"
        rustup target add "$target"
        cargo build -p mvm-contract --lib --target "$target"
        ;;
      ebpf)
        cd crates/mvm-hostd/ebpf
        PATH="${HOME}/.cargo/bin:${PATH}" cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
        ;;
      toolchain) ./scripts/check-cargo-toolchain.sh ;;
      *)
        echo "unknown check: $1" >&2
        echo "usage: just check [gated|linux|embedded|ebpf|toolchain] [TARGET]" >&2
        exit 1
        ;;
    esac


# Bare (or with a nextest filter such as "my_test" or "test(my_*)") this runs
# the workspace and keeps the full output at target/nextest/last-run.log: an
# intermittent failure in a suite this size is only diagnosable from the panic
# and captured streams nextest prints beside it. `pipefail` is load-bearing —
# without it the recipe reports `tee`'s status and a failing suite exits 0.
#
#   scoped CRATE [FILTER] [--lib | --test NAME]  one crate, optionally one
#       target, so unrelated test binaries are not compiled. FILTER "" runs
#       every test in the target.
#   doc              the workspace doctests, which nextest does not run.
#   ci [FILTER]      the nextest `ci` profile: no retries, slow-test warnings,
#       a JUnit report at target/nextest/ci/junit.xml.
#   bdd              the hermetic cucumber suite: builds mvmctl and the
#       TypeScript SDK, checks generated SDK artifacts, then runs every Gherkin
#       scenario under features/suites/. `@wip` scenarios are filtered out.
#   sdk [python|typescript|kotlin]  the language SDKs' own unit suites, which
#       are not cargo targets and so are not covered by anything above.
#   fuzz TARGET [SECONDS]  a cargo-fuzz target of mvm-agentd
#       (fuzz_guest_request, fuzz_authenticated_frame); 300 s by default.

# Run all tests with nextest [FILTER], or: scoped, doc, ci, bdd, sdk, fuzz
test *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    case "${1:-}" in
      scoped)
        ./scripts/require-nextest.sh
        crate="${2:?usage: just test scoped CRATE [FILTER] [--lib | --test NAME]}"
        filter="${3:-}"
        shift "$(( $# < 3 ? $# : 3 ))"
        args=(nextest run -p "$crate" "$@")
        if [ -n "$filter" ]; then
          args+=(-E "test($filter)")
        fi
        exec ./scripts/cargo.sh "${args[@]}"
        ;;
      doc) ./scripts/cargo.sh test --workspace --doc ;;
      ci)
        ./scripts/require-nextest.sh
        if [ -n "${2:-}" ]; then
          ./scripts/cargo.sh nextest run --workspace --profile ci -E "test($2)"
        else
          ./scripts/cargo.sh nextest run --workspace --profile ci
        fi
        ;;
      bdd)
        source scripts/e2e-phase-timings.sh
        bdd_phase_summary() {
            local status=$?
            e2e_phase_summary "BDD phase timings" "$status" || true
            exit "$status"
        }
        trap bdd_phase_summary EXIT
        e2e_phase mvmctl-build
        cargo build --bin mvmctl --features user
        e2e_phase schema-emitters
        ./scripts/cargo.sh build -p xtask
        # The schema emitters `check-stubs` runs, built here rather than through
        # `cargo run` from inside a scenario. `cargo run` takes cargo's package
        # lock, which is global to the machine, so a suite that shells out
        # mid-run serialises against every other cargo process on the host.
        ./scripts/cargo.sh build -p mvm-sdk --features schema --bin emit_workload_schema --bin emit_runtime_schema
        ./scripts/cargo.sh build -p mvm-agentd --features schema --bin emit_protocol_schema
        ./scripts/cargo.sh build -p mvm-core --features schema --bin emit_broker_schema
        ./scripts/cargo.sh build -p mvm-sdk --bin emit_sdk_env --bin emit_sdk_errors --bin emit_sdk_ctors
        e2e_phase typescript-preparation
        just setup typescript
        just build sdk typescript
        # Cargo compiles the runner here as well as executing it.
        e2e_phase conformance-compile-and-run
        CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" ./scripts/cargo.sh test -p mvm-conformance --test conformance --features bdd
        ;;
      sdk)
        lang="${2:-all}"
        case "$lang" in
          all|python|typescript|kotlin) ;;
          *) echo "unknown SDK language: $lang (expected all, python, typescript, or kotlin)" >&2; exit 1 ;;
        esac
        if [ "$lang" = all ] || [ "$lang" = python ]; then
          # `--extra schema` installs pydantic; without it the `derive_schema`
          # tests fail on an ImportError rather than being skipped.
          uv run --directory crates/mvm-sdk/sdks/python --group dev --extra schema pytest -q
        fi
        if [ "$lang" = all ] || [ "$lang" = typescript ]; then
          just setup typescript
          npm --prefix crates/mvm-sdk/sdks/typescript run test
        fi
        if [ "$lang" = all ] || [ "$lang" = kotlin ]; then
          # Needs only kotlinc and a JDK (sdks/kotlin/scripts/install-kotlinc.sh).
          crates/mvm-sdk/sdks/kotlin/scripts/test.sh
        fi
        ;;
      fuzz)
        target="${2:?usage: just test fuzz TARGET [SECONDS]}"
        cd crates/mvm-agentd
        cargo +nightly fuzz run "$target" -- -max_total_time="${3:-300}"
        ;;
      *)
        ./scripts/require-nextest.sh
        mkdir -p target/nextest
        if [ -n "${1:-}" ]; then
          ./scripts/cargo.sh nextest run --workspace -E "test($1)" 2>&1 | tee target/nextest/last-run.log
        else
          ./scripts/cargo.sh nextest run --workspace 2>&1 | tee target/nextest/last-run.log
        fi
        ;;
    esac


# `all` is what CI's lint jobs run, including the compiler-pin check.
# `clippy-bdd` exists because the cucumber target sits behind the `bdd` feature
# (nextest cannot list a `harness = false` target) and `--all-targets` honors
# `required-features`, so nothing else compiles it. `supply-chain` is
# cargo-audit + cargo-deny, the nightly `security.yml` lanes, and is not in `all`.

# Lint: all (default), or one of fmt, clippy, clippy-bdd, model, policy, supply-chain
lint SUBSET="all":
    #!/usr/bin/env bash
    set -euo pipefail
    fmt() { cargo fmt --all -- --check; }
    clippy() { ./scripts/cargo.sh clippy --workspace --all-targets -- -D warnings; }
    clippy_bdd() { ./scripts/cargo.sh clippy -p mvm-conformance --tests --features bdd -- -D warnings; }
    model() {
      cargo run -p xtask -- check-conformance
      cargo run -p xtask -- check-honesty
      cargo run -p xtask -- check-deferrals
    }
    policy() { cargo run -p xtask -- check-all; }
    case "$1" in
      fmt) fmt ;;
      clippy) clippy ;;
      clippy-bdd) clippy_bdd ;;
      model) model ;;
      policy) policy ;;
      supply-chain)
        cargo audit
        cargo deny check
        ;;
      all)
        fmt
        clippy
        clippy_bdd
        model
        policy
        ./scripts/check-cargo-toolchain.sh
        ;;
      *)
        echo "Unknown lint subset: $1" >&2
        echo "Valid subsets: fmt, clippy, clippy-bdd, model, policy, supply-chain, all" >&2
        exit 1
        ;;
    esac

# Format all code
fmt:
    cargo fmt --all

# Full CI gate: lint + test + doctests + hermetic BDD + model gates.
ci: lint test (test "doc") (test "bdd")

# Run this checkout's mvmctl with arguments (`cargo run --`)
run *ARGS:
    ./scripts/cargo.sh run -- "$@"


# Every lane here boots real guests; none is part of `ci`.
#
#   docs                 every documented example against a real host. Needs an
#       artifact-warm home: defaults to the real `~/.mvm`, override with
#       MVM_E2E_HOME. Follows each guest's console (MVM_E2E_FOLLOW=0 silences
#       it) and sweeps its own machines on entry and exit.
#   launch               a guest through every README-documented entry point
#       (CLI verbs, both SDKs, the Rust library facade) on whatever backend this
#       host has; deliberately not narrowed to the merge-queue subset.
#   live-ci [TAG]        one tagged subset of the live BDD scenarios on a KVM
#       host (default `ci_live`).
#   smoke-fresh-install [VERSION]  install a release into a throwaway HOME with
#       this checkout's install.sh and run the README's first command; the
#       release workflow runs the same script before it promotes a tag.
#   live-fork-witness TARGET [BOOT_IMAGE_TAG]  the Firecracker live-parent fork
#       witness on a remote KVM host over ssh, e.g. `root@host`.
#   hvf-oci-smoke        Apple-Silicon HVF smoke of OCI --allow-host egress.
#   gcp-kvm PROGRAM [ARGS]  one repository test command on a disposable GCP
#       nested-KVM host: creates an Intel Spot VM, runs the command, downloads
#       its results, deletes the VM. Billable — see AGENTS.md before running.
#   cve-3655-gcp [ARGS]  the pinned CVE-2026-80521 containment witness on such
#       a host (`--dry-run` to preview). Billable.

# Live end-to-end lanes: docs, launch, live-ci, smoke-fresh-install, live-fork-witness, hvf-oci-smoke, gcp-kvm, cve-3655-gcp
e2e WHAT="" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    usage="usage: just e2e <docs|launch|live-ci [TAG]|smoke-fresh-install [VERSION]|live-fork-witness TARGET [TAG]|hvf-oci-smoke|gcp-kvm PROGRAM [ARGS]|cve-3655-gcp [ARGS]>"
    what="${1:-}"
    [ "$#" -eq 0 ] || shift
    case "$what" in
      "") echo "$usage" ;;
      docs) ./scripts/e2e-documented-surface.sh ;;
      launch) ./scripts/e2e-launch-modes.sh ;;
      live-ci)
        # `embed-host-bins` because these scenarios boot real microVMs:
        # `MVM_BDD_LIVE=1` admits the `@live` set, which reaches the builder
        # VM, and without the payload mvmctl refuses at bootstrap. A launch
        # boots only what its home already holds, so the live home is prepared
        # from bytes built here: the workload kernel, and the host helpers
        # mvmctl spawns, built beside it so no launch compiles one.
        cargo build --bin mvmctl --features user,embed-host-bins
        cargo build -p mvm-hostd --bin mvm-host-agent --bin mvm-policy-coordinator --bin mvm-signer-helper --bin mvm-network-endpoint
        "${CARGO_TARGET_DIR:-target}/debug/mvmctl" kernel build --which workload --source download
        allowed_skips=outside-selected-tag
        if [ "${MVM_BDD_ALLOW_RUNTIME_CANDIDATE_SKIP:-false}" = true ] && [ -z "${MVM_E2E_RUNTIME_CANDIDATE_DIR:-}" ]; then
          allowed_skips="$allowed_skips,needs-runtime-candidate"
        fi
        CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" \
        MVM_BDD_LIVE=1 \
        MVM_BDD_ONLY_TAG="${1:-ci_live}" \
        MVM_BDD_STRICT_SKIPS=1 \
        MVM_BDD_ALLOWED_SKIPS="$allowed_skips" \
        cargo test -p mvm-conformance --test conformance --features bdd
        ;;
      smoke-fresh-install) ./scripts/smoke-fresh-install.sh "$@" ;;
      live-fork-witness)
        : "${1:?$usage}"
        ./scripts/live-fork-witness-remote.sh "$@"
        ;;
      hvf-oci-smoke) bash scripts/check-hvf-oci-allow-host-smoke.sh ;;
      gcp-kvm)
        : "${1:?$usage}"
        ./scripts/run-gcp-kvm-test.sh -- "$@"
        ;;
      cve-3655-gcp) ./scripts/run-cve-2026-80521-gcp.sh "$@" ;;
      *)
        echo "unknown e2e lane: $what" >&2
        echo "$usage" >&2
        exit 1
        ;;
    esac


# `dev` and `build` stage the /demo wasm assets first when any is missing.
# `demo-all [PACK_DIR]` also builds the weblinux demo from a qemu-wasm smoke
# pack (default ./qemu-wasm-smoke-pack; fetch one with `qemu-pack [DIR] [TAG]`,
# seconds against 10-30 minutes from scratch) and needs Linux.

# Documentation site: dev, build, demo, demo-all, qemu-pack
docs WHAT="" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    usage="usage: just docs <dev|build|demo|demo-all [PACK_DIR]|qemu-pack [DIR] [TAG]>"
    what="${1:-}"
    [ "$#" -eq 0 ] || shift
    demo_assets() {
      test -s public/public/demo/demo.js \
        && test -s public/public/demo/worker.js \
        && test -s public/public/demo/pkg/mvm_demo_web.js \
        && test -s public/public/demo/pkg/mvm_demo_web_bg.wasm \
        && test -s public/public/demo/guest/mvm-demo-guest.wasm \
        && test -s public/public/demo/fixtures/allowed.opt.wasm \
        && test -s public/public/demo/fixtures/denied.opt.wasm \
        && test -s public/public/demo/fixtures/unbound.opt.wasm \
        || ./web/mvm-demo/build.sh
    }
    case "$what" in
      "") echo "$usage" ;;
      dev)
        demo_assets
        cd public
        pnpm dev
        ;;
      build)
        demo_assets
        cd public
        pnpm build
        ;;
      demo) ./web/mvm-demo/build.sh ;;
      demo-all)
        ./web/mvm-demo/build.sh
        PACK_DIR="${1:-$PWD/qemu-wasm-smoke-pack}"
        if [ ! -d "$PACK_DIR" ]; then
          echo "qemu-wasm-smoke-pack not found at $PACK_DIR"
          echo "Download it first with: just docs qemu-pack"
          exit 1
        fi
        ./web/weblinux-demo/build.sh "$PACK_DIR"
        ;;
      qemu-pack) ./scripts/download-qemu-wasm-smoke-pack.sh "$@" ;;
      *)
        echo "unknown docs command: $what" >&2
        echo "$usage" >&2
        exit 1
        ;;
    esac


# Usage: just release [--dry-run] VERSION   (0.29.0 or 0.29.0-rc.1, no `v`)
#
# `main` is protected (enforce_admins + merge queue), so the version bump lands
# through a PR and the tag follows the merge; tags are not branch-protected.
# Pushing the tag starts release.yml, which builds, signs, publishes and — for a
# version without `-rc` — promotes.
#
# Safe to re-run from any point. Each run reads what is already done — the tag
# on origin, the version on main, the release PR — and continues from there:
#
#   1. tag already on origin       nothing to push; print the follow-ups
#   2. main already at VERSION     tag origin/main, push the tag
#   3. release PR open             enable auto-merge, wait for it, then 2
#   4. branch pushed, no PR        open the PR, then 3
#   5. nothing yet                 bump, changelog, suite, commit, push, then 4
#
# `--dry-run` reads the same state and prints every remaining step without
# changing the checkout, origin or GitHub. Needs git-cliff, cargo-nextest and
# an authenticated `gh` with push access.

# Cut a release: bump PR, merge queue, tag. Safe to re-run; --dry-run prints the steps
release *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    DRY="" V=""
    for arg in "$@"; do
      case "$arg" in
        --dry-run) DRY=1 ;;
        *) V="$arg" ;;
      esac
    done
    # V reaches `sed` and a branch name below, so it is held to the two shapes
    # a release has.
    if ! [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
      echo "usage: just release [--dry-run] VERSION   (0.29.0 or 0.29.0-rc.1, without a v prefix)" >&2
      exit 1
    fi
    BRANCH="release/v$V"
    step() { echo "==> $*"; }
    fail() { echo "ERROR: $*" >&2; exit 1; }
    # Everything that changes the checkout, origin or GitHub goes through `run`,
    # which is what makes --dry-run exhaustive. It reports on fd 3 so a step
    # whose own output is discarded is still printed.
    exec 3>&1
    run() {
      if [ -n "$DRY" ]; then
        echo "    [dry-run] $*" >&3
      else
        "$@"
      fi
    }
    followups() {
      echo "==> Left to do by hand for v$V:"
      echo "    gh run watch \$(gh run list --workflow=release.yml --branch v$V --limit 1 --json databaseId --jq '.[0].databaseId')   # the release pipeline"
      if [[ "$V" == *-rc.* ]]; then
        echo "    (a release candidate stays a prerelease: no promotion, no pin PR, no crates.io publish)"
      else
        echo "    gh pr merge chore/prebuilt-pin-v$V --auto --squash   # the pin PR promote-release opens"
        echo "    gh workflow run publish-crates.yml -f tag=v$V -f dry_run=false   # crates.io, once the release is promoted"
      fi
      echo "    gh workflow run installer-compat.yml   # the installer against the published release"
    }

    tagged=0
    git ls-remote --exit-code --tags origin "refs/tags/v$V" >/dev/null || tagged=$?
    case "$tagged" in
      0)
        step "v$V is already tagged on origin — nothing to push"
        followups
        exit 0
        ;;
      2) ;;
      *) fail "could not read origin's tags" ;;
    esac

    # Captured, not piped into `grep -q`: under pipefail an early-exiting grep
    # fails the pipeline.
    main_toml="$(gh api -H 'Accept: application/vnd.github.raw' 'repos/{owner}/{repo}/contents/Cargo.toml?ref=main')"
    if grep -qxF "version = \"$V\"" <<<"$main_toml"; then
      step "main is already at $V — the release PR has merged"
    else
      pr="$(gh pr list --head "$BRANCH" --state all --limit 1 --json number,state --jq '.[0] | select(.) | "\(.number) \(.state)"')"
      n="#${pr% *}"
      case "${pr#* }" in
        OPEN) step "release PR $n is open" ;;
        MERGED) fail "release PR $n merged, but main is not at $V — look before going on" ;;
        CLOSED) fail "release PR $n was closed unmerged — reopen it, or delete $BRANCH on origin and re-run" ;;
        "")
          branch_on_origin=0
          git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null || branch_on_origin=$?
          if [ "$branch_on_origin" -eq 0 ]; then
            step "$BRANCH is on origin without a PR"
          else
            step "preparing $BRANCH"
            if [ -n "$(git status --porcelain)" ] || [ "$(git rev-parse --abbrev-ref HEAD)" != main ]; then
              if [ -z "$DRY" ]; then
                fail "start from a clean checkout of main"
              fi
              echo "    [dry-run] a real run refuses here: this checkout is not a clean main"
            fi
            if git rev-parse -q --verify "refs/heads/$BRANCH" >/dev/null; then
              fail "a local $BRANCH is left from an interrupted run — inspect it, 'git branch -D $BRANCH', and re-run"
            fi
            run git pull --ff-only origin main
            run ./scripts/cargo.sh clippy --workspace --all-targets -- -D warnings
            run git switch -c "$BRANCH"
            # The workspace version AND every internal path-dep pin, or the
            # pins version-mismatch on `cargo update`.
            run sed -i.bak -E \
                -e "s/^version = \"[^\"]*\"/version = \"$V\"/" \
                -e "s/(path = \"[^\"]*\", version = )\"[^\"]*\"/\1\"$V\"/" Cargo.toml
            run rm Cargo.toml.bak
            # The installer's checked-in fallback follows the newest *promoted*
            # release, with the archive hashes its signed manifest carries —
            # never the version this PR prepares: that tag does not exist yet,
            # has no hashes, and has not passed the first-run smoke that
            # promotes it. Left as it is, with a warning, when that release
            # cannot be authenticated.
            if run ./scripts/pin-installer-default.sh --newest install.sh nix/prebuilt-release.nix; then
                run git add install.sh nix/prebuilt-release.nix
            else
                echo "WARN: install.sh's offline fallback is unchanged — see the reason above." >&2
            fi
            run cargo update -w
            # The cargo-fuzz crates are separate workspaces with their own
            # lockfiles, each pinning the internal `mvm-*` crates by version.
            # Re-resolve each lock so the release PR's locked fuzz checks see
            # the bumped package versions.
            for manifest in crates/*/fuzz*/Cargo.toml crates/deps/*/fuzz*/Cargo.toml; do
                [ -f "$manifest" ] || continue
                run cargo metadata --manifest-path "$manifest" --format-version 1 >/dev/null
                run git add "$(dirname "$manifest")/Cargo.lock"
            done
            run git-cliff --tag "v$V" --unreleased --prepend CHANGELOG.md
            if [ -z "$DRY" ] && ! grep -qE "^## \[$V\]" CHANGELOG.md; then
                fail "git-cliff did not add a '## [$V]' section to CHANGELOG.md — aborting (no changelog for the release)."
            fi
            run git add Cargo.toml Cargo.lock CHANGELOG.md
            # A suite run before the bump cannot witness the tree that is pushed.
            step "running the workspace suite against the bumped tree"
            run cargo nextest run --workspace
            run git commit -m "release: v$V"
            run git push -u origin "$BRANCH"
            run git switch main
          fi
          run gh pr create --base main --head "$BRANCH" --title "release: v$V" \
              --body "Version bump + git-cliff changelog for v$V. \`just release $V\` merges it through the queue and tags the result."
          n="the new PR"
          [ -n "$DRY" ] || n="#$(gh pr view "$BRANCH" --json number --jq .number)"
          ;;
        *) fail "unexpected state for $BRANCH: $pr" ;;
      esac

      # Not fatal: on a re-run the PR may already be auto-merging or queued,
      # and the wait below reports a PR that never merges.
      run gh pr merge "${n#\#}" --auto --squash \
        || echo "    auto-merge was not newly enabled on $n — waiting for it anyway"
      step "waiting for the checks on $n, then for the merge queue"
      if [ -n "$DRY" ]; then
        echo "    [dry-run] gh pr checks ${n#\#} --watch --fail-fast"
        echo "    [dry-run] poll 'gh pr view ${n#\#} --json state' up to five times over 15 minutes"
      else
        gh pr checks "${n#\#}" --watch --fail-fast \
          || fail "the checks on $n are not green (or none has reported yet). Fix the PR if it needs it, then re-run: just release $V"
        # The queue merges on its own schedule and tells this shell nothing; a
        # `pull_request.closed` webhook is the event that would replace this
        # poll. Five polls, backing off, then stop and say how to resume.
        state=""
        for delay in 0 60 120 240 480; do
          sleep "$delay"
          state="$(gh pr view "${n#\#}" --json state --jq .state)"
          [ "$state" != MERGED ] || break
        done
        [ "$state" = MERGED ] \
          || fail "$n is $state, not merged yet — it may still be in the queue. Re-run when it lands: just release $V"
      fi
    fi

    step "tagging origin/main as v$V"
    run git fetch origin main
    if [ -z "$DRY" ]; then
      # The commit about to be tagged, not the API's answer of a moment ago.
      tagged_toml="$(git show origin/main:Cargo.toml)"
      grep -qxF "version = \"$V\"" <<<"$tagged_toml" \
        || fail "origin/main is not at version $V — the release PR has not merged."
    fi
    # A tag left by a run that died before its push is pushed, not re-created.
    git rev-parse -q --verify "refs/tags/v$V" >/dev/null || run git tag "v$V" origin/main
    run git push origin "v$V"
    step "pushed tag v$V — the release pipeline will build and publish"
    followups


# Bare, this removes build artifacts, the regenerable mvm cache and this
# worktree's dev state root `.mvm-test` (DRY_RUN=1 previews that last part).
# `scripts/dev-env.sh` points MVM_HOME, CARGO_TARGET_DIR and CARGO_HOME at
# `.mvm-test`, so it is the largest thing a checkout owns (65 GB in one
# worktree, measured 2026-08-09) and neither `cargo clean` nor
# `mvmctl env cleanup` sees it. Safe whenever no dev VM is live out of this
# worktree.
#
#   payload            drop the cached cross-compiled host binaries so the next
#       build rebuilds them. Run it after editing anything they link (mvm-build,
#       mvm-core, ...) when you are about to boot a real VM.
#   helpers [MINUTES]  reap leaked host-side helper subprocesses older than
#       MINUTES (default 30); the backstop for the in-binary parent-death
#       watchdog. DRY_RUN=1 previews.

# Clean build artifacts, caches and dev state, or: payload, helpers
clean WHAT="" MINUTES="30":
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
      "")
        root="$(git rev-parse --show-toplevel)/.mvm-test"
        if [ ! -d "$root" ]; then
          echo "clean-dev-state: nothing at $root"
        else
          size=$(du -sh "$root" 2>/dev/null | cut -f1)
          if [ -n "${DRY_RUN:-}" ]; then
            echo "clean-dev-state: would remove $root ($size)"
          else
            rm -rf "$root"
            echo "clean-dev-state: removed $root ($size)"
          fi
        fi
        cargo clean
        cargo run --quiet -- env cleanup --cache --yes
        ;;
      payload)
        # Located with `find`, not a glob: a glob hardcodes `target/` and so
        # misses any CARGO_TARGET_DIR. Only the musl cross-compile is cached
        # this way; the per-VM host helpers are ordinary workspace binaries
        # that cargo rebuilds on its own.
        root="${CARGO_TARGET_DIR:-target}"
        [[ -d "$root" ]] || exit 0
        found=0
        while IFS= read -r dir; do
          echo "  removing $dir"
          rm -rf "$dir"
          found=$((found + 1))
        done < <(find "$root" -type d -name host-vm-target 2>/dev/null)
        echo "embed-refresh: cleared $found nested target dir(s)"
        ;;
      helpers) ./scripts/reap-helper-orphans.sh "$2" ;;
      *)
        echo "unknown clean target: $1" >&2
        echo "usage: just clean [payload|helpers [MINUTES]]" >&2
        exit 1
        ;;
    esac


#   hooks       wire core.hooksPath at .githooks/ (once per clone). Without it
#       git falls back to .git/hooks/pre-commit, which may be a stale copy.
#   toolchain   the pinned zig + cargo-zigbuild cross-compile toolchain the
#       Linux host binaries are built with: the exact zig from the `ziglang`
#       PyPI package, the musl and glibc rust targets, and the pinned
#       cargo-zigbuild. Homebrew's `zig` drifts to newer, incompatible releases
#       (`CacheCheckFailed`). Once per machine, or after a toolchain pin bump.
#   typescript  the TypeScript SDK's dependencies (`npm ci`), after a fresh
#       clone or whenever package-lock.json changes.

# One-time setup: hooks, toolchain, typescript
setup WHAT="":
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
      "") echo "usage: just setup <hooks|toolchain|typescript>" ;;
      hooks)
        git config core.hooksPath .githooks
        echo "core.hooksPath -> .githooks/"
        ;;
      toolchain)
        RUST=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['rust'])")
        ZIG=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['zig'])")
        ZIGBUILD=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['cargo-zigbuild'])")
        echo "installing pinned Rust ${RUST} + zig ${ZIG} (ziglang) + musl/glibc targets + cargo-zigbuild ${ZIGBUILD}"
        python3 -m pip install --quiet --upgrade --target "${HOME}/.local/share/mvm/toolchains/zig/${ZIG}" "ziglang==${ZIG}"
        rustup toolchain install "${RUST}" --profile minimal
        rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl \
            aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu --toolchain "${RUST}"
        if [[ "$(cargo-zigbuild --version 2>/dev/null || true)" != "cargo-zigbuild ${ZIGBUILD}" ]]; then
          cargo install cargo-zigbuild --version "${ZIGBUILD}" --locked
        fi
        echo "embed toolchain ready: Rust ${RUST} + zig ${ZIG} + aarch64/x86_64 musl and glibc targets + cargo-zigbuild ${ZIGBUILD}"
        ;;
      typescript) npm --prefix crates/mvm-sdk/sdks/typescript ci ;;
      *)
        echo "unknown setup step: $1" >&2
        echo "usage: just setup <hooks|toolchain|typescript>" >&2
        exit 1
        ;;
    esac


# Local findings under .agent-memory/notes, which is gitignored: a fresh clone
# has none, and the recipes say so rather than erroring. `recall` is lexical
# and its terms are OR-ed — `just mem recall teardown ram` finds notes
# mentioning either.

# Local findings: recall TERMS, notes, remember SLUG
mem VERB="" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    usage="usage: just mem <recall TERMS...|notes|remember SLUG>"
    none="no .agent-memory/notes yet — notes are local and gitignored; \`just mem remember <slug>\` starts one"
    verb="${1:-}"
    [ "$#" -eq 0 ] || shift
    case "$verb" in
      "") echo "$usage" ;;
      recall)
        : "${1:?$usage}"
        if [ ! -d .agent-memory/notes ]; then
          echo "$none"
          exit 0
        fi
        pattern=$(printf '%s' "$*" | tr ' ' '|')
        rg -il --sort path -e "$pattern" .agent-memory/notes | while read -r path; do
          printf '%s\n    %s\n' \
            "$(basename "$path" .md)" \
            "$(sed -n 's/^title: //p' "$path")"
        done
        ;;
      notes)
        shopt -s nullglob
        set -- .agent-memory/notes/*.md
        if [ "$#" -eq 0 ]; then
          echo "$none"
          exit 0
        fi
        for path in "$@"; do
          printf '%s  %s — %s\n' \
            "$(sed -n 's/^date: //p' "$path")" \
            "$(basename "$path" .md)" \
            "$(sed -n 's/^title: //p' "$path")"
        done | sort -r
        ;;
      remember)
        slug="${1:?$usage}"
        path=".agent-memory/notes/$slug.md"
        if [ -e "$path" ]; then echo "note $slug already exists" >&2; exit 1; fi
        printf -- '---\ntitle: \ndate: %s\ntags: []\n---\n\n' "$(date +%F)" > "$path"
        echo "created $path"
        ;;
      *)
        echo "unknown mem verb: $verb" >&2
        echo "$usage" >&2
        exit 1
        ;;
    esac
