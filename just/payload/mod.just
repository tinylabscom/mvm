set working-directory := "../.."

# The Linux host binaries are built with it — by a release `cargo build`, or by an `mvmctl` built without them: the
# exact zig from the `ziglang` PyPI package, the musl rust targets, and the
# pinned cargo-zigbuild. Homebrew's `zig` drifts to newer, incompatible releases
# (fails downstream with `CacheCheckFailed`); the `ziglang`-installed zig is
# auto-detected instead. Run once per machine (or after a toolchain pin bump).

# Provision the pinned zig + cargo-zigbuild cross-compile toolchain
toolchain:
    #!/usr/bin/env bash
    set -euo pipefail
    RUST=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['rust'])")
    ZIG=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['zig'])")
    ZIGBUILD=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['cargo-zigbuild'])")
    echo "installing pinned Rust ${RUST} + zig ${ZIG} (ziglang) + musl targets + cargo-zigbuild ${ZIGBUILD}"
    python3 -m pip install --quiet "ziglang==${ZIG}"
    rustup toolchain install "${RUST}" --profile minimal
    rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl --toolchain "${RUST}"
    if [[ "$(cargo-zigbuild --version 2>/dev/null || true)" != "cargo-zigbuild ${ZIGBUILD}" ]]; then
      cargo install cargo-zigbuild --version "${ZIGBUILD}" --locked
    fi
    echo "embed toolchain ready: Rust ${RUST} + zig ${ZIG} + aarch64/x86_64 musl targets + cargo-zigbuild ${ZIGBUILD}"

# Build the per-VM host helper bins into `target/<profile>/`, where
# `aux_bin::resolve` looks for them. Optional: a contributor mvmctl run from
# `target/<profile>/` builds a missing or out-of-date helper itself before
# spawning it. This prebuilds them all at once, and is the way to get them for
# an mvmctl that runs from anywhere else.
#
# Bare, this writes the debug helpers. Pass `--release` if the mvmctl you invoke
# is the release one: `aux_bin::resolve` searches `target/release` before
# `target/debug` and takes the first hit, so a release mvmctl with no release
# helper beside it silently falls through to whichever debug helper was built
# last. That one is stale as soon as the config contract moves, and a stale
# helper refuses the config the current mvmctl sends.
#

# Build the per-VM supervisor bins (--release to match a release mvmctl)
supervisors *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe links the same `mvm-hostd` binaries `embed` does and needs the
    # same rust-objcopy repair; without it every supervisor ships unstripped.
    source "{{justfile_directory()}}/scripts/macos-objcopy-env.sh" "{{justfile_directory()}}"
    ./scripts/cargo-fast.sh build -p mvm-hostd --bins {{ARGS}}
    ./scripts/cargo-fast.sh build -p mvm-gpu --bin mvm-gpu-endpoint {{ARGS}}

# Intentionally absent from `build` and `supervisors` so standard builds never
# probe for libkrun.h or enable native libkrun linkage.

# Build the contributor-only libkrun supervisor
libkrun-supervisor *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    source "{{justfile_directory()}}/scripts/macos-objcopy-env.sh" "{{justfile_directory()}}"
    ./scripts/cargo-fast.sh build -p mvm-hostd \
      --bin mvm-libkrun-supervisor --features libkrun-sys {{ARGS}}

# Dev builds reuse these instead of re-running cargo-zigbuild, which is the bulk
# of mvm-cli's build-script wall time. Run this after editing anything they link
# (mvm-build, mvm-core, ...) when you are about to boot a real VM; ordinary
# check/test/clippy runs never need it. Release builds always rebuild.

# Drop the cached cross-compiled host binaries so the next build rebuilds them
refresh:
    #!/usr/bin/env bash
    set -euo pipefail
    # Located with `find`, not a glob. The previous pattern
    # (`target/*/build/mvm-cli-nested-target/host-vm-target`) matched nothing:
    # it hardcoded `target/` so it missed any CARGO_TARGET_DIR, and it lacked
    # the `mvm-cli/` path segment the current layout uses. The recipe was a
    # silent no-op, which is why the launch path kept refusing helpers that
    # "were reused from an earlier build".
    #
    # Only the musl cross-compile is cached this way. The per-VM host helpers
    # are ordinary workspace binaries now, so cargo rebuilds them on its own
    # and there is nothing here to clear for them.
    root="${CARGO_TARGET_DIR:-target}"
    [[ -d "$root" ]] || exit 0
    found=0
    while IFS= read -r dir; do
      echo "  removing $dir"
      rm -rf "$dir"
      found=$((found + 1))
    done < <(find "$root" -type d -name host-vm-target 2>/dev/null)
    echo "embed-refresh: cleared $found nested target dir(s)"
