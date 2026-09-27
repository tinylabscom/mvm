# ── Release ──────────────────────────────────────────────────────────────
# Cut a release with automatic version bump (based on conventional commits)
# Cut the next release (auto-detected version) via a PR. `main` is protected
# (enforce_admins + merge queue), so the version bump lands through a PR — a
# ── Release ──────────────────────────────────────────────────────────────
# Cut a release with automatic or manual version bump (based on conventional commits).
# Cut the next release (auto-detected version) via a PR. `main` is protected
# (enforce_admins + merge queue), so the version bump lands through a PR — a
# direct `git push` to main is rejected. After the PR merges, run

# `just release::tag <version>` to publish.
# Usage: just release::pr [VERSION]
#   VERSION: version string (e.g., "0.17.0") or "auto" (default, auto-detected)

pr VERSION="auto":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo fmt --all
    ./scripts/cargo-stable.sh clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    ./scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    if [ "{{ VERSION }}" = "auto" ]; then
    echo "==> Preparing automatic release (PR-based)"
    NEXT_VERSION=$(git cliff --bumped-version | sed 's/^v//')
    echo "==> Auto-detected next version: $NEXT_VERSION"
    just release::_prep "$NEXT_VERSION"
    else
    echo "==> Preparing release v{{ VERSION }}"
    just release::_prep "{{ VERSION }}"
    fi

# Shared release prep: on a `release/v<version>` branch, bump every version pin,
# prepend the changelog, commit, push, and open the release PR. Bumps the
# workspace version AND every internal path-dep pin — the old `mvm-[a-z]*` regex
# missed `mvm`, `mvm-ext4`, `libkrun-sys`, `mvm-egress-proxy`, which then

# version-mismatched on `cargo update`.
_prep VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{ VERSION }}"
    BRANCH="release/v$V"
    git switch -c "$BRANCH"
    sed -i.bak -E \
        -e "s/^version = \"[^\"]*\"/version = \"$V\"/" \
        -e "s/(path = \"[^\"]*\", version = )\"[^\"]*\"/\1\"$V\"/" Cargo.toml
    rm Cargo.toml.bak
    # The installer's checked-in fallback follows the newest *promoted*
    # release, with the archive hashes its signed manifest carries — never the
    # version this PR prepares: that tag does not exist yet, has no hashes, and
    # has not passed the first-run smoke that promotes it. Left as it is, with
    # a warning, when that release cannot be authenticated.
    if ./scripts/pin-installer-default.sh --newest install.sh; then
        git add install.sh
    else
        echo "WARN: install.sh's offline fallback is unchanged — see the reason above." >&2
    fi
    cargo update -w
    # The runtime overlay, SDK sidecar and initramfs take their VERSION from
    # one pin (check-runtime-overlay-version fails closed on a mismatch), so
    # bump it alongside Cargo.toml. The mvmctl and SDK cdylib nix packages
    # read their version from Cargo.toml and need no edit.
    sed -i.bak -E "s/^\"[^\"]*\"$/\"$V\"/" nix/images/version.nix
    rm nix/images/version.nix.bak
    grep -qxF "\"$V\"" nix/images/version.nix
    git add nix/images/version.nix
    # The cargo-fuzz crates are separate workspaces with their own lockfiles,
    # each pinning the internal `mvm-*` crates by version. Re-resolve each lock
    # so the release PR's locked fuzz checks see the bumped package versions.
    for manifest in crates/*/fuzz*/Cargo.toml crates/deps/*/fuzz*/Cargo.toml; do
        [ -f "$manifest" ] || continue
        cargo metadata --manifest-path "$manifest" --format-version 1 >/dev/null
        git add "$(dirname "$manifest")/Cargo.lock"
    done
    git-cliff --tag "v$V" --unreleased --prepend CHANGELOG.md
    if ! grep -qE "^## \[$V\]" CHANGELOG.md; then
        echo "ERROR: git-cliff did not add a '## [$V]' section to CHANGELOG.md — aborting (no changelog for the release)." >&2
        exit 1
    fi
    git add Cargo.toml Cargo.lock CHANGELOG.md
    # The pre-bump suite cannot witness the tree that will actually be pushed.
    echo "==> re-running the workspace suite against the bumped tree"
    cargo nextest run --workspace
    git commit -m "release: v$V"
    git push -u origin "$BRANCH"
    gh pr create --base main --head "$BRANCH" --title "release: v$V" \
        --body "Version bump + git-cliff changelog for v$V. Merge via the queue, then \`just release::tag $V\`."
    echo "==> Opened release PR for v$V. Merge it via the queue, then run: just release::tag $V"
# which triggers the build + publish pipeline. Tags are not branch-protected.
tag VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{ VERSION }}"
    git fetch origin main
    # The bump commit must be on main (the release PR merged) before tagging.
    if ! git show "origin/main:Cargo.toml" | grep -qE "^version = \"$V\""; then
    echo "ERROR: origin/main is not at version $V — merge the release PR first." >&2
    exit 1
    fi
    git tag "v$V" origin/main
    git push origin "v$V"
    echo "==> Pushed tag v$V — the release pipeline will build + publish."

# Cross-compile release binary for a target
build-target TARGET:
    cargo build --release --target {{ TARGET }} --features host,user,template-registry-s3,release-artifact-bootstrap,embed-host-bins

# Dry-run crates.io publish (all crates in dependency order)
publish-dry-run:
    ./scripts/release-dry-run.sh

# Pre-publish verification (version, tag, clippy)
deploy-guard:
    ./scripts/deploy-guard.sh
# Print workspace version
@version:
    awk '/^\[workspace\.package\]/{inpkg=1;next} /^\[/{inpkg=0} inpkg && /^version/{print $3;exit}' "{{ justfile_directory() }}/Cargo.toml" | tr -d '"'

# Release the boot image train (`boot-image/v*`)
# This creates and pushes a tag for the boot image release, which triggers
# the release-boot-image.yml workflow to build and publish all microVM assets.
# Usage: just release::image <version>
#   version: The version tag (e.g., 1.2.3) - creates boot-image/v1.2.3
image VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{ VERSION }}"
    TAG="boot-image/v$V"
    git fetch origin main --tags
    if git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "ERROR: tag $TAG already exists." >&2
    exit 1
    fi
    git tag "$TAG" origin/main
    git push origin "$TAG"
    echo "==> Pushed tag $TAG from origin/main — the boot-image release pipeline will build + publish."
