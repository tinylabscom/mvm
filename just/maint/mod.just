set working-directory := "../.."

# ── Development ──────────────────────────────────────────────────────────

# Wire core.hooksPath at .githooks/ (one-time per clone)
hooks:
    # Without this, git falls back to .git/hooks/pre-commit, which may
    # be a stale local copy or the legacy heavy hook. .githooks/pre-commit
    # is intentionally light (cargo fmt + nix fmt --check).
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks/"

# ── VMM setup ────────────────────────────────────────────────────────────

# Install libkrun (the macOS VMM mvm targets)
setup: libkrun
    @echo
    @echo "libkrun installed. Validate with:"
    @echo "  cargo run --example libkrun-bootcheck --features libkrun-sys   (macOS)"

# Install libkrun (macOS via slp/krun tap; Linux via apt/dnf/pacman)
libkrun:
    #!/usr/bin/env bash
    # macOS:   brew install slp/krun/libkrun  (libkrun is not in core; the
    #                                          qualified form auto-taps)
    # Linux:   apt install libkrun-dev        (Debian/Ubuntu, drags libkrun1)
    #          dnf install libkrun-devel      (Fedora/RHEL)
    #          pacman -S libkrun              (Arch / community)
    # Other:   build from source at https://github.com/containers/libkrun
    set -euo pipefail
    EXISTING=""
    for p in \
    /opt/homebrew/lib/libkrun.dylib \
    /usr/local/lib/libkrun.dylib \
    /usr/lib/x86_64-linux-gnu/libkrun.so \
    /usr/lib/aarch64-linux-gnu/libkrun.so \
    /usr/lib64/libkrun.so \
    /usr/local/lib/libkrun.so
    do
    if [ -f "$p" ]; then
    EXISTING="$p"
    break
    fi
    done
    if [ -n "$EXISTING" ]; then
    echo "libkrun already installed at $EXISTING — skipping."
    exit 0
    fi
    case "$(uname -s)" in
    Darwin)
    if ! command -v brew >/dev/null; then
        echo "error: Homebrew not found. Install: https://brew.sh" >&2
        exit 1
    fi
    echo "→ brew install slp/krun/libkrun"
    brew install slp/krun/libkrun
    ;;
    Linux)
    if command -v apt-get >/dev/null; then
        echo "→ apt install libkrun-dev"
        sudo apt-get update
        sudo apt-get install -y libkrun-dev
    elif command -v dnf >/dev/null; then
        echo "→ dnf install libkrun-devel"
        sudo dnf install -y libkrun-devel
    elif command -v pacman >/dev/null; then
        echo "→ pacman -S libkrun"
        sudo pacman -S --needed libkrun
    else
        echo "error: no recognized package manager (apt / dnf / pacman)." >&2
        echo "       Build from source: https://github.com/containers/libkrun" >&2
        exit 1
    fi
    ;;
    *)
    echo "error: libkrun is not supported on $(uname -s)." >&2
    exit 1
    ;;
    esac
    echo "Verifying install…"
    for p in \
    /opt/homebrew/lib/libkrun.dylib \
    /usr/local/lib/libkrun.dylib \
    /usr/lib/x86_64-linux-gnu/libkrun.so \
    /usr/lib/aarch64-linux-gnu/libkrun.so \
    /usr/lib64/libkrun.so \
    /usr/local/lib/libkrun.so
    do
    if [ -f "$p" ]; then
    echo "  ✓ $p"
    exit 0
    fi
    done
    echo "  ! libkrun shared library not found at the standard locations." >&2
    exit 1

# ── Utilities ────────────────────────────────────────────────────────────

# Generate a disposable issue → ADR/contract → Graft briefing
task-context ISSUE:
    python3 scripts/task-context.py {{ ISSUE }}

# Clean build artifacts, the regenerable mvm cache, and the dev state root
clean: clean-dev-state
    cargo clean
    cargo run --quiet -- env cleanup --cache --yes

# Remove this worktree's dev state root `.mvm-test` (DRY_RUN=1 to preview)
clean-dev-state:
    #!/usr/bin/env bash
    # `scripts/dev-env.sh` points MVM_HOME, CARGO_TARGET_DIR *and* CARGO_HOME at
    # `<repo>/.mvm-test`, so every `just dev-*` run accumulates VM images, a full
    # build tree and a per-worktree cargo registry in one gitignored directory.
    # It is the largest thing a checkout owns and nothing used to sweep it:
    # `cargo clean` cleans `./target`, and `mvmctl env cleanup` only ever sees
    # whatever MVM_HOME points at in the shell that invokes it — which, outside
    # `just dev-*`, is not this directory. Measured 2026-08-09: 65 GB in one
    # worktree and 282 GB across a machine's worktrees, none of it reported by
    # any clean command.
    #
    # Safe whenever no dev VM is live out of this worktree; the contents are
    # rebuilt or re-fetched on demand.
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)/.mvm-test"
    if [ ! -d "$root" ]; then
    echo "clean-dev-state: nothing at $root"
    exit 0
    fi
    size=$(du -sh "$root" 2>/dev/null | cut -f1)
    if [ -n "${DRY_RUN:-}" ]; then
    echo "clean-dev-state: would remove $root ($size)"
    exit 0
    fi
    rm -rf "$root"
    echo "clean-dev-state: removed $root ($size)"

# Classify worktrees: finished, needs-a-human, or in use (--safe-only for paths)
worktrees *ARGS:
    ./scripts/worktree-status.sh {{ ARGS }}

# Remove worktrees the classifier calls finished — preview by default, APPLY=1 to do it
prune:
    #!/usr/bin/env bash
    # Separate from `just maint::worktrees`, which is read-only and says so in its own
    # header. Classifying and deleting are different risks, so they stay
    # different commands. This one only ever acts on paths that classifier
    # already called SAFE: the PR merged, and this tip is exactly the merged head.
    #
    # Previews by default. `clean-dev-state` is the other way round (DRY_RUN=1)
    # because its blast radius is one regenerable directory; here it is whole
    # checkouts, so the cautious mode is the one you get without asking.
    #
    # Never passes --force, so git independently refuses any worktree with
    # uncommitted or untracked files — a second veto behind the classifier.
    # Branches are kept: removing a worktree does not touch its commits, so
    # anything that never landed stays reachable by branch name.
    set -euo pipefail
    paths=$(./scripts/worktree-status.sh --safe-only)
    if [ -z "$paths" ]; then
    echo "worktrees-prune: nothing finished to remove"
    exit 0
    fi
    # Snapshot the process list ONCE. Grepping ps per path inside the loop looks
    # equivalent and is not: the grep's own argv holds the path it searches for,
    # so every worktree matches itself and the whole set reads as busy.
    ps_snapshot=$(ps -eo command 2>/dev/null || true)
    removed=0
    while IFS= read -r p; do
    [ -d "$p" ] || continue
    # Re-checked at the moment of action: the classification is seconds old,
    # and a session may have started work in one since.
    case "$ps_snapshot" in
    *"$p"*) echo "  skip (in use)     $(basename "$p")"; continue ;;
    esac
    if [ -n "$(git -C "$p" status --porcelain 2>/dev/null)" ]; then
    echo "  skip (now dirty)  $(basename "$p")"; continue
    fi
    size=$(du -sh "$p" 2>/dev/null | cut -f1 | tr -d ' ')
    if [ -z "${APPLY:-}" ]; then
    echo "  would remove      $(basename "$p")  (${size})"
    continue
    fi
    if git worktree remove "$p" 2>/tmp/wtprune-err.$$; then
    echo "  removed           $(basename "$p")  (${size})"
    removed=$((removed + 1))
    else
    echo "  refused           $(basename "$p"): $(head -1 /tmp/wtprune-err.$$)"
    fi
    rm -f /tmp/wtprune-err.$$
    done <<< "$paths"
    if [ -z "${APPLY:-}" ]; then
    echo "worktrees-prune: preview only — re-run with APPLY=1 to remove"
    else
    echo "worktrees-prune: removed ${removed}; branches kept"
    fi

# Reap leaked host-side helper subprocesses (broker/host-agent/signer/etc.)
# older than N minutes (default 30). Backstop for the in-binary parent-death
# watchdog; clears orphans from past test runs across worktrees. DRY_RUN=1 to

# preview, e.g. `DRY_RUN=1 just maint::reap-helpers` or `just maint::reap-helpers 5`.
reap-helpers MINUTES="30":
    ./scripts/reap-helper-orphans.sh {{ MINUTES }}

# Check for outdated dependencies
outdated:
    cargo outdated -R

# Watch open PRs for a GitHub repo
watch-prs repo="tinylabscom/mvm" interval="10":
    watch -n {{ interval }} "gh pr list --repo {{ repo }} --state open --json number,title,mergeStateStatus,reviewDecision,isDraft --jq '.[] | \"#\(.number)  \(.mergeStateStatus // \"UNKNOWN\")  review=\(.reviewDecision // \"NONE\")  draft=\(.isDraft)  \(.title)\"'"
