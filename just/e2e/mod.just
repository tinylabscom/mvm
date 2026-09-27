# End-to-end launch gate: boot a real guest through every README-documented
# entry point (CLI verbs, runtime SDK, decorator SDK, Rust library facade) on
# whatever backend this host has. Unlike `live-ci` this is deliberately NOT
# narrowed to the merge-queue subset and NOT `@firecracker`-gated — that
# narrowing is what left the macOS default backend with no lane that boots a
# guest at all.
#
# Sibling of `e2e-docs`: this one proves the ways in, that one proves the whole
# documented command surface. They overlap in the suite they drive; the split is
# that this lane also exercises the in-process Rust library seam.
#

# Boot a real guest through every documented entry point
launch:
    ./scripts/e2e-launch-modes.sh

# Runs both live lanes in order, against one shared artifact home:
#
#   e2e-launch  the ways in — CLI verbs, both SDKs, and the in-process Rust
#               library seam
#   e2e-docs    the whole documented command surface, plus the machine journey
#
# They overlap in the suite they drive, so this is the belt-and-braces run
# rather than the quick one; reach for a single lane when iterating. Both sweep
# their own machines, and the second refuses to start if the first is still
# holding the home.
#
# Read the "did NOT run" tally at the end, not just the pass count: a skipped
# scenario names a capability this host lacks, and a green suite is not full
# coverage while any of them are nonzero.
#
# Run the Firecracker live-parent fork witness (crates/mvm-runtime/tests/
# fc_fork_live.rs, #[ignore]d: needs /dev/kvm) on a real Linux KVM host over
# ssh. Idempotent — re-runs reuse the remote toolchain and image caches.
# Extra args pass through as the boot-image tag, e.g.
# `just e2e::live-fork-witness root@host boot-image/v0.1.5`.
live-fork-witness TARGET *ARGS:
    ./scripts/live-fork-witness-remote.sh {{ TARGET }} {{ ARGS }}

# Every live end-to-end lane, back to back
all:
    ./scripts/e2e-launch-modes.sh
    ./scripts/e2e-documented-surface.sh

# The hermetic `bdd` lane proves a documented command parses; this one boots
# real microVMs and runs them. Needs an artifact-warm home: it defaults to the
# real `~/.mvm`, override with MVM_E2E_HOME. Expect minutes on a cold home.
#
# Follows each guest's console as it boots; MVM_E2E_FOLLOW=0 silences that.
# Sweeps its own machines on entry and exit — see `docs-clean`.
#

# Every documented example, executed against a real host
docs:
    ./scripts/e2e-documented-surface.sh

# The release lane fetches the signed builder image; this proves a checkout can
# still build one from nothing. Needs an empty MVM_E2E_HOME, Linux with KVM, and
# the time a cold Stage 0 takes — Extended CI runs it nightly.
#

# Bootstrap the builder image from source against a cold home
source-bootstrap:
    ./scripts/e2e-source-bootstrap.sh

# What a new user gets: install a release into a throwaway HOME under /tmp with
# this checkout's install.sh — builder bootstrap included — then run the
# README's `machine run --image alpine` with stdin closed and require its output
# within a time budget. The release workflow runs the same script before it
# promotes a tag. Omit VERSION to test whatever the one-liner installs today.
# Boots a real microVM; never touches your own ~/.mvm or ~/.local.
#

# Install a release as a new user would and run the first command
smoke-fresh-install VERSION="":
    ./scripts/smoke-fresh-install.sh {{ VERSION }}

# Reap machines a killed e2e run left behind. Scoped to the `bdd-` prefix the
# suite creates, so it never touches a machine you made.
#

# Clean up after an interrupted e2e run
docs-clean:
    ./scripts/e2e-documented-surface.sh --clean-only

# `e2e-docs` records this for you on a clean run; this recipe is for
# re-recording from a log you kept. The lane is `macos-hvf` or
# `linux-firecracker`, and the log is the full output of the run that earned it
# — the recorder parses the `[Summary]` block out of it and refuses a run with
# failing scenarios, so a record cannot be minted from a red run.
#

# Record that a documented-surface lane ran clean against this tree
record-evidence lane log:
    cargo run -p xtask -- record-release-evidence {{ lane }} {{ log }}

# The release-side half of the above: fails unless each lane's committed record
# describes the tree you are about to tag. Run it before pushing a tag; CI runs
# it too, for the macOS lane, whenever no runner could produce that evidence
# live.
#

# Check every documented-surface lane's evidence covers this tree
check-evidence *lanes:
    cargo run -p xtask -- check-release-evidence {{ lanes }}
