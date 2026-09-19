# An explicit local image-source selector with its own trust tier

Backing: shipped-source
Validation: cargo nextest run -p mvm-core -p mvm-build -p mvm-client -p mvm-cli -E 'test(image_source) | test(trust_tier) | test(local_image_checkout)'

The first slice of the sibling-checkout workflow (#3364). It gives a
contributor a way to name a local `mvm-images` checkout, says how far images
from it are trusted, and makes sure a release binary and a production boot
cannot be pointed at one. It does not yet route any image build through the
selection: every consumer that builds from the in-tree `nix/images` still does,
and the plan's W5 section lists the slices that move them.

## What changed

- `mvm_build::image_source` resolves `MVM_IMAGES_DIR`. The path is
  canonicalized and must be a directory that is the root of its git work tree
  and carries the `mvm-images` layout as regular files — a symlinked marker is
  refused. The selection records the canonical root, the commit and the working
  tree state: clean, or a SHA-256 over the tracked diff, the status listing and
  every untracked file's path and contents. `reverify` re-resolves the path and
  re-reads the identity, so a retargeted symlink or an edit after selection is
  refused rather than attributed to the recorded identity. Nothing searches for
  a sibling, and a configured path that cannot be used is an error, never a
  fallback to the in-tree flakes or the released set.
- `mvm_core::image_set::ImageTrustTier` has two values, `verified-release` and
  `local-dev`, with no conversion between them. The released set is the only
  source classified `verified-release`; a local checkout and the mvm checkout's
  own in-tree flakes are both `local-dev`.
- A binary built with the `release-channel` feature refuses `MVM_IMAGES_DIR`
  at CLI entry, before any verb runs and whether or not the path is valid;
  `doctor` is exempt so it can report the refusal. A sealed-production
  admission refuses while the variable is set, before it signs anything. Both
  refusals are declared live in `xtask/dormant-controls.toml`.
- `mvmctl doctor` gains an `image source` line:
  `<tier> — <source> — <identities>`, naming the selected checkout's commit and
  state and the mvm checkout's, or `mvm release build`.

## Why an environment variable

A `~/.mvm` config key is shared by every worktree, and the plan forbids making
image work depend on editing global configuration. The variable is scoped to
one shell, so two paired worktrees select two checkouts, and it reaches every
child `mvmctl` a build spawns, as `MVM_BOOT_IMAGE` and `MVM_BUILDER_BACKEND`
already do.

## Evidence

38 new tests across the four crates pass, in a full run of those crates (5833
tests). The negative cases: a missing path, a file, a directory without the
image sources (an mvm checkout's layout), `..` leaving the checkout, a
subdirectory of another repository, markers with no repository, a symlinked
marker, a selection symlink retargeted after selection, an edit after
selection, a release build given a valid and an invalid path, and a sealed
admission with the variable set (refused before any key is written), beside the
dev admission it leaves alone.
