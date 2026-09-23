# The sibling checkout is the contributor default; CI consumes mvm-images

Backing: shipped-source
Validation: cargo nextest run -p mvm-build -p mvm-cli -E 'test(sibling) | test(discovered) | test(outranks) | test(no_sibling) | test(image_source)' && cargo nextest run -p mvmctl --test ci_scope_aggregate

The wiring the project's other working sessions flagged as missing: with
`MVM_IMAGES_DIR` unset, nothing consumed `mvm-images` — normal image-backed
launches and the merge-queue tree-built witness both rebuilt the in-tree
flakes. This change makes the external image source the default.

## What changed

- **Sibling discovery as the contributor default.** `resolve_current_source`
  now answers: the configured `${MVM_IMAGES_DIR}` when set (unchanged, still
  strict — an unusable configured path is an error, never a fall-through);
  else a sibling `mvm-images` checkout next to the compiled-from mvm checkout
  (the standard two-repository layout, detected by a `flake.nix` marker);
  else the in-tree window. A discovered checkout that fails validation warns
  with the reason and falls through to the in-tree flakes rather than breaking
  the build. Release builds never look — discovery is gated on the contributor
  channel, which also refuses the variable at CLI entry, so the production
  boundary (release binaries boot verified released sets; production admission
  refuses local-dev however selected) is unchanged. The trust argument for
  discovery: planting a sibling directory is no more powerful than editing the
  in-tree flakes the build already trusts, and the tier rules treat both
  identically.
- **Consumers move to the one entry point.** `selected_local_checkout`,
  `images_built_from_source`, and `doctor`'s image-source line now resolve
  through `resolve_current_source`, so the builder VM, default image, kernel,
  overlay, sidecars, and the doctor report all honor the default. The doctor
  line names how the checkout was chosen (`$MVM_IMAGES_DIR=…` vs `discovered
  sibling checkout at …`).
- **The merge-queue guest-image witness consumes mvm-images.** The
  `guest-image-boot` job checks out `tinylabscom/mvm-images` at `main` and
  builds the default tenant and the runtime overlay from
  `path:…/images#legacyPackages.…` with `--override-input mvm path:<this
  checkout>`, so the queue boot-tests each PR's mvm changes against the
  external image source — the same pairing a contributor gets locally. The
  determinism-rebuild and boot steps run unchanged on those artifacts.
- **The plan's "nothing searches for a sibling" bullet is amended** in place,
  with the reasoning recorded.

## Evidence

- New tests: a valid sibling is the contributor default; the configured
  checkout outranks the sibling and stays strict; a discovered sibling that
  names itself but is not usable warns and falls back (and release ignores
  it); no sibling keeps the in-tree window.
- `check-workflow-paths` and the CI-scope aggregate tests pass; full workspace
  suite and gates run as part of this change.

## Not done

- The `build image-set` verb still requires an explicit selection when no
  sibling exists (its error names both routes).
- The remaining in-tree consumers are the Stage 0 source bootstrap and the
  kernel lanes; they move with W6/W8. The `Guest image boots` check was
  renamed (`tree-built` → `mvm-images`); if branch protection names the old
  check, the setting needs the same rename.
