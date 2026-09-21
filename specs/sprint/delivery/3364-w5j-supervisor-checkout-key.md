# The libkrun supervisor auto-build keys on the checkout, not the image flakes

Backing: shipped-source
Validation: cargo nextest run -p mvm-build --features builder-vm -E 'test(supervisor_auto_build_keys) | test(mvm_checkout_is_the_workspace_manifest)'

Slice W5j of the image-repository extraction (#3364). The libkrun
supervisor auto-build decided "is this a source checkout?" by looking for
`nix/images/builder-vm/flake.nix`. That conflates the mvm checkout with
the in-tree image flakes: when W8 deletes `nix/images`, the probe would
start answering "installed binary", the supervisor auto-build would
silently stop, and a contributor build would behave like an installed one.

## What changed

- `source_checkout_supervisor_build` and
  `auto_build_supervisor_from_source_checkout` now key on
  `image_source::mvm_source_checkout(compiled_channel())` — the workspace
  manifest probe, already release-channel-aware — via a local
  `supervisor_source_checkout_root` helper.
- `mvm_source_checkout` is split: the channel gate stays, and the root
  probe is `mvm_source_checkout_at(root)`, which tests can drive against a
  synthetic tree. `builder_vm_source_checkout_root` keeps its remaining
  callers (the bootstrap helper re-exec), whose semantics genuinely concern
  the in-tree flake.

## Evidence

- New tests: a directory with a workspace manifest and no `nix/images` is
  an mvm checkout; a directory without the manifest is not. The supervisor
  probe finds this workspace and agrees with the flake-based probe while
  the flakes exist — the test documents that the supervisor probe must not
  come to depend on them.
- The full workspace suite and gates run as part of this change.

## Not done

- W5i (runtime overlay and both SDK sidecar build paths, and collapsing
  the duplicate checkout detection), W5k (tier at admission), W5l (docs
  and the paired CI job), W5m (the acceptance witnesses).
