# W8 Waves 1+2 — no code path in mvm builds an image in-tree

Backing: shipped-source
Validation: cargo nextest run -p mvm-build -p mvm-cli --features mvm-build/test-support

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md`
Waves 1+2.

Image construction lives in `mvm-images`. Every `mvm` arm that built, probed or
read `nix/images` now takes one of two sources: the `mvm-images` checkout
selected by `MVM_IMAGES_DIR` or found as a sibling, or the signed set that
`images.lock` pins. When neither can supply what was asked for, it refuses with
one shared error, `ImageConstructionRefused`, whose text says "image
construction lives in mvm-images" and names both ways to select a checkout.
Its tests cover the error text itself and the refusals for the builder image,
the kernel build, the dev default image and the SDK sidecar build.

- **Source-checkout detection.** It is now the workspace manifest
  (`mvm_source_checkout`), not the in-tree builder flake. A checkout with no
  sibling uses the released set.
- **Builder image.** It is fetched from the signed set. The in-tree Stage 0
  builder-image build is gone, together with its source fingerprint and that
  fingerprint's tests. That removes the #3737 layer that keyed the fingerprint
  on the baked host binaries: the fetched image is keyed by the set.
- **Pair-build key.** The consumed-input key for pair builds survives, along
  with the modules it depends on: #3741's `mvm-setpriv` leaf crate,
  `source_closure`, `workspace_graph` and `builder_image_inputs`.
- **Kernel builds.** `kernel build` compiles only from a checkout's kernel
  flake. The `workload-k8s` kernel, which `mvm-images` does not define, is
  refused.
- **Other build commands.**
  - The dev default image builds through the pair, answers from a previous
    cache, or refuses.
  - `build sdk-sidecar build` is pair-only.
  - `stage0-init` requires the host to name its flake.

`host_binaries::manifest::is_baked_into_rootfs` lost its only caller, the
in-tree fingerprint, and is removed. The builder-image plan that still names
it (`specs/plans/2026-09-24-builder-image-without-host-bins.md`) describes the
key this wave deletes.

The documented-surface suite built its SDK sidecar with
`build sdk-sidecar build`, which now needs an image checkout. Its scenarios
load the sidecar from the version-matched cache, so it is still built from
this tree's C ABI, not fetched: `e2e-docs.yml` checks out `mvm-images` inside
the workspace (`.e2e-mvm-images`), away from the sibling path an image checkout
is discovered at, and the script hands it to that one step alone. Found by
dispatching Extended CI on the Wave 3 branch, where both documented-surface
lanes stopped at that step.
