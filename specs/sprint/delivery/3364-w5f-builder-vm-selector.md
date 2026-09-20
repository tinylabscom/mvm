# The builder VM reads the image source selector

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -p mvm-build -E 'test(local_pair) | test(image_source) | test(shell_job) | test(bootstrap_helper) | test(stage0_cache)'

Slice W5f of the sibling-checkout workflow (#3364). With `MVM_IMAGES_DIR`
naming a checkout, the builder VM a consumer boots is that checkout pair's
`builder-vm` target: built once by the shared local-image-set build, served
from the local image cache, and installed into the builder-VM cache with a
`local_pair` provenance record. With the selector unset, nothing changes: the
in-tree Stage 0 build or the published prebuilt prepares the builder as
today. The builder that BUILDS a local image set is exempt from the selector,
so building the builder image never routes through the image being built.

## What changed

- `mvm_build::image_source::build_target_for_pair` is now the one
  implementation of a local image-set build. The `build image-set` verb and
  the builder-VM bootstrap share it, so a target built either way is the same
  bytes under the same key. The VM boundary (preparing the builder image,
  running the shell job) is injected, which is how the bootstrap passes the
  exempt tool bootstrap and tests run a build without a VM. `build image-set`
  keeps its CLI concerns (argument parsing, reporting) and loses its private
  copy of the orchestration.
- `bootstrap_builder_vm_image` routes through the selector. A selected
  checkout serves its `builder-vm` target: an unchanged pair answers from the
  installed cache; a changed pair builds through the shared path and
  installs. An unusable configured path is an error, never a quiet
  fall-through to the in-tree flake. `bootstrap_tool_builder_vm_image` is the
  exempt in-tree/published path and keeps the helper re-exec wrapper;
  `builder shell-job` and the SDK sidecar build call it.
- The install reuses the Stage 0 cache's staging, sidecar (fingerprint,
  artifact-digest manifest, provenance) and promoted-swap machinery, with the
  provenance `source_kind` parameterized: `source_checkout_stage0` (existing)
  or `local_pair` (new). The recorded fingerprint is the pair cache key's
  digest, so a change in either checkout, the toolchain pins or a flake lock
  invalidates exactly this cache — and a pair-installed cache does not verify
  as a Stage 0 cache, or the other way around.
- `BUILDER_VM_CACHE_CONTRACT_VERSION` moved to mvm-build's ungated
  `builder_vm` module (re-exported from `libkrun_builder`) so the shared
  build can name the manifest's builder-cache contract without the
  `builder-vm` feature.
- `stage0-init` takes its flake attr namespace from `MVM_STAGE0_FLAKE` in
  `stage0-build.conf`, defaulting to the in-tree
  `path:/work/nix/images/builder-vm#packages`. The hard-code is gone; no
  writer needs to change because absence means the default. The local-pair
  path does not use Stage 0 — the W5e shell job builds the sibling checkout —
  so the guest default is exercised exactly where the in-tree tree is staged.
- `image boot update` refuses to replace a locally built image with a
  prebuilt under a selected checkout too: either source makes the local build
  authoritative. Kernel-pin resolution keeps the in-tree check until W5h
  moves kernel acquisition; flipping it now would misroute a pinned kernel
  build to the in-tree flake while the selector names another checkout.

## Evidence

- New unit tests: the routing (none selected, a selected checkout, an
  unusable path); the pair fingerprint is the key digest and moves with a
  pre-selection image edit, while a post-selection edit is refused at
  key-derivation time; a pair entry publishes and installs into a
  `local_pair`-provenance cache that verifies ready under the pair
  fingerprint and does not verify as a Stage 0 cache.
- `crates/mvm-build/src/image_source/build.rs` tests cover the shared build's
  contract refusals and rendered script unchanged; the CLI's
  `build image-set` behavior (cache hit reporting, refusals) is covered by
  the existing `image_source`/`shell_job` tests now running against the
  shared path.
- No VM witness: the routing and install are covered without booting
  anything; a live boot of a pair-built builder image is W5m's witness.

## Not done

- W5g (default workload image), W5h (kernel and initramfs), W5i (runtime
  overlay and SDK sidecars) and W5j (the libkrun supervisor auto-build's
  checkout key) remain; each moves its consumer in its own slice. W5k makes
  admission read the recorded tier; until then a pair-built builder image is
  `local-dev` by construction and refuses production admission only through
  the selector being set, not through what the cache recorded.
