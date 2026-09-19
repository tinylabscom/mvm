# Building a local image set, and the paired-checkout wrapper

Backing: shipped-source
Validation: cargo nextest run -p mvm-build -p mvm-core -p mvm-cli -E 'test(image_source) | test(kernel_format) | test(shell_job)'

Slice W5e of the sibling-checkout workflow (#3364). `mvmctl build image-set
<role>` builds one target of the `mvm-images` checkout named by
`MVM_IMAGES_DIR` against the mvm checkout the binary was compiled from, in the
builder VM, and publishes the result to the local image cache (W5d). `bin/dev`
runs it for a pair of checkouts with state scoped to that pair. No image
consumer reads the cache yet; W5f–W5k move them.

## What changed

- `mvmctl build image-set <role> [--attr <attr>]`, under `build` beside
  `kernel`, `runtime-overlay` and `sdk-sidecar` — the other source builds of
  image-set members — rather than under `image`, which acquires and manages
  images and builds none. It needs a contributor build (a release build
  already refuses `MVM_IMAGES_DIR`) and a set selector. It derives the cache
  key, and an unchanged pair is answered from the cache without booting
  anything.
- Targets with an output contract: `builder-vm.default`,
  `runtime-overlay.default`, `runtime-overlay.sdk-sidecar-image`,
  `runtime-overlay.sdk-sidecar-image-musl`, `default-tenant.default`. Each
  names its output files, the manifest role and format of each, the guest
  capabilities, and whether it needs host binaries. `initramfs` is refused (the
  image-set schema has no initramfs role) and so is the kernel flake
  (`default-tenant` carries the workload kernel).
- The build runs in the builder VM as a shell job, never with host Nix.
  `/work` holds a filtered copy of each checkout. The guest runs `nix build
  path:/work/images#legacyPackages.<system>.<role>.<attr> --override-input mvm
  path:/work/mvm` and copies the contract's files to `/out`. The key is
  re-derived after staging, so a checkout edited while it was being copied
  is refused rather than published under the old identity. Only HVF and
  Firecracker run shell jobs in their own image. `ShellJobBuilder` is now
  shared with the SDK sidecar build. Every other builder is refused by name.
  libkrun is the only builder on macOS 13–25, so this is the seam W5f's
  builder work picks up.
- Two steps run on the host with the image checkout's own scripts:
  `scripts/build-host-binaries.sh --mvm-checkout` builds the builder image's
  three static host binaries, which must be built exactly as the image
  release builds them, and the builder image carries Nix but no pinned zig;
  `scripts/emit-local-manifest.py` writes the manifest into a cache staging
  directory. That emitter stays the single producer of a local set; mvm is
  its reader, and every build checks the one against the other. The
  manifest's builder-cache contract is this host's
  `BUILDER_VM_CACHE_CONTRACT_VERSION`. Kernel formats come from the built
  bytes through `KernelFormat::sniff_magic`, which is now in `mvm-core` and
  shared with the runtime's Nix artifact reader.
- `bin/dev`: `MVM_IMAGES_DIR=../mvm-images bin/dev build image-set
  builder-vm`. The wrapper canonicalizes both roots and keys the pair's state
  by a digest of them. `MVM_HOME` goes in
  `${MVM_PAIRS_DIR:-$XDG_STATE_HOME/mvm/pairs}/<digest>/home`, outside both
  checkouts, so nothing written there changes a recorded identity; VM, TAP and
  socket names derive from it. `CARGO_TARGET_DIR` goes in
  `<mvm>/target/pair-<digest>`, inside the ignored target directory where the
  cargo wrappers require it. The wrapper then builds with `just embed` and
  runs the debug `mvmctl`.

## Evidence

The new unit tests cover:

- each supported target's roles, files, capabilities and host-binary need;
- the refusals and their reasons;
- the rendered script: the flake reference, the override, no
  `MVM_HOST_BIN_DIR` except for the builder image, and every output file;
- the work tree: both checkouts with `.git` and `target` pruned, plus the host
  binaries, and a missing host binary refused;
- the host-binary directory parse;
- the emitter's argument vector, with every file, format and capability, the
  kernel format read from its bytes, and an unrecognized kernel refused;
- kernel magic classification;
- which builders run shell jobs.

End to end without the VM, synthetic `default-tenant` outputs were described
by the real `emit-local-manifest.py` from the `mvm-images` checkout at
`e102dc1`, with this dirty mvm worktree as the paired checkout. The emitter
wrote into a cache staging directory, the set was published, and a second
lookup hit at `local-dev`. The Python and Rust fingerprints agreed on a dirty
tree.
