# Kernel acquisition reads the image source selector

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(pair_default_image) | test(workload_kernel) | test(kernel_less_fallback) | test(local_pair)'

Slice W5h of the sibling-checkout workflow (#3364). With `MVM_IMAGES_DIR`
naming a checkout, the workload kernel is the pair's `default-tenant`
`workload_kernel` member: built once by the shared local-image-set build,
served from the local image cache, and the path handed to launch is the
file the set's manifest digests were verified over. With the selector
unset, the in-tree Stage 0 build and the published download are unchanged.

## What changed

- `ensure_workload_kernel` routes a selected checkout to the pair before
  the in-tree/download resolver runs. The returned path is the verified
  artifact from the pair's cache entry, not a filename that happens to
  exist. A binary without the `builder-vm` feature refuses the selector
  rather than silently downloading.
- The `--kernel-pin` resolution (`mvmctl up`) and the kernel-less-image
  fallback for the out-of-process backends answer from the same pair
  kernel, so a kernel-less mkGuest workload under a selector boots the
  kernel the checkout names rather than an in-tree or published one.
- The verity-capability check applies to the pair kernel unchanged: it
  reads an optional config sidecar the set does not carry, and the absence
  of that witness is not a rejection — the pair kernel is the same kernel
  the sealed default image boots.
- The plan gains the design constraint this work is witnessed against:
  one base Linux image per guest architecture, bootable by every
  Linux-direct backend that declares the set's boot protocol and
  capabilities, with backend adaptation (kernel format conversion, boot
  floors) as the host's translation layer. The wasm/WebLinux tier is not a
  target of the base image. Tracked on the `mvm-images` side by
  tinylabscom/mvm-images#8; the W5m acceptance now names the
  boot-on-every-backend witness.

## The initramfs

No change, by construction: the universal initramfs is a deterministic
cargo artifact — the pinned guest agent cross-compiled from this mvm
checkout, packed as `/init` in an epoch-zero cpio — not an image
repository product. `nix/images/initramfs` remains the optional
publish-path build of the same artifact. It therefore has nothing to route
through the selector; it keeps building from the mvm sources whichever
image source is selected. When the initramfs joins the published image
set (W6), it gains a set role and this position is revisited.

## Evidence

- New tests: the pair kernel resolver returns the verified
  `workload_kernel` artifact (not a rootfs file); `ensure_workload_kernel`
  answers from the pair under a selector; the kernel-less fallback and the
  `--kernel-pin` path answer the same pair kernel. The default-tenant
  publish fixture moved into the shared `test_pair` module.
- Full workspace suite and gates run as part of this change's validation.

## Not done

- W5i (runtime overlay and both SDK sidecar build paths), W5j (the libkrun
  supervisor auto-build's checkout key), W5k (tier at admission), W5l
  (docs and the paired CI job), W5m (the acceptance witnesses, now
  including the one-base-image boot witness).
- `mvmctl kernel build --which workload` stays an explicit in-tree verb:
  it names the checkout it builds from, which is the whole point of it.
