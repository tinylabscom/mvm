# Which image sources move, and which stay

Backing: preview
Validation: none — this records an inventory; no code changed.

W4 of `specs/plans/2026-09-16-image-repository-extraction.md` moves image
building to `tinylabscom/mvm-images`. Its first step is an exact inventory, and
the plan's own ownership list turned out to be stale: it named a
`nix/images/sdk-sidecar/` that does not exist and left out the kernel, the
initramfs, and the QEMU/WebAssembly smoke pack.

The corrected lists are in the plan. The rule that decides them: an image flake,
a kernel config, or an image-assembly script moves; a Nix recipe that compiles
`mvm` source stays beside `mvm`'s `Cargo.lock` and is consumed by `mvm-images`
through an `mvm` flake input pinned to an exact commit. Copying the recipes
would split them from the lockfile they encode.

The inventory also found a current bug, filed as #3447: the builder image cache
fingerprint does not hash the kernel configs, the runtime-overlay flake or the
setpriv recipe the builder-vm flake imports, so an edit to any of them reuses a
stale builder image.

Next is W4a: `nix/flake.nix` exports the guest recipes, and the in-tree image
flakes switch to consuming those outputs, so the interface `mvm-images` pins is
one `mvm` already builds through.
