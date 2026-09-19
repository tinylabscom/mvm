# Export the guest recipes images build through

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test nix_flake_structure

Image building is moving to `mvm-images`, but the Nix recipes that compile
`mvm` source for a guest stay here, beside `Cargo.lock`. `mvm-images` will pin
`mvm` as a flake input and build through its outputs. Until this slice those
outputs did not exist: every image flake imported `nix/lib` and
`nix/packages/*.nix` by file path, and `nix/flake.nix` exported none of the
guest recipes.

## What exists now

`nix/packages/guest.nix` is the recipe set, and `nix/flake.nix` exports it as
`packages.<system>.*` for `x86_64-linux` and `aarch64-linux`:

- `mvm-guest-agent`, `mvm-guest-agent-static`, `mvm-setpriv`, `mvm-runner`,
  `mvm-egress-client`, `mvm-addon-dns`, `mvm-exit-report`;
- `mvm-sdk-cdylib-glibc` and `mvm-sdk-cdylib-musl`.

`mvm-runner` used to be written inline in the runtime-overlay flake. It is now
`nix/packages/mvm-runner.nix`, with the same attributes. `lib.<system>` still
carries `mkGuest` unchanged, and adds `hostBinaries`, the manifest of the
host-side binaries a builder image installs.

The builder-vm, default-tenant, runtime-overlay and initramfs flakes each call
`(import (workspaceRoot + "/nix/flake.nix")).outputs`, passing their pinned
inputs and filtered workspace, and take mkGuest, the recipes and the manifest
from the result. The only `nix/lib` file an image flake still imports is
`workspace-filter.nix`, which builds the source it passes in. Kernel imports
and the runtime-overlay flake import are image-internal and move with W4b.

## Evidence

Nothing is built. The comparison evaluates `drvPath` for every package output of
the four image flakes and every `nix/flake.nix` check, on both Linux systems.
It uses `path:` flake references with a fixed `MVM_WORKSPACE_PATH` and a dummy
`MVM_HOST_BIN_DIR`, the way the builder VM evaluates them. The old and new
wiring are evaluated against the same workspace content. They have to be,
because the filtered workspace includes `nix/` and `tests/`, so any edit there
changes every source hash. All 52 derivations are identical. Against the
unmodified tree, the 40 that depend on workspace source differ. The 12 kernels
and kernel configs, which do not, are identical. For the x86_64 glibc SDK
cdylib, `nix derivation show` finds only two differences: the `mvm-workspace`
source path, and the vendor directory derived from that source's `Cargo.lock`. `nix flake check --no-build --all-systems` passes on `nix/` and
checks the 18 new package outputs.

## Not yet

The Stage 0 source fingerprint (`builder_vm_source_fingerprint`) hashes
`nix/lib` but not `nix/flake.nix` or `nix/packages/`. The builder image already
depended on `nix/packages/mvm-setpriv.nix` without that file being hashed; it
now also depends on `nix/flake.nix` and `nix/packages/guest.nix`, which are not
hashed either.
