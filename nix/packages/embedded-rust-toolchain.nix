# Use one upstream release for cargo, rustc and the musl standard library.
# The common supplier selects the repository's compiler and locked component hashes.
{ pkgs, mvmSrc, target }:
(import ./rust-platform.nix { inherit pkgs mvmSrc target; }).toolchain
