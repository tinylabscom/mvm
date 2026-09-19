# Evaluation test for nix/lib/workspace-filter.nix. Run via:
#
#   nix --extra-experimental-features 'nix-command flakes' eval --impure --json \
#     --expr 'import ./nix/tests/workspace-filter-eval.nix {
#       canonical = "/private/tmp/ws"; linked = "/tmp/ws"; }'
#
# `canonical` is a workspace root with every symlink resolved; `linked` is the
# same workspace reached through a symlink. The filter strips the root from
# symlink-resolved paths as text, so the linked root must be refused by name
# rather than yield an empty tree. The Rust test in
# `tests/nix_flake_structure.rs` builds both and shells out to this file when
# nix is on PATH.

{ canonical, linked }:
let
  flake = builtins.getFlake (toString ./..);
  inherit (flake.inputs.nixpkgs) lib;
  filter = root: (import ../lib/workspace-filter.nix { inherit lib; }) { workspaceRoot = /. + root; };
  canonicalTree = filter canonical;
in
{
  canonicalKeepsTheLockfile = builtins.pathExists (canonicalTree + "/Cargo.lock");
  canonicalDropsUnlistedEntries = !(builtins.pathExists (canonicalTree + "/docs"));
  linkedRootIsRefused = !(builtins.tryEval (filter linked)).success;
}
