# Single source of truth for filtering the host workspace tree into
# the Nix store when building images. Used by:
#
#   nix/images/builder-vm/flake.nix
#   nix/images/runtime-overlay/flake.nix
#
# Note: nix/images/builder/flake.nix was deleted in Plan 115 / ADR-065.
# The builder-vm flake now produces both the headless (default) and
# interactive (dev) attrs — no separate builder/ flake is needed.
#
# Maintenance: the excluded basenames here must stay aligned with the
# root .gitignore. The two serve different purposes — .gitignore
# honors path prefixes and negation; this filter matches basenames —
# so they are not auto-derived. When you add a directory to
# .gitignore that names something anywhere in the tree (a new build
# artifact, a new tool's scratch dir), add its basename here too.

{ lib }:

{ workspaceRoot, name ? "mvm-workspace" }:
builtins.path {
  inherit name;
  path = workspaceRoot;
  filter =
    path: _type:
    let
      base = baseNameOf path;
    in
    !(builtins.elem base [
      # Build artifacts (Rust / Node / Astro / Swift / Nix outputs).
      "target"
      "result"
      "node_modules"
      ".direnv"
      ".cargo"
      "dist"
      ".astro"
      # Swift Package Manager output. mvm-backend/swift and
      # mvm-vz-supervisor each carry a multi-GB .build; leaving it in
      # OOMs the Stage 0 guest while it unpacks the staged workspace.
      ".build"
      "dev-prebuilt"
      # Test / generated outputs.
      ".mvm-test"
      "graphify-out"
      ".ur-seed-result"
      "nixos.qcow2"
      # VCS / agent / worktree / tooling scratch.
      ".git"
      ".claude"
      ".worktrees"
      ".playwright-mcp"
      # Secrets (host-side; the in-VM key path is ~/.mvm/keys).
      "keys"
    ])
    && !(lib.hasPrefix "result-" base);
}
