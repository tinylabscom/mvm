# Single source of truth for filtering the host workspace tree into
# the Nix store when building images. Used by:
#
#   nix/images/builder-vm/flake.nix
#   nix/images/runtime-overlay/flake.nix
#
# Note: there is no longer a separate nix/images/builder/flake.nix.
# The builder-vm flake now produces both the headless (default) and
# interactive (dev) attrs — no separate builder/ flake is needed.
#
# ## Why this is an allow-list
#
# The filtered tree becomes `mvmSrc`, and `buildRustPackage { src = mvmSrc; }`
# derives its output path from the whole filtered NAR. Every file that survives
# this filter is therefore a cache key for every guest binary we build. A
# deny-list over the workspace root meant that editing a Markdown file — which
# the contribution rules require on essentially every change — moved the store
# path and forced a full guest-agent rebuild.
#
# The allow-list is the set of top-level entries `cargo` can read while building
# or testing any workspace target:
#
#   Cargo.toml / Cargo.lock  workspace + dependency resolution
#   rust-toolchain.toml      toolchain pin
#   build.rs                 root package build script
#   src/                     root package (`mvmctl`) sources
#   crates/                  every workspace member
#   third_party/             workspace-local patched/path dependencies
#   xtask/                   workspace member
#   tests/                   root package integration targets; the source-built
#                            mvmctl derivation leaves doCheck at its default, so
#                            `cargo test --package mvmctl` compiles these
#   third_party/             vendored path dependencies referenced by Cargo.toml
#   schema/                  wire schemas; kept because they never churn, so
#                            excluding them would buy nothing
#   nix/                     the flakes themselves, nix/lib, nix/packages, and
#                            the wrapper scripts guest code include_str!s
#
# Everything else — docs, the site, the language SDK surfaces, BDD features,
# examples, scripts, top-level tool config — cannot reach a compiled target, so
# touching it no longer invalidates a build.
#
# ## Maintenance
#
# Adding a top-level directory that a crate reads at *compile* time (an
# `include_str!` / `include_bytes!` escaping its crate root) means adding it
# here, or the build breaks with a missing-file error at the include site.
#
# `crates/mvm-build`'s host-side build fingerprint mirrors this list, and the
# binding runs the opposite way from the old deny-list: the fingerprint must
# hash a *superset* of what this filter admits, because hashing extra files
# only costs a redundant rebuild while hashing too few serves a stale image. A
# test in that crate reads this file and enforces it.
#
# The excluded-basename list is pruned inside the admitted roots (build
# artifacts, VCS and agent scratch, key material) and must stay aligned with the
# root .gitignore for those names.

{ lib }:

{ workspaceRoot, name ? "mvm-workspace" }:
let
  root = toString workspaceRoot;

  # Top-level entries admitted into the store path. Order is irrelevant;
  # `crates/mvm-build/src/pipeline/build_cache.rs` parses this list by name.
  includedTopLevel = [
    "Cargo.toml"
    "Cargo.lock"
    "rust-toolchain.toml"
    "build.rs"
    "src"
    "crates"
    "third_party"
    "xtask"
    "tests"
    "third_party"
    "schema"
    "nix"
    ".github"
  ];

  # Pruned *within* the admitted roots.
  excludedBasenames = [
    # Build artifacts (Rust / Node / Astro / Swift / Nix outputs).
    "target"
    "result"
    "node_modules"
    ".direnv"
    ".cargo"
    "dist"
    ".astro"
    # Swift Package Manager output dirs can carry a multi-GB .build;
    # leaving it in OOMs the Stage 0 guest while it unpacks the staged
    # workspace.
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
  ];

  # Path relative to the workspace root. The root itself maps to "", which is
  # always admitted — a rootless relative path must never reach `head`.
  relativeTo = path: lib.removePrefix "${root}/" (toString path);

  topLevelOf = rel: lib.head (lib.splitString "/" rel);
in
builtins.path {
  inherit name;
  path = workspaceRoot;
  filter =
    path: _type:
    let
      rel = relativeTo path;
      base = baseNameOf path;
    in
    (rel == "" || builtins.elem (topLevelOf rel) includedTopLevel)
    && !(builtins.elem base excludedBasenames)
    && !(lib.hasPrefix "result-" base);
}
