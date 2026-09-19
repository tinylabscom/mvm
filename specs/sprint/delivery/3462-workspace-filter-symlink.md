# A symlinked workspace root is resolved or refused, never filtered to nothing

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test nix_flake_structure -E 'test(workspace_filter_refuses_a_symlinked_root_when_nix_available)'

`nix/lib/workspace-filter.nix` decides what to keep by stripping the workspace
root from each path as text. Nix hands the filter symlink-resolved paths, so a
root reached through a symlink — on macOS any path under `/tmp`, which is a
link to `/private/tmp` — matches nothing, and the filtered `mvm-workspace`
store path is empty. Nothing said so: the build failed later with
`path '/nix/store/…-mvm-workspace/Cargo.lock' does not exist`, pointing away
from the cause.

Two changes, one on each side of the boundary:

- The filter now refuses a tree with no `Cargo.lock`, naming the root, the
  likely cause, and the `pwd -P` remedy. Nix cannot resolve a path itself, so
  refusing by name is the most the filter can do. For a canonical root the
  returned value is the same `builtins.path` expression, so the store path is
  unchanged.
- `OverlayBuildSpec::env`, the one place the host hands a host path to Nix as
  `MVM_WORKSPACE_PATH`, now passes it through `fs::canonicalize`. Every other
  setter passes `/work`, the builder VM's mount point, which has no symlink.

Evidence, from `nix eval` (Nix 2.35.1) on macOS:

| root | `origin/main` filter | this change |
|---|---|---|
| worktree, canonical | `afinzg6c…-mvm-workspace` | `afinzg6c…-mvm-workspace` |
| same tree via `/tmp/…` symlink | `587dgbdh…-mvm-workspace` (empty) | refused: "the filtered tree of /tmp/… has no Cargo.lock" |
| `packages.aarch64-linux.mvm-setpriv.drvPath`, symlinked root | `path '/nix/store/587dgbdh…-mvm-workspace/Cargo.lock' does not exist` | the same named refusal |

The canonical row is the same store path under both filters against the same
tree, which is the proof the filter's output did not move. The symlinked case
now fails at evaluation, where the message can name the cause.

`nix/tests/workspace-filter-eval.nix` pins that behaviour and
`tests/nix_flake_structure.rs` drives it whenever `nix` is on `PATH`; the
`runtime_overlay` unit test `build_spec_env_resolves_a_symlinked_workspace_root`
covers the Rust side. `build_cache.rs` parses the filter's lists by name and
still finds both.
