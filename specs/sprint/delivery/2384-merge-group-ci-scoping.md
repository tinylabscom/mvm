# Merge-group CI scoping

A fail-closed SHA-range classifier keeps the full Rust matrix for
behavior-changing diffs and manual runs, while prose/site-only pull requests
and merge groups avoid six cold Rust jobs. Policy and the independently scoped
required Nix check remain unconditional authorities for their own input
surfaces. Workflow syntax, formatting, workspace compilation, all-target
Clippy, and all 499 `xtask` tests pass; the sole transient workspace-suite
host-restart failure passed on its exact isolated rerun.
