# Issue #2941 — SDK sidecar source build

**Status:** implementation and validation complete; merge delivery remains

The contributor path now has an explicit `mvmctl build sdk-sidecar build`
command. It realizes the existing glibc sidecar derivation through Stage 0,
verifies the three-file artifact contract, and atomically installs the image
with the source fingerprint used by launch-time staleness checks.

The builder-VM flake only passes through the runtime-overlay package, keeping
the glibc closure and ext4 layout in one derivation. Kernel compilation and the
new sidecar build use one shared Stage 0 artifact runner. Workload launch still
never starts a builder VM implicitly; a missing or stale source sidecar names
the explicit command.

Focused Rust and structural regressions, serialized workspace tests, workspace
check, gated Linux and BDD compilation, zero-warning Clippy, and all repository
policy gates are green. A live Stage 0 run built the aarch64 glibc cdylib and
ext4 sidecar inside Nix, then verified and atomically installed the artifact
set with its BLAKE3 source fingerprint. Merge-queue delivery remains before
closeout.
