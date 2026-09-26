//! What the builder image reads from an mvm tree.
//!
//! Two cache keys describe a builder image built from mvm source: the Stage 0
//! fingerprint of the in-tree builder flake, and the local image cache key of a
//! builder image built from a paired image checkout. Both must cover every
//! mvm source the image's evaluation reads, and both read the same ones: the
//! pair's builder evaluation calls `nix/flake.nix`'s outputs for mkGuest, the
//! guest recipes and the host-binaries manifest, exactly as the in-tree flake
//! does. One list, so the two keys cannot disagree about it.

/// The Nix sources, relative to the workspace root, that the builder-vm flake
/// imports from outside its own directory: the shared library (mkGuest, the
/// workspace filter, the host-binaries manifest), the guest package recipes,
/// the kernel configs, and the runtime-overlay flake. The top-level `nix`
/// flake is listed because a build reaches the recipes through it.
///
/// A test holds this list to the flakes' actual import sites, so adding an
/// import without listing it fails rather than going stale.
pub const BUILDER_FLAKE_NIX_INPUTS: &[&str] = &[
    "nix/flake.nix",
    "nix/flake.lock",
    "nix/lib",
    "nix/packages",
    "nix/images/kernel",
    "nix/images/runtime-overlay",
];
