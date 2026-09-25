//! What the builder image reads from an mvm tree.
//!
//! The local image cache key of a builder image built from a paired image
//! checkout must cover every mvm source the image's evaluation reads: the
//! pair's builder evaluation calls `nix/flake.nix`'s outputs for mkGuest, the
//! guest recipes and the host-binaries manifest. This is that list, and the key
//! falls back to the whole checkout when the image checkout reads anything
//! outside it.

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
