# Host-installable packages for the mvm flake.
#
# Keep these separate from nix/lib: nix/lib is the user-facing image
# construction API (`mvm.lib.<system>.mkGuest`), while this package set
# builds host tools from the source checkout.

{ pkgs
, mvmSrc
}:

{
  mvmctl = pkgs.callPackage ./mvmctl.nix {
    inherit mvmSrc;
  };
}
