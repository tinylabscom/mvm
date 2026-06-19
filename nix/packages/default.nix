# Host-installable packages for the mvm flake.
#
# Keep these separate from nix/lib: nix/lib is the user-facing image
# construction API (`mvm.lib.<system>.mkGuest`), while this package set
# builds host tools from the source checkout.

{ pkgs
, mvmSrc
}:

let
  inherit (pkgs) lib;

  embeddedRustTarget =
    if pkgs.stdenv.hostPlatform.isAarch64 then
      "aarch64-unknown-linux-musl"
    else if pkgs.stdenv.hostPlatform.isx86_64 then
      "x86_64-unknown-linux-musl"
    else
      throw "mvmctl Nix package only supports embedded host binaries on aarch64 and x86_64 hosts";

  embeddedRustToolchain = pkgs.callPackage ./embedded-rust-toolchain.nix {
    cargo = pkgs.rust_1_91.packages.prebuilt.cargo;
    rustc = pkgs.rust_1_91.packages.prebuilt.rustc;
    target = embeddedRustTarget;
  };

  nativeVmmPackages = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (rec {
    libkrunfw = pkgs.callPackage ./libkrunfw.nix { };
    libkrun = pkgs.callPackage ./libkrun.nix {
      inherit libkrunfw;
    };

    mvmctl-native-libkrun = mvmctl.override {
      withNativeLibkrun = true;
      inherit libkrun libkrunfw;
    };
  });

  mvmctl = pkgs.callPackage ./mvmctl.nix {
    inherit mvmSrc;
    embeddedCargo = embeddedRustToolchain;
    embeddedRustc = embeddedRustToolchain;
  };
in

{
  inherit mvmctl;
} // nativeVmmPackages
