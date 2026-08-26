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

    # Browser-only WebLinux engine.  Built on demand; default native targets
    # do not depend on it.
    qemu-wasm-engine = pkgs.callPackage ./qemu-wasm.nix { };

    # Minimal x86_64 guest image for QEMU-Wasm smoke tests.
    qemu-wasm-smoke-image = pkgs.callPackage ./qemu-wasm-smoke-image.nix {
      inherit qemu-wasm-engine;
    };

    # Browser-ready asset bundle (engine + image + HTML runner).
    qemu-wasm-smoke-pack = pkgs.callPackage ./qemu-wasm-smoke-pack.nix {
      inherit qemu-wasm-engine qemu-wasm-smoke-image;
    };
  });

  mvmctl = pkgs.callPackage ./mvmctl.nix {
    inherit mvmSrc;
    embeddedCargo = embeddedRustToolchain;
    embeddedRustc = embeddedRustToolchain;
    zig = pkgs.zig_0_13;
  };

  mvmctl-tpm2 = pkgs.callPackage ./mvmctl.nix {
    inherit mvmSrc;
    embeddedCargo = embeddedRustToolchain;
    embeddedRustc = embeddedRustToolchain;
    tpm2-tss = pkgs.tpm2-tss;
    withTpm2 = true;
    runTests = false;
    zig = pkgs.zig_0_13;
  };

  mvm-core-tpm2 = pkgs.callPackage ./mvm-core-tpm2.nix {
    inherit mvmSrc;
    tpm2-tss = pkgs.tpm2-tss;
  };

  mvm-core-tpm2-clippy = pkgs.callPackage ./mvm-core-tpm2-clippy.nix {
    inherit mvmSrc;
    tpm2-tss = pkgs.tpm2-tss;
    clippy = pkgs.clippy;
  };

  mvm-core-tpm2-test = pkgs.callPackage ./mvm-core-tpm2-test.nix {
    inherit mvmSrc;
    tpm2-tss = pkgs.tpm2-tss;
    swtpm = pkgs.swtpm;
  };
in

{
  inherit mvmctl mvmctl-tpm2 mvm-core-tpm2 mvm-core-tpm2-clippy mvm-core-tpm2-test;
} // nativeVmmPackages
