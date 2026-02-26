{
  description = "mvm guest agent — vsock agent binary for Firecracker microVMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mvm-src = {
      url = "path:../..";
      flake = false;
    };
  };

  outputs = { nixpkgs, rust-overlay, mvm-src, ... }:
    let
      forEachSystem = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in {
      packages = forEachSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable.latest.minimal;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in {
          default = rustPlatform.buildRustPackage {
            pname = "mvm-guest-agent";
            version = "0.3.0";

            src = pkgs.lib.fileset.toSource {
              root = mvm-src;
              fileset = pkgs.lib.fileset.unions [
                (mvm-src + "/Cargo.toml")
                (mvm-src + "/Cargo.lock")
                (mvm-src + "/src")
                (mvm-src + "/crates")
              ];
            };

            cargoLock.lockFile = mvm-src + "/Cargo.lock";
            cargoBuildFlags = [ "-p" "mvm-guest" "--bin" "mvm-guest-agent" ];
            doCheck = false;
          };
        });
    };
}
