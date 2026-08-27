{ pkgs, lockFile }:

let
  cratesIoApi = "https://crates.io/api/v1/crates";
  staticCrates = "https://static.crates.io/crates";
  fetchStaticCrate =
    args:
    pkgs.fetchurl (
      args
      // {
        url = builtins.replaceStrings [ cratesIoApi ] [ staticCrates ] args.url;
      }
    );
  importCargoLock = pkgs.callPackage (pkgs.path + "/pkgs/build-support/rust/import-cargo-lock.nix") {
    fetchurl = fetchStaticCrate;
  };
in
importCargoLock { inherit lockFile; }
