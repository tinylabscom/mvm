{ pkgs, lockFile }:

let
  cratesIo = import ./crates-io.nix;
  fetchStaticCrate =
    args:
    pkgs.fetchurl (
      args
      // {
        url = cratesIo.toCdn args.url;
      }
    );
  importCargoLock = pkgs.callPackage (pkgs.path + "/pkgs/build-support/rust/import-cargo-lock.nix") {
    fetchurl = fetchStaticCrate;
  };
in
importCargoLock { inherit lockFile; }
