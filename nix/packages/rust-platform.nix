# One compiler source for first-party recipes, including direct library consumers.
{ pkgs
, mvmSrc
, target ? pkgs.stdenv.hostPlatform.rust.rustcTarget
, extensions ? [ ]
}:

let
  version = (builtins.fromTOML (builtins.readFile (mvmSrc + "/rust-toolchain.toml"))).toolchain.channel;
  lock = (builtins.fromJSON (builtins.readFile (mvmSrc + "/nix/flake.lock"))).nodes.rust-overlay.locked
    or (throw "MVM Rust platform requires the repository's locked rust-overlay input");
  validLock =
    (lock.type or "") == "github"
    && (lock.owner or "") == "oxalica"
    && (lock.repo or "") == "rust-overlay"
    && builtins.match "[0-9a-f]{40}" (lock.rev or "") != null
    && builtins.match "sha256-[A-Za-z0-9+/]{43}=" (lock.narHash or "") != null;
  overlaySource =
    assert pkgs.lib.assertMsg validLock "MVM Rust platform requires an immutable, hash-pinned oxalica/rust-overlay GitHub lock";
    builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/${lock.rev}.tar.gz";
      sha256 = lock.narHash;
    };
  # Executables run on the build machine; the platform below retains the target stdenv.
  buildPkgs = pkgs.buildPackages.extend (import overlaySource);
  toolchain = buildPkgs.rust-bin.stable.${version}.minimal.override {
    targets = [ target ];
    inherit extensions;
  };
in
{
  inherit toolchain;
  rustPlatform = pkgs.makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };
}
