# Build `mvm-verity-init` as a fully-static musl-libc binary.
#
# The verity initramfs has no glibc loader, no /lib/ld-linux*, no
# anything beyond what we put in `/init`. A normal dynamic-linked
# build dies with `Failed to execute /init (error -2)` because the
# kernel can't find the dynamic loader. Static linking against musl
# produces a self-contained ELF that runs as PID 1 from a bare
# directory tree.
#
# This is a separate derivation from `mvm-guest-agent.nix` because:
#   1. The toolchain differs (musl vs. glibc).
#   2. The agent + seccomp-apply run inside the rootfs and can keep
#      dynamic linking — no reason to recompile them statically.
#   3. The closure is much smaller (~600 KB vs. tens of MB), which
#      matters for the initramfs size.
#
# We use `pkgs.pkgsStatic` — a nixpkgs cross-compilation alias whose
# stdenv defaults to musl-static linking. `rustPlatform.buildRustPackage`
# under that stdenv produces a self-contained ELF.
#
# ADR-002 §W3.

{ pkgs, mvmSrc }:

let
  staticPkgs = pkgs.pkgsStatic;
in

staticPkgs.rustPlatform.buildRustPackage {
  pname = "mvm-verity-init";
  version = "0.1.0";

  src = pkgs.lib.fileset.toSource {
    root = mvmSrc;
    fileset = pkgs.lib.fileset.unions [
      (mvmSrc + "/Cargo.toml")
      (mvmSrc + "/Cargo.lock")
      (mvmSrc + "/src")
      (mvmSrc + "/crates")
      (mvmSrc + "/xtask")
    ];
  };

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  cargoBuildFlags = [ "-p" "mvm-guest" "--bin" "mvm-verity-init" ];
  doCheck = false;
}
