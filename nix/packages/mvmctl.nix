# Build the `mvmctl` host CLI from the workspace root.
#
# This is the developer-machine binary — same output you get from
# `cargo build -p mvmctl --release`. It runs natively on the host (macOS
# or Linux) and dispatches into the builder VM for everything that needs
# `/dev/kvm`. Image-build outputs (rootfs, kernel) are deliberately NOT
# part of mvmctl's closure: those run inside the builder VM.
#
# Usage from `nix/flake.nix`:
#   mvmctl = import ./packages/mvmctl.nix {
#     inherit pkgs rustPlatform mvmSrc;
#   };

{ pkgs, mvmSrc, rustPlatform ? pkgs.rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "mvmctl";
  version = "0.13.0";

  # Same workspace-only filter the guest-agent uses: just the Rust + cargo
  # bits, no specs/public/scripts. Editing markdown, the public doc site,
  # or `nixos.qcow2` doesn't rebuild the binary.
  src = pkgs.lib.fileset.toSource {
    root = mvmSrc;
    fileset = pkgs.lib.fileset.unions [
      (mvmSrc + "/Cargo.toml")
      (mvmSrc + "/Cargo.lock")
      (mvmSrc + "/build.rs")
      (mvmSrc + "/src")
      (mvmSrc + "/crates")
      (mvmSrc + "/xtask")
      (mvmSrc + "/resources")
    ];
  };

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  cargoBuildFlags = [ "-p" "mvmctl" "--bin" "mvmctl" ];

  # Workspace tests need a live Lima VM / KVM / Apple Container; running
  # them inside a Nix sandbox would fail. CI runs `cargo nextest run` in
  # a separate job (`.github/workflows/ci.yml`).
  doCheck = false;

  meta = {
    description = "mvm host CLI";
    mainProgram = "mvmctl";
    platforms = pkgs.lib.platforms.unix;
  };
}
