# Build the mvm-guest-agent binary from the workspace.
#
# Usage from `nix/flake.nix` (alongside this file):
#   mvm-guest-agent = import ./guest-agent-pkg.nix {
#     inherit pkgs rustPlatform;
#     mvmSrc   = ./..;
#     devShell = false; # default — production: no Exec handler compiled in
#   };
#
# `devShell = true` enables the `dev-shell` Cargo feature which compiles
# in the vsock Exec handler used by `mvmctl exec` and `mvmctl console`.
# Default is `false` so production rootfs builds are physically incapable
# of executing arbitrary commands over vsock.

{ pkgs, mvmSrc, rustPlatform ? pkgs.rustPlatform, devShell ? false }:

rustPlatform.buildRustPackage {
  pname = "mvm-guest-agent";
  version = "0.3.0";

  # Only include Rust source to avoid rebuilds when docs/specs change.
  # Use path concatenation (+) not string interpolation — fileset requires paths, not strings.
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
  # `dev-shell` enables the Exec handler. Production builds omit this feature
  # entirely, so the handler is not compiled into the binary at all.
  cargoBuildFlags = [ "-p" "mvm-guest" "--bin" "mvm-guest-agent" ]
    ++ pkgs.lib.optionals devShell [ "--features" "dev-shell" ];
  doCheck = false;
}
