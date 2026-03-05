# Build the mvm-guest-agent binary from the workspace.
#
# Usage from a flake:
#   mvm-guest-agent = import ../../nix/guest-lib/guest-agent-pkg.nix {
#     inherit pkgs;
#     mvmSrc = ../../.;
#   };

{ pkgs, mvmSrc, rustPlatform ? pkgs.rustPlatform }:

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
    ];
  };

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  # dev-shell enables the Exec handler; access is controlled at runtime
  # by the security policy on the config drive (access.debug_exec).
  cargoBuildFlags = [ "-p" "mvm-guest" "--bin" "mvm-guest-agent" "--features" "dev-shell" ];
  doCheck = false;
}
