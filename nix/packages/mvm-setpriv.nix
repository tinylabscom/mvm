# Minimal static-musl privilege-drop helper used by the guest PID 1.

{
  rustPlatform,
  lib,
  mvmSrc,
}:

rustPlatform.buildRustPackage {
  pname = "mvm-setpriv";
  version = "0.18.1";

  src = mvmSrc;
  cargoLock = import ../lib/static-crates-cargo-lock.nix {
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Stage 0 runs Nix without its normal sandbox. Keep Cargo from creating
  # Nix's sentinel home directory in the shared build root.
  HOME = "/tmp";
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-setpriv"
  ];
  doCheck = false;

  meta = with lib; {
    description = "minimal static-musl privilege-drop helper for mvm guests";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
