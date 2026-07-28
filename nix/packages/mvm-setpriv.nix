# Minimal static-musl privilege-drop helper used by the guest PID 1.

{ rustPlatform, lib, mvmSrc }:

rustPlatform.buildRustPackage {
  pname = "mvm-setpriv";
  version = "0.18.0";

  src = mvmSrc;
  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  cargoBuildFlags = [
    "--package" "mvm-agentd"
    "--bin" "mvm-setpriv"
  ];
  doCheck = false;

  meta = with lib; {
    description = "minimal static-musl privilege-drop helper for mvm guests";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
