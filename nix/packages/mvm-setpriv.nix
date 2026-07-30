# Minimal static-musl privilege-drop helper used by the guest PID 1.

{ rustPlatform, lib, mvmSrc }:

rustPlatform.buildRustPackage {
  pname = "mvm-setpriv";
  version = "0.18.0";

  src = mvmSrc;
  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # A path input evaluated from the nix subflake can retain a trailing
  # `nix/..` source shape. Copy it into a normal directory before the generic
  # unpacker sees it.
  unpackPhase = ''
    runHook preUnpack
    cp -R ${mvmSrc}/. source
    chmod -R u+w source
    sourceRoot=source
    runHook postUnpack
  '';

  # Stage 0 runs Nix without its normal sandbox. Keep Cargo from creating
  # Nix's sentinel home directory in the shared build root.
  HOME = "/tmp";
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
