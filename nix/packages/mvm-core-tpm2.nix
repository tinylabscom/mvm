# Compile-check mvm-core with the real TPM2 provider enabled.
#
# This is a lighter validation target than the full mvmctl package: it avoids
# the heavy mvmctl build-script path (which builds qemu-wasm-engine) and only
# exercises the tss-esapi link surface inside mvm-core.

{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  mvmSrc,
  tpm2-tss,
}:

rustPlatform.buildRustPackage {
  pname = "mvm-core-tpm2";
  version = "0.18.0";

  src = mvmSrc;

  cargoLock = import ../lib/static-crates-cargo-lock.nix {
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = ''
    runHook preUnpack
    cp -R ${mvmSrc}/. source
    chmod -R u+w source
    sourceRoot=source
    runHook postUnpack
  '';

  cargoBuildFlags = [
    "--package"
    "mvm-core"
    "--features"
    "attestation-tpm2"
  ];

  cargoTestFlags = [
    "--package"
    "mvm-core"
    "--features"
    "attestation-tpm2"
  ];

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    tpm2-tss
  ];

  # We only need compile + link validation, not the full cargo test matrix.
  doCheck = false;

  meta = with lib; {
    description = "mvm-core compile-check with TPM2 attestation";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
