# Runtime test for the TPM2 attestation provider.
#
# Builds mvm-core with the real tss-esapi provider enabled and runs an
# integration test that starts a software TPM (swtpm), generates a quote,
# and validates the JSON envelope. This is heavier than the compile-only
# `mvm-core-tpm2` package because it must build swtpm and exercise the
# full TPM2 command flow.

{ lib
, stdenv
, rustPlatform
, pkg-config
, mvmSrc
, tpm2-tss
, swtpm
}:

rustPlatform.buildRustPackage {
  pname = "mvm-core-tpm2-test";
  version = "0.18.0";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

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
    "--test"
    "tpm2_swtpm"
  ];

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    tpm2-tss
  ];

  nativeCheckInputs = [
    swtpm
  ];

  # Run only the swtpm-backed runtime test; the compile/link path is already
  # covered by `mvm-core-tpm2`.
  doCheck = true;

  meta = with lib; {
    description = "mvm-core TPM2 attestation runtime test";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
