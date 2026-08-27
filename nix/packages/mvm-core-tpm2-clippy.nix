# Run `cargo clippy -D warnings` on mvm-core with the real TPM2 provider.
#
# This is separate from `mvm-core-tpm2` because clippy needs the `clippy`
# driver, which is not part of the minimal rustPlatform toolchain used for
# the release build.

{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  clippy,
  mvmSrc,
  tpm2-tss,
}:

rustPlatform.buildRustPackage {
  pname = "mvm-core-tpm2-clippy";
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

  nativeBuildInputs = [
    pkg-config
    clippy
  ];

  buildInputs = [
    tpm2-tss
  ];

  # Skip the default cargo build; run clippy instead.
  buildPhase = ''
    runHook preBuild
    cargo clippy --offline ''${cargoBuildFlags[@]} -- -D warnings
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p "$out"
  '';

  doCheck = false;

  meta = with lib; {
    description = "mvm-core clippy check with TPM2 attestation";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
