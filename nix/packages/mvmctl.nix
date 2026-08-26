# Source-built host package for the `mvmctl` CLI.
#
# Security invariants:
# - build from `mvmSrc` and its committed Cargo.lock, never from a
#   project-published release tarball;
# - native libkrun FFI is opt-in and requires explicit `libkrun`
#   and `libkrunfw` packages so the bindgen/link boundary is visible in Nix;
# - the default package keeps the builder-VM feature enabled for normal
#   DX but does not force a host libkrun install on systems that do not
#   need the native FFI path.

{ lib
, stdenv
, rustPlatform
, pkg-config
, cargo-zigbuild
, curl
, zig
, embeddedCargo
, embeddedRustc
, lld
, mvmSrc
, libkrun ? null
, libkrunfw ? null
, tpm2-tss ? null
, withBuilderVm ? true
, withNativeLibkrun ? false
, withTpm2 ? false
, runTests ? true
}:

assert withNativeLibkrun -> libkrun != null;
assert withNativeLibkrun -> libkrunfw != null;
assert withNativeLibkrun -> withBuilderVm;
assert withTpm2 -> tpm2-tss != null;

let
  featureList =
    []
    ++ lib.optionals withBuilderVm [
      "mvm-cli/builder-vm"
      "mvm-build/builder-vm"
    ]
    ++ lib.optionals withNativeLibkrun [
      "mvm-cli/libkrun-sys"
      "mvm-hostd/libkrun-sys"
    ]
    ++ lib.optionals withTpm2 [ "mvmctl/attestation-tpm2" ];
in
rustPlatform.buildRustPackage {
  pname = "mvmctl";
  version = "0.18.0";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # The `nix/` subflake imports the workspace as `path:..`; when the
  # flake itself is evaluated from a git source, that input can arrive
  # as a store path ending in `nix/..`. The generic unpacker refuses
  # that parent-segment shape, so copy the workspace into a normal
  # `source/` directory before the Rust builder enters it.
  unpackPhase = ''
    runHook preUnpack
    cp -R ${mvmSrc}/. source
    chmod -R u+w source
    sourceRoot=source
    runHook postUnpack
  '';

  cargoBuildFlags =
    [
      "--package"
      "mvmctl"
      "--package"
      "mvm-hostd"
    ]
    ++ lib.optionals (!withBuilderVm) [
      "--no-default-features"
    ]
    ++ lib.optionals (featureList != [ ]) [
      "--features"
      (lib.concatStringsSep "," featureList)
    ];

  cargoTestFlags = [
    "--package"
    "mvmctl"
    "--package"
    "mvm-hostd"
  ];

  doCheck = runTests;

  # cargo-auditable 0.6.5 runs `cargo metadata` from each rustc wrapper
  # invocation. With package-qualified native features enabled, that metadata
  # path treats `libkrun-sys` as an unqualified workspace feature and trips over
  # mvm-build's intentionally dep-only `libkrun-sys` dependency. Keep the
  # default source-built mvmctl package auditable; disable the wrapper only for
  # the opt-in native-libkrun variant so the native sidecar set still builds and
  # runs its checks. TPM2 forwards through a root-owned feature and stays
  # auditable.
  auditable = !withNativeLibkrun;

  nativeBuildInputs =
    [
      cargo-zigbuild
      lld
      pkg-config
      zig
    ]
    ++ lib.optional withNativeLibkrun rustPlatform.bindgenHook;

  nativeCheckInputs = [
    curl
  ];

  buildInputs = lib.optionals withNativeLibkrun [
    libkrun
    libkrunfw
  ]
  ++ lib.optionals withTpm2 [
    tpm2-tss
  ];

  env = {
    MVM_EMBED_CARGO = "${embeddedCargo}/bin/cargo";
    MVM_EMBED_RUSTC = "${embeddedRustc}/bin/rustc";
  } // lib.optionalAttrs withNativeLibkrun {
    MVM_LIBKRUN_HEADER = "${lib.getDev libkrun}/include/libkrun.h";
  };

  meta = with lib; {
    description = "mvm command-line tool";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    mainProgram = "mvmctl";
    platforms = platforms.unix;
  };
}
