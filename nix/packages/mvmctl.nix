# Source-built host package for the `mvmctl` CLI.
#
# Security invariants:
# - build from `mvmSrc` and its committed Cargo.lock, never from a
#   project-published release tarball;
# - native libkrun FFI is opt-in and requires an explicit `libkrun`
#   package so the bindgen/link boundary is visible in Nix;
# - the default package keeps the builder-VM feature enabled for normal
#   DX but does not force a host libkrun install on systems that do not
#   need the native FFI path.

{ lib
, stdenv
, rustPlatform
, pkg-config
, mvmSrc
, libkrun ? null
, withBuilderVm ? true
, withNativeLibkrun ? false
}:

assert withNativeLibkrun -> libkrun != null;
assert withNativeLibkrun -> withBuilderVm;

let
  featureList =
    lib.optionals withBuilderVm [ "mvmctl/builder-vm" ]
    ++ lib.optionals withNativeLibkrun [
      "mvm-cli/libkrun-sys"
      "mvm-vm-host/libkrun-sys"
    ];
in
rustPlatform.buildRustPackage {
  pname = "mvmctl";
  version = "0.16.1";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  cargoBuildFlags =
    [
      "--package"
      "mvmctl"
      "--package"
      "mvm-vm-host"
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
    "mvm-vm-host"
  ];

  nativeBuildInputs =
    [
      pkg-config
    ]
    ++ lib.optional withNativeLibkrun rustPlatform.bindgenHook;

  buildInputs = lib.optional withNativeLibkrun libkrun;

  env = lib.optionalAttrs withNativeLibkrun {
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
