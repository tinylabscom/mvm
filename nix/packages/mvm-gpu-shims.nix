# Guest GPU shim libraries: drop-in libcuda.so.1 / libcudart.so /
# libnvidia-ml.so.1 replacements that forward the CUDA driver/runtime/NVML
# APIs to the per-VM host GPU endpoint over vsock.
#
# Each derivation builds one cdylib from its crate, linked against the same
# libc the guest userland runs (glibc for OCI-rooted guests, musl-static for
# the sealed overlay). The image composition (which guests carry the shims
# and where the loader finds them) lives in the mvm-images repository; these
# recipes only produce the .so files with the right sonames.

{
  pkgs,
  lib,
  mvmSrc,
  static ? false,
}:

let
  # The musl variant must NOT use pkgsStatic: that stdenv disables dynamic
  # linking, and a shim is by definition a shared object — rustc refuses the
  # cdylib crate type there. pkgsMusl keeps dynamic linking available while
  # the +crt-static RUSTFLAGS below still link musl into the cdylib, so the
  # result is self-contained and dlopen-able from a sealed-overlay musl guest.
  toolchainPkgs = if static then pkgs.pkgsMusl else pkgs;
  variant = if static then "musl" else "glibc";
  crateFor =
    {
      crate,
      soname,
    }:
    toolchainPkgs.rustPlatform.buildRustPackage {
      pname = crate;
      version = "0.18.0";

      src = mvmSrc;

      cargoDeps = import ../lib/static-crates-cargo-deps.nix {
        inherit pkgs;
        lockFile = mvmSrc + "/Cargo.lock";
      };

      cargoBuildFlags = [
        "--package"
        crate
      ];

      # cdylibs only: no test harness, no bins.
      doCheck = false;

      env = {
        # The build.rs sets -Wl,-soname,<soname>; the installed file must
        # carry the soname too, because the guest loader resolves by it.
        RUSTFLAGS = lib.optionalString static "-C target-feature=+crt-static";
        CARGO_PROFILE_RELEASE_LTO = "thin";
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
        CARGO_PROFILE_RELEASE_STRIP = "symbols";
      };

      # buildRustPackage installs `${libName}.so`; rename to the soname the
      # loader looks for.
      postInstall = ''
        libdir="$out/lib"
        mv "$libdir/lib${crate}.so" "$libdir/${soname}" 2>/dev/null || true
      '';

      meta = with lib; {
        description = "mvm guest GPU shim library (${soname})";
        homepage = "https://github.com/tinylabscom/mvm";
        license = licenses.asl20;
        platforms = platforms.linux;
      };
    };

  # crate name -> installed soname. The cdylib target name is the crate's
  # [lib] name (cuda / cudart / nvidia_ml); the soname is what workloads
  # link against.
  shims = {
    "mvm-gpu-cuda-shim" = "libcuda.so.1";
    "mvm-gpu-cudart-shim" = "libcudart.so";
    "mvm-gpu-nvml-shim" = "libnvidia-ml.so.1";
  };

  each = lib.mapAttrs (crate: soname: crateFor { inherit crate soname; }) shims;
in
# One derivation per variant: flake `packages` outputs must be derivations,
# and consumers (the runtime overlay in mvm-images) want the whole shim set
# at once anyway. symlinkJoin merges each shim's $out/lib/<soname>.
pkgs.symlinkJoin {
  name = "mvm-gpu-shims-${variant}";
  paths = lib.attrValues each;
  meta = with lib; {
    description = "mvm guest GPU shim libraries (libcuda.so.1, libcudart.so, libnvidia-ml.so.1), ${variant} variant";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
