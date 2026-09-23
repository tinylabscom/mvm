# Guest GPU shim libraries: drop-in libcuda.so.1 / libcudart.so /
# libnvidia-ml.so.1 replacements that forward the CUDA driver/runtime/NVML
# APIs to the per-VM host GPU endpoint over vsock.
#
# Each derivation builds one cdylib from its crate, linked against the same
# libc the guest userland runs (glibc for OCI-rooted guests, musl for the
# sealed overlay). The image composition (which guests carry the shims
# and where the loader finds them) lives in the mvm-images repository; these
# recipes only produce the .so files with the right sonames.

{
  pkgs,
  lib,
  mvmSrc,
  musl ? false,
}:

let
  isMusl = musl;
  variant = if musl then "musl" else "glibc";

  muslTarget =
    if pkgs.stdenv.hostPlatform.isAarch64 then
      "aarch64-unknown-linux-musl"
    else if pkgs.stdenv.hostPlatform.isx86_64 then
      "x86_64-unknown-linux-musl"
    else
      throw "no musl target for this host platform";

  # A musl stdenv rebuilds the Rust/LLVM toolchain and its bootstrap closure
  # from source on the image builders. The shims are pure Rust, so use the
  # same lightweight prebuilt Rust + musl-std wrapper as the SDK cdylib.
  muslToolchain = pkgs.callPackage ./embedded-rust-toolchain.nix {
    cargo = pkgs.rust_1_91.packages.prebuilt.cargo;
    rustc = pkgs.rust_1_91.packages.prebuilt.rustc;
    target = muslTarget;
  };

  # Only the linker needs to come from pkgsMusl. This wrapper is cached and
  # makes the resulting shared object depend on musl's libc.so, not glibc.
  muslLinker = "${pkgs.pkgsMusl.stdenv.cc}/bin/gcc";

  crateFor =
    {
      crate,
      libName,
      soname,
    }:
    pkgs.rustPlatform.buildRustPackage ({
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
        CARGO_PROFILE_RELEASE_LTO = "thin";
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
        CARGO_PROFILE_RELEASE_STRIP = "symbols";
      };

      # buildRustPackage installs `${libName}.so`; rename to the soname the
      # loader looks for.
      postInstall = ''
        libdir="$out/lib"
        mkdir -p "$libdir"
        if [ ! -e "$libdir/lib${libName}.so" ]; then
          find target -name 'lib${libName}*.so' -print \
            -exec install -m0644 {} "$libdir/lib${libName}.so" \;
        fi
        mv "$libdir/lib${libName}.so" "$libdir/${soname}"

        needed="$(${pkgs.binutils}/bin/readelf -d "$libdir/${soname}" \
          | grep NEEDED || true)"
        echo "$needed"
        ${if isMusl then ''
          if ! echo "$needed" | grep -q 'Shared library: \[libc\.so\]'; then
            echo "expected a musl object (NEEDED libc.so); got the above" >&2
            exit 1
          fi
        '' else ''
          if ! echo "$needed" | grep -q 'Shared library: \[libc\.so\.6\]'; then
            echo "expected a glibc object (NEEDED libc.so.6); got the above" >&2
            exit 1
          fi
        ''}
      '';

      meta = with lib; {
        description = "mvm guest GPU shim library (${soname})";
        homepage = "https://github.com/tinylabscom/mvm";
        license = licenses.asl20;
        platforms = platforms.linux;
      };
    } // lib.optionalAttrs isMusl {
      nativeBuildInputs = [ muslToolchain ];
      CARGO_BUILD_TARGET = muslTarget;
      # A cdylib must stay dynamically linked to the matching guest libc.
      RUSTFLAGS = "-C target-feature=-crt-static -C linker=${muslLinker}";
    });

  # crate name -> installed soname. The cdylib target name is the crate's
  # [lib] name (cuda / cudart / nvidia_ml); the soname is what workloads
  # link against.
  shims = {
    "mvm-gpu-cuda-shim" = {
      libName = "cuda";
      soname = "libcuda.so.1";
    };
    "mvm-gpu-cudart-shim" = {
      libName = "cudart";
      soname = "libcudart.so";
    };
    "mvm-gpu-nvml-shim" = {
      libName = "nvidia_ml";
      soname = "libnvidia-ml.so.1";
    };
  };

  each = lib.mapAttrs (crate: shim: crateFor ({ inherit crate; } // shim)) shims;
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
