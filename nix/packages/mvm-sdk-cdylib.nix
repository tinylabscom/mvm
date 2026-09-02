# `libmvm_host_services.so` — the in-guest host-services FFI shared object.
#
# Built from the `mvm-host-services` crate's `cdylib` output. Packaged in the
# SDK sidecar at
# `/mvm/sdk/lib/` and loaded via `ctypes` / `koffi` by the in-guest language
# SDKs (`mvm.audit.emit`, `mvm.host.time()`, ...). It is the single JSON-in/
# JSON-out C ABI over `mvm_agentd::host_{audit,time,cost}`, so every language
# SDK is a thin shim over this one object.
#
# Built for the workload rootfs's libc (the nixpkgs Linux platform = glibc,
# matching `mvm-guest-agent`), not the static-musl builder-VM target — a
# `cdylib` needs a dynamic loader, which the glibc rootfs provides.
#
# Built from `mvm-host-services`, not `mvm-sdk`. The FFI used to live in the
# SDK crate, so this derivation compiled that crate's host-side decorator
# toolchain — five tree-sitter C parsers, blake3's NEON path and, until it was
# made optional, rustls/ring/tokio — into the object loaded inside every guest.
# `mvm-host-services` depends only on `mvm-agentd`, `mvm-core` and serde, so
# its closure is pure Rust by construction.

{
  pkgs,
  lib,
  mvmSrc,
  # Which libc the cdylib is built against. A guest can only `dlopen` the
  # variant matching its own: musl's loader fails resolving glibc-only symbols
  # such as `_dl_find_object`, and one process cannot use two libcs. The host
  # records each image's libc in its `mvm-meta.json` sidecar and selects.
  libc ? "glibc",
}:

assert lib.assertOneOf "libc" libc [ "glibc" "musl" ];

let
  isMusl = libc == "musl";

  # Same-arch musl triple. The cdylib is built for the guest that will load it,
  # and every backend runs a same-arch guest.
  muslTarget =
    if pkgs.stdenv.hostPlatform.isAarch64 then
      "aarch64-unknown-linux-musl"
    else if pkgs.stdenv.hostPlatform.isx86_64 then
      "x86_64-unknown-linux-musl"
    else
      throw "no musl target for this host platform";

  # Native cargo plus a rustc sysroot carrying the musl std — the mechanism
  # `embedded-rust-toolchain.nix` exists for. `pkgsMusl.rustPlatform` would
  # instead rebuild the toolchain itself against musl, which this crate does
  # not need: its closure is pure Rust, so nothing here compiles C.
  muslToolchain = pkgs.callPackage ./embedded-rust-toolchain.nix {
    cargo = pkgs.rust_1_91.packages.prebuilt.cargo;
    rustc = pkgs.rust_1_91.packages.prebuilt.rustc;
    target = muslTarget;
  };

  # The linker driver, and the thing that actually decides the output's libc.
  # Naming a `*-linux-musl` target is NOT sufficient: with `crt-static` off the
  # default driver is the host `cc`, which links against the host's glibc and
  # produces a glibc object that builds clean and fails inside an Alpine guest.
  # Only `pkgsMusl`'s cc wrapper is borrowed here, which comes from the binary
  # cache; no package set is rebuilt against musl.
  # `/bin/gcc` specifically: the wrapper does not reliably provide a `cc`
  # alias, and a linker path that does not exist fails loudly, whereas an
  # unset linker fails silently by falling back to the host cc.
  muslLinker = "${pkgs.pkgsMusl.stdenv.cc}/bin/gcc";
in

pkgs.rustPlatform.buildRustPackage ({
  pname = "mvm-sdk-cdylib" + lib.optionalString isMusl "-musl";
  version = "0.18.0";

  src = mvmSrc;

  cargoDeps = import ../lib/static-crates-cargo-deps.nix {
    inherit pkgs;
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Stage 0 runs Nix without its inner sandbox. Keep Cargo from creating
  # Nix's sentinel builder home and making the following derivation fail its
  # purity check.
  HOME = "/tmp";

  # Build only the library target, which produces both the Rust `lib` and the
  # `cdylib`.
  cargoBuildFlags = [
    "--package"
    "mvm-host-services"
    "--lib"
  ];

  # Tests run in the workspace's host-side `cargo test` lane.
  doCheck = false;

  # Cargo emits `libmvm_host_services.so` directly — the package name is the
  # stable FFI filename the SDK bindings and the runtime overlay key on. This
  # used to rename `libmvm_sdk*.so` into place, which meant that filename was
  # established by an install line rather than by the build.
  postInstall = ''
    mkdir -p $out/lib
    if [ ! -e $out/lib/libmvm_host_services.so ]; then
      find target -name 'libmvm_host_services*.so' -print \
        -exec install -m0644 {} $out/lib/libmvm_host_services.so \;
    fi

    # Assert the artifact is the libc it claims to be, by its NEEDED soname:
    # musl's is `libc.so`, glibc's is `libc.so.6`. This is not belt-and-braces.
    # A `*-linux-musl` build with the wrong linker driver produces a glibc
    # object, exports the right symbols, and reports success — the failure only
    # appears later as a relocation error inside a guest. Refuse to publish a
    # mislabelled object instead.
    needed="$(${pkgs.binutils}/bin/readelf -d $out/lib/libmvm_host_services.so \
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
    description = "mvm in-guest host-services FFI (${libc}) — one JSON-in/JSON-out C ABI over the broker clients, loaded by every language SDK";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
} // lib.optionalAttrs isMusl {
  # Cross-compile to musl with a native toolchain. `-crt-static` off because a
  # cdylib needs a dynamic loader; the guest supplies musl's.
  nativeBuildInputs = [ muslToolchain ];
  CARGO_BUILD_TARGET = muslTarget;
  # The linker goes in RUSTFLAGS rather than `CARGO_TARGET_<TRIPLE>_LINKER`.
  # Both are documented, but only this one was verified end to end to produce
  # a musl object here; the env-var form left the default host `cc` in place
  # and silently yielded glibc, which the NEEDED assertion below caught.
  RUSTFLAGS = "-C target-feature=-crt-static -C linker=${muslLinker}";
})
