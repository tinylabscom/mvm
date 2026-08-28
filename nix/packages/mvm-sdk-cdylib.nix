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
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-sdk-cdylib";
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
  '';

  meta = with lib; {
    description = "mvm in-guest host-services FFI — one JSON-in/JSON-out C ABI over the broker clients, loaded by every language SDK";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
