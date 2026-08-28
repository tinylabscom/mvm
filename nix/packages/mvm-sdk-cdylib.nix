# `libmvm_host_services.so` — the in-guest host-services FFI shared object.
#
# Built from the `mvm-sdk` crate's `cdylib` output and renamed to the stable
# `libmvm_host_services.so` filename. Packaged in the SDK sidecar at
# `/mvm/sdk/lib/` and loaded via `ctypes` / `koffi` by the in-guest language
# SDKs (`mvm.audit.emit`, `mvm.host.time()`, ...). It is the single JSON-in/
# JSON-out C ABI over `mvm_agentd::host_{audit,time,cost}`, so every language
# SDK is a thin shim over this one object.
#
# Built for the workload rootfs's libc (the nixpkgs Linux platform = glibc,
# matching `mvm-guest-agent`), not the static-musl builder-VM target — a
# `cdylib` needs a dynamic loader, which the glibc rootfs provides.

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

  # Build only mvm-sdk's library target, which produces both the Rust `lib`
  # and the `cdylib`. The cdylib is renamed to the stable FFI filename below.
  cargoBuildFlags = [
    "--package"
    "mvm-sdk"
    "--lib"
  ];

  # Tests run in the workspace's host-side `cargo test` lane.
  doCheck = false;

  # Cargo emits the cdylib as `libmvm_sdk.so` because the package name is
  # `mvm-sdk`. The SDK bindings and the runtime overlay key on the stable
  # `libmvm_host_services.so` name, so rename it during install.
  postInstall = ''
    mkdir -p $out/lib
    if [ ! -e $out/lib/libmvm_host_services.so ]; then
      find target -name 'libmvm_sdk*.so' -print -exec install -m0644 {} $out/lib/libmvm_host_services.so \;
    fi
  '';

  meta = with lib; {
    description = "mvm in-guest host-services FFI — one JSON-in/JSON-out C ABI over the broker clients, loaded by every language SDK";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
