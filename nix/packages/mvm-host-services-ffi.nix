# `libmvm_host_services.so` — the in-guest host-services FFI shared object.
#
# Built from `crates/mvm-host-services-ffi` (crate-type `cdylib`). Baked into
# the runtime overlay at `/mvm/runtime/lib/` and loaded via `ctypes` / `koffi`
# by the in-guest language SDKs (`mvm.audit.emit`, `mvm.host.time()`, ...).
# It is the single JSON-in/JSON-out C ABI over `mvm_guest::host_{audit,time,
# cost}`, so every language SDK is a thin shim over this one object.
#
# Built for the workload rootfs's libc (the nixpkgs Linux platform = glibc,
# matching `mvm-guest-agent`), not the static-musl builder-VM target — a
# `cdylib` needs a dynamic loader, which the glibc rootfs provides.

{ pkgs
, lib
, mvmSrc
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-host-services-ffi";
  version = "0.16.1";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # Only the cdylib crate; the workspace's heavier members are not in its
  # closure, so the artifact stays small.
  cargoBuildFlags = [
    "--package" "mvm-host-services-ffi"
    "--lib"
  ];

  # Tests run in the workspace's host-side `cargo test` lane.
  doCheck = false;

  # `buildRustPackage` installs the cdylib to `$out/lib`; pin the canonical
  # name so the overlay bake and the SDK loaders can both reference
  # `$out/lib/libmvm_host_services.so` unconditionally.
  postInstall = ''
    mkdir -p $out/lib
    if [ ! -e $out/lib/libmvm_host_services.so ]; then
      find target -name 'libmvm_host_services.so' -print -exec install -m0644 {} $out/lib/ \;
    fi
  '';

  meta = with lib; {
    description =
      "mvm in-guest host-services FFI — one JSON-in/JSON-out C ABI over the broker clients, loaded by every language SDK";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
