# `mvm-addon-dns` — production in-guest addon DNS resolver binary.
#
# Built from `crates/mvm-addon-dns` in the workspace. Baked into the
# rootfs alongside `mvm-guest-agent` so every guest carries the binary;
# `/init` only activates it when a zone file is present (see
# `nix/lib/mk-guest.nix::initScript`).
#
# Always built without any dev-shell-style feature flag — the DNS
# binary has no `do_exec`-equivalent surface and the same artifact is
# safe for dev and prod images.

{ pkgs
, lib
, mvmSrc
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-addon-dns";
  version = "0.14.0";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # Restrict the build to the addon DNS binary. The workspace's
  # heavier members (mvm-libkrun, mvm-providers, etc.) are not in the
  # closure of this crate, so the produced artifact stays small.
  cargoBuildFlags = [
    "--package" "mvm-guest-helpers"
    "--bin" "mvm-addon-dns"
  ];

  cargoTestFlags = [
    "--package" "mvm-guest-helpers"
  ];

  # Tests run in the workspace's host-side `cargo test` lane; the Nix
  # build path stays focused on producing the cross-compiled binary
  # for the rootfs.
  doCheck = false;

  meta = with lib; {
    description =
      "mvm in-guest addon DNS — loopback-only UDP resolver for configured local-addon hostnames";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
