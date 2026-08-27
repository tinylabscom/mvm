# `mvm-addon-dns` — production in-guest addon DNS resolver binary.
#
# Built from `crates/mvm-agentd` in the workspace. Baked into the
# rootfs alongside `mvm-guest-agent` so every guest carries the binary;
# `/init` only activates it when a zone file is present (see
# `nix/lib/mk-guest.nix::initScript`).
#
# Always built without any interactive-style feature flag — the DNS
# binary has no `do_exec`-equivalent surface and the same artifact is
# safe for dev and prod images.
#
# Requires the `addons` feature: this bin (along with mvm-egress-client
# and mvm-addon-vsock-bridge) is the only mvm-agentd consumer of tokio,
# so the crate keeps it behind that feature to hold the sealed agent's
# default build tokio-free.

{
  pkgs,
  lib,
  mvmSrc,
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-addon-dns";
  version = "0.14.0";

  src = mvmSrc;

  cargoLock = import ../lib/static-crates-cargo-lock.nix {
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Restrict the build to the addon DNS binary. The workspace's
  # heavier members (mvm-libkrun, mvm-providers, etc.) are not in the
  # closure of this crate, so the produced artifact stays small.
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-addon-dns"
    "--features"
    "mvm-agentd/addons"
  ];

  cargoTestFlags = [
    "--package"
    "mvm-agentd"
  ];

  # Tests run in the workspace's host-side `cargo test` lane; the Nix
  # build path stays focused on producing the cross-compiled binary
  # for the rootfs.
  doCheck = false;

  meta = with lib; {
    description = "mvm in-guest addon DNS — loopback-only UDP resolver for configured local-addon hostnames";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
