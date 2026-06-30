# `mvm-egress-client` — production in-guest egress shim (ADR-100).
#
# Built from `crates/mvm-guest-helpers` in the workspace. A loopback SOCKS5 proxy
# that funnels the workload's egress to the host vsock egress gateway — the guest's
# only path off-VM under the vsock-only model (no NIC, no IP routing, no gateway).
# `/init` starts it and exports `ALL_PROXY=socks5h://127.0.0.1:<port>` when the boot
# env requests vsock egress; `socks5h` pushes DNS host-side (no guest resolver).
#
# Baked unconditionally (it is inert unless `/init` starts it), like mvm-exit-report.
# Always built without any dev-shell feature — it has no interactive surface.

{ pkgs
, lib
, mvmSrc
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-egress-client";
  version = "0.14.0";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # Restrict the build to the egress-client binary; the workspace's heavier members
  # are not in this crate's closure, so the artifact stays small.
  cargoBuildFlags = [
    "--package" "mvm-guest-helpers"
    "--bin" "mvm-egress-client"
  ];

  cargoTestFlags = [
    "--package" "mvm-guest-helpers"
  ];

  # Host-side `cargo test` lane runs the tests; the Nix build stays focused on the
  # cross-compiled rootfs binary.
  doCheck = false;

  meta = with lib; {
    description =
      "mvm in-guest egress shim — loopback SOCKS5 to the host vsock egress gateway (ADR-100)";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
