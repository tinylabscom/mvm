# `mvm-net-agent` — the in-guest L3 tunnel agent.
#
# Built from `crates/mvm-agentd` in the workspace. Creates the point-to-point
# `mvm0` TUN interface, applies the addressing the host assigns over vsock,
# drops every capability it no longer needs, and then moves one IP packet per
# framed vsock message in each direction.
#
# `/init` starts it only when the host sets `mvm.l3=1` on the kernel cmdline,
# which it does only for a boot whose signed plan selected the l3-vsock mode.
# Baked unconditionally because it is inert otherwise — the same posture as
# mvm-egress-client and mvm-exit-report.
#
# No `addons` feature: the agent is synchronous throughout (raw netlink and
# ioctls, a poll loop, no tokio), so it does not pull the async stack the
# loopback helpers need and the sealed agent's default build stays
# tokio-free.

{ pkgs
, lib
, mvmSrc
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-net-agent";
  version = "0.14.0";

  src = mvmSrc;

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Restrict the build to this one binary; the workspace's heavier members are
  # not in its closure, so the artifact stays small.
  cargoBuildFlags = [
    "--package" "mvm-agentd"
    "--bin" "mvm-net-agent"
  ];

  cargoTestFlags = [
    "--package" "mvm-agentd"
  ];

  # Host-side `cargo test` lane runs the tests; the Nix build stays focused on
  # the cross-compiled rootfs binary.
  doCheck = false;

  meta = with lib; {
    description =
      "mvm in-guest L3 tunnel agent — mvm0 TUN framed over vsock to the host gateway";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
