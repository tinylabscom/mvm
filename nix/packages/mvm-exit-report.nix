# `mvm-exit-report` — production in-guest exit-report binary.
#
# Built from `crates/mvm-agentd` in the workspace. Baked
# unconditionally into every guest rootfs (prod and dev) so the guest
# can record its exit status before poweroff regardless of whether
# interactive features are compiled in.
#
# Always built without any interactive-style feature flag — the exit
# reporter has no `do_exec`-equivalent surface and the same artifact
# is safe for dev and prod images.

{
  pkgs,
  lib,
  mvmSrc,
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-exit-report";
  version = "0.14.0";

  src = mvmSrc;

  cargoDeps = import ../lib/static-crates-cargo-deps.nix {
    inherit pkgs;
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Restrict the build to the exit-report binary. The workspace's
  # heavier members (mvm-libkrun, mvm-providers, etc.) are not in the
  # closure of this crate, so the produced artifact stays small.
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-exit-report"
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
    description = "mvm in-guest exit reporter — records workload exit status before poweroff";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
