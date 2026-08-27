# Static `mvm-guest-agent` binary for the universal initramfs.
#
# This derivation builds only the `mvm-guest-agent` binary from the
# `mvm-agentd` crate, linked statically against musl so it can serve as
# `/init` (PID 1) in a minimal initramfs with no dynamic loader, no glibc,
# and no runtime overlay available at early boot.
#
# The binary is stripped and built with LTO to keep the initramfs small.

{
  pkgs,
  lib,
  mvmSrc,
}:

let
  # Use the static-musl package set for the target architecture.  The caller
  # is expected to pass the target-system `pkgs` (e.g. from the flake's
  # `forAllSystems`), so `pkgsStatic` gives us a same-arch musl toolchain.
  staticPkgs = pkgs.pkgsStatic;
in
staticPkgs.rustPlatform.buildRustPackage {
  pname = "mvm-guest-agent-static";
  version = "0.18.0";

  src = mvmSrc;

  cargoLock = import ../lib/static-crates-cargo-lock.nix {
    lockFile = mvmSrc + "/Cargo.lock";
  };

  # Build only the guest-agent binary; the initramfs does not need the
  # seccomp shim, verity-init, netinit, or runner.
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-guest-agent"
  ];

  cargoTestFlags = [
    "--package"
    "mvm-agentd"
  ];

  doCheck = false;

  env = {
    # Static linking against musl.  `pkgsStatic` already sets the musl target,
    # but explicitly requesting a static CRT ensures we do not accidentally
    # produce a position-independent or dynamically-linked binary.
    RUSTFLAGS = "-C target-feature=+crt-static";

    # Size-focused release profile.  These mirror the release-profile tuning
    # in the workspace Cargo.toml and keep the initramfs under the 5–10 MiB
    # budget.
    CARGO_PROFILE_RELEASE_LTO = "thin";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
    CARGO_PROFILE_RELEASE_STRIP = "symbols";
    CARGO_PROFILE_RELEASE_PANIC = "abort";
  };

  meta = with lib; {
    description = "static mvm guest agent for the universal initramfs";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
