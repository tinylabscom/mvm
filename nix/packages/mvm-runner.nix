# `mvm-runner` — the function-workload entrypoint runner, a `[[bin]]` of
# `mvm-agentd` linked static-musl for the runtime overlay.
#
# Vendoring goes through the caller's (non-static) `pkgs`, like the other
# static guest recipes, so the crate fetches are shared with them.

{
  pkgs,
  lib,
  mvmSrc,
  version,
}:

pkgs.pkgsStatic.rustPlatform.buildRustPackage {
  pname = "mvm-runner";
  inherit version;
  src = mvmSrc;
  cargoDeps = import ../lib/static-crates-cargo-deps.nix {
    inherit pkgs;
    lockFile = mvmSrc + "/Cargo.lock";
  };
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-runner"
  ];
  doCheck = false;
  meta = {
    description = "mvm function-workload entrypoint runner";
    mainProgram = "mvm-runner";
    platforms = lib.platforms.linux;
  };
}
