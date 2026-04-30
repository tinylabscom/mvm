# Build the workspace's `xtask` runner as its own package.
#
# `xtask` is a workspace member that hosts repo-level tasks (man-page
# generation, etc.). Promoting it to its own package lets users run
# `nix run github:auser/mvm#xtask -- <task>` without a checkout, and
# keeps it visible as a deliberate output rather than smuggled inside
# `mvm-guest-agent`'s source closure.
#
# The fileset still pulls the whole workspace because xtask is a
# Cargo workspace member: cargo needs `xtask/Cargo.toml`, the root
# `Cargo.toml`, and the shared `Cargo.lock` together to resolve the
# build. Carving xtask into a separate workspace would defeat the
# point of having a single root `Cargo.lock`.

{ pkgs, mvmSrc, rustPlatform ? pkgs.rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "xtask";
  version = "0.0.0";

  src = pkgs.lib.fileset.toSource {
    root = mvmSrc;
    fileset = pkgs.lib.fileset.unions [
      (mvmSrc + "/Cargo.toml")
      (mvmSrc + "/Cargo.lock")
      (mvmSrc + "/src")
      (mvmSrc + "/crates")
      (mvmSrc + "/xtask")
    ];
  };

  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  cargoBuildFlags = [ "-p" "xtask" "--bin" "xtask" ];
  doCheck = false;

  meta = {
    description = "mvm workspace task runner";
    mainProgram = "xtask";
  };
}
