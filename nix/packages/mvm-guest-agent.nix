# Build the mvm-guest-agent binary from the workspace.
#
# Usage from `nix/flake.nix` (alongside this file):
#   mvm-guest-agent = import ./guest-agent-pkg.nix {
#     inherit pkgs rustPlatform;
#     mvmSrc   = ./..;
#     devShell = false; # default — production: no Exec handler compiled in
#   };
#
# `devShell = true` enables the `dev-shell` Cargo feature which compiles
# in the vsock Exec handler used by `mvmctl exec` and `mvmctl console`.
# Default is `false` so production rootfs builds are physically incapable
# of executing arbitrary commands over vsock.

{ pkgs, mvmSrc, rustPlatform ? pkgs.rustPlatform, devShell ? false }:

rustPlatform.buildRustPackage {
  pname = "mvm-guest-agent";
  version = "0.3.0";

  # Only include Rust source to avoid rebuilds when docs/specs change.
  # Use path concatenation (+) not string interpolation — fileset requires paths, not strings.
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
  # `dev-shell` enables the Exec handler. Production builds omit this feature
  # entirely, so the handler is not compiled into the binary at all.
  #
  # We also build `mvm-seccomp-apply` here — the per-service seccomp shim
  # used by the init's `mkServiceBlock`. It ships in the same store path
  # as the guest agent so `mkServiceBlock` can reference it via
  # `${guestAgentPkg}/bin/mvm-seccomp-apply` without a separate package.
  #
  # `mvm-verity-init` is NOT built here because it has to run from the
  # initramfs (no glibc available); it's built statically by
  # `nix/packages/mvm-verity-init.nix` against musl. Building it both
  # ways would just be busywork — the agent + seccomp-apply run after
  # the rootfs is mounted and can keep dynamic linking against glibc.
  cargoBuildFlags =
    [ "-p" "mvm-guest" "--bin" "mvm-guest-agent" "--bin" "mvm-seccomp-apply" ]
    ++ pkgs.lib.optionals devShell [ "--features" "dev-shell" ];
  doCheck = false;

  # Surface the dev-shell feature flag on the derivation so `mkGuest` can
  # assert at build time that the rootfs `variant` tag matches the agent's
  # compiled features (prod rootfs ↔ no Exec handler, dev rootfs ↔ Exec
  # handler). See ADR-002 §W4.3 + the W7 plan.
  passthru.devShell = devShell;
}
