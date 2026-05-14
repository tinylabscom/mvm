# `mvm-builder-init` — tiny in-guest init for the libkrun builder VM.
#
# Plan 71 W3 ships the crate skeleton at
# `crates/mvm-builder-init/`. The binary is Linux-only — on
# non-Linux targets it builds to a stub that exits 1 — so this
# derivation only makes sense on a Linux pkgs.
#
# ## Where it lives in the rootfs
#
# `mkGuest` installs the resulting `mvm-builder-init` binary into
# `/usr/local/bin/`; the builder VM image flake then symlinks
# `/sbin/mvm-builder-init -> /usr/local/bin/mvm-builder-init` so the
# kernel's `init=/sbin/mvm-builder-init` arg resolves. The kernel
# cmdline is centralized in
# `mvm_build::libkrun_builder::builder_kernel_cmdline()`.
#
# ## Cross-targeting
#
# Same approach as `mvm-guest-agent.nix`: caller passes `pkgs` for
# the target system. The builder VM image flake at
# `nix/images/builder-vm/flake.nix` calls this with each system's
# pkgs in turn so we get aarch64-linux + x86_64-linux artifacts.

{ pkgs
, lib
, mvmSrc
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-builder-init";
  version = "0.14.0";

  src = mvmSrc;

  # Workspace lockfile, same vendoring story as mvm-guest-agent.
  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # Restrict the build to just this crate. The workspace has heavier
  # members (mvm-build pulls microsandbox, etc.) that don't belong
  # in the builder-init closure.
  cargoBuildFlags = [
    "--package" "mvm-builder-init"
    "--bin" "mvm-builder-init"
  ];

  cargoTestFlags = [
    "--package" "mvm-builder-init"
  ];

  # Tests are pure (result-file format, cmdline parser) so they
  # would run, but the builder VM image build path doesn't need
  # them re-run inside the sandbox. CI's workspace test lane covers
  # them.
  doCheck = false;

  meta = with lib; {
    description = "mvm libkrun builder-VM init — Plan 71 W3";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
