# `mvm-guest-agent` — the production guest agent binary.
#
# The real Rust binary defined at
# `crates/mvm-guest/src/bin/mvm-guest-agent.rs` (~2400 LOC of vsock
# RPC + worker-pool dispatch + integration manifest + system
# metrics). Side-bins `mvm-seccomp-apply` (the per-service seccomp
# shim) and `mvm-verity-init` (the verity-initrd PID 1) ride the
# same derivation since the rootfs needs them too.
#
# ## Build environment
#
# `rustPlatform.buildRustPackage` against the workspace at
# `mvmSrc`. The crate is built with `--package mvm-guest --bins`
# so the workspace's heavier consumers (mvm, mvm-backend,
# libkrun, etc.) don't enter the closure. Cargo still
# resolves and vendors the full workspace lockfile, but only the
# selected crate's deps compile.
#
# ## Cross-targeting
#
# The caller passes `pkgs` for the target system (e.g. on a macOS
# host with nix-darwin's linux-builder configured, the caller
# resolves `pkgs.pkgsCross.aarch64-multiplatform.pkgs` and hands
# it here). For native Linux + KVM the caller's own `pkgs` is
# already the right thing. The builder VM sets this up
# transparently — `nix build` inside the sandbox runs on Linux,
# so `pkgs` is Linux pkgs.
#
# ## Features
#
# `dev-shell` is opt-in. With it, the agent accepts the `Exec`
# vsock request and shells out arbitrary commands — required for
# `mvmctl exec`/`mvmctl console` against dev images. Without it
# (production), the `Exec` symbol is absent — the
# `prod-agent-no-exec` CI gate enforces this on the release lane.

{ pkgs
, lib
, mvmSrc
, withDevShell ? false
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-guest-agent";
  version = "0.14.0";

  src = mvmSrc;

  # Workspace's Cargo.lock is the source of truth for every crate
  # we vendor. `buildRustPackage` vendors the closure even though
  # we only build mvm-guest; the unused deps compile zero code.
  cargoLock.lockFile = mvmSrc + "/Cargo.lock";

  # Restrict the build to the mvm-guest binaries. The workspace
  # has heavier members (libkrun via mvm-build, libkrun via
  # mvm-providers, etc.) that aren't in the guest closure.
  cargoBuildFlags = [
    "--package" "mvm-guest"
    "--bin" "mvm-guest-agent"
    "--bin" "mvm-seccomp-apply"
    "--bin" "mvm-verity-init"
    # Guest-side network defense. Installs kernel blackhole routes
    # for `MANDATORY_DENY_RANGES` at boot from `/init` (uid 0) before
    # the main agent forks under setpriv.
    "--bin" "mvm-guest-netinit"
  ] ++ lib.optionals withDevShell [
    "--features" "mvm-guest/dev-shell"
  ];

  # Same selection for the `nix flake check`-equivalent test run.
  # mvm-guest's tests are pure (vsock framing, integration manifest
  # parsing, seccomp filter golden tests) so they run inside the
  # sandbox without privilege.
  cargoTestFlags = [
    "--package" "mvm-guest"
  ];

  # Skip tests by default — they need a Linux build host and the
  # builder VM already runs `nix build` (not `nix flake check`).
  # CI's dedicated test lane covers the Rust test suite directly.
  doCheck = false;

  meta = with lib; {
    description = "mvm guest agent — vsock RPC handler for microVM guests";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
