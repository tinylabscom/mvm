# `mvm-guest-agent` — the production guest agent binary.
#
# The real Rust binary defined at
# `crates/mvm-agentd/src/bin/mvm-guest-agent.rs` (~2400 LOC of vsock
# RPC + worker-pool dispatch + integration manifest + system
# metrics). Side-bins `mvm-seccomp-apply` (the per-service seccomp
# shim) rides the
# same derivation since the rootfs needs them too.
#
# ## Build environment
#
# `rustPlatform.buildRustPackage` against the workspace at
# `mvmSrc`. The crate is built with `--package mvm-agentd --bins`
# so the workspace's heavier consumers (mvm-runtime,
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
# ## Runtime access
#
# The same binary serves every image tier. DevOnly requests are admitted by
# the guest agent's runtime profile and signed verb grant, after protocol
# authentication; image construction does not select a handler set.

{
  pkgs,
  lib,
  mvmSrc,
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-guest-agent";
  version = "0.14.0";

  src = mvmSrc;

  # Workspace's Cargo.lock is the source of truth for every crate
  # we vendor. `buildRustPackage` vendors the closure even though
  # we only build mvm-agentd; the unused deps compile zero code.
  cargoDeps = import ../lib/static-crates-cargo-deps.nix {
    inherit pkgs;
    lockFile = mvmSrc + "/Cargo.lock";
  };

  unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };

  # Restrict the build to the mvm-agentd binaries. The workspace
  # has heavier members (libkrun via mvm-build, libkrun via
  # mvm-providers, etc.) that aren't in the guest closure.
  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "mvm-guest-agent"
    "--bin"
    "mvm-seccomp-apply"
    # Guest-side network defense. Installs kernel blackhole routes
    # for `MANDATORY_DENY_RANGES` at boot from `/init` (uid 0) before
    # the main agent forks under setpriv.
    "--bin"
    "mvm-guest-netinit"
    # Runtime-lean OCI roots still need their entrypoint wrapper; PID 1 is
    # the universal initramfs agent, not a binary baked into the rootfs.
    "--bin"
    "mvm-oci-entrypoint"
  ];

  # Same selection for the `nix flake check`-equivalent test run.
  # mvm-agentd's tests are pure (vsock framing, integration manifest
  # parsing, seccomp filter golden tests) so they run inside the
  # sandbox without privilege.
  cargoTestFlags = [
    "--package"
    "mvm-agentd"
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
