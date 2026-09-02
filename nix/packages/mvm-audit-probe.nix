# `mvm-audit-probe` — in-guest host.audit.v1 driver, test fixture only.
#
# The real Rust binary at `crates/mvm-agentd/src/bin/audit-probe.rs`. It calls
# `mvm_agentd::host_audit::emit` from inside a booted guest so an audit entry
# travels the full spine (guest → backend vsock splice → per-VM mvm-broker →
# mvm-audit-signer → the per-VM workload chain). It is the in-guest half of the
# live-VM round-trip proof.
#
# NOT a production binary: only the opt-in `withAuditProbe` mkGuest flag bakes
# it (into a dedicated fixture image), and `mvm-guest-agent.nix` never selects
# it, so the production guest closure stays free of it.
#
# Same build shape as `mvm-guest-agent.nix`: `buildRustPackage` against the
# workspace, restricted to the single bin so the workspace's heavier members
# don't enter the closure.

{
  pkgs,
  lib,
  mvmSrc,
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-audit-probe";
  version = "0.14.0";

  src = mvmSrc;

  cargoDeps = import ../lib/static-crates-cargo-deps.nix {
    inherit pkgs;
    lockFile = mvmSrc + "/Cargo.lock";
  };

  cargoBuildFlags = [
    "--package"
    "mvm-agentd"
    "--bin"
    "audit-probe"
  ];

  cargoTestFlags = [
    "--package"
    "mvm-agentd"
  ];

  # Tests run in the workspace's host-side `cargo test` lane (the probe's
  # build_record unit test runs there under target_os = "linux"); the Nix
  # path stays focused on producing the cross-compiled binary.
  doCheck = false;

  meta = with lib; {
    description = "mvm in-guest host.audit.v1 probe — live-VM audit round-trip fixture";
    homepage = "https://github.com/tinylabscom/mvm";
    license = licenses.asl20;
    platforms = platforms.linux;
  };
}
