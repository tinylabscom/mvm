# NixOS module: mvm guest agent systemd service.
#
# Runs the mvm-guest-agent inside the microVM, providing host-to-guest
# communication via Firecracker vsock (port 52). Handles Ping, WorkerStatus,
# SleepPrep, Wake, and integration lifecycle requests.
#
# Usage from a flake:
#   nixpkgs.lib.nixosSystem {
#     specialArgs = { inherit mvm-guest-agent; };
#     modules = [ ../../nix/modules/guest-agent.nix ./guests/baseline.nix ];
#   };
#
# The package must be built separately and passed via specialArgs:
#   mvm-guest-agent = import ../../nix/modules/guest-agent-pkg.nix {
#     inherit pkgs;
#     mvmSrc = ../../.;
#   };

{ mvm-guest-agent, ... }:

{
  # Ensure the integration drop-in directory exists so the agent can scan it.
  systemd.tmpfiles.rules = [
    "d /etc/mvm/integrations.d 0755 root root -"
  ];

  systemd.services.mvm-guest-agent = {
    description = "MVM Guest Agent";
    after = [ "basic.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${mvm-guest-agent}/bin/mvm-guest-agent";
      Restart = "on-failure";
      RestartSec = "2s";
    };
  };
}
