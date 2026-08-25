{
  description = "mvm microVM — background worker preset";

  inputs = {
    mvm.url = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-worker-vm";

        packages = [ pkgs.bash pkgs.coreutils ];

        # PID 1. The services below are declarations for the supervisor;
        # until it lands, the primary one runs here as the entrypoint.
        entrypoint.command = [
          "/bin/sh"
          "-c"
          "mkdir -p /run/worker; exec ${pkgs.bash}/bin/bash -c 'while true; do echo \"[worker] tick $(date)\"; touch /run/worker/healthy; sleep 10; done'"
        ];

        # Long-running worker loop.  Replace the script body with your workload.
        services.worker = {
          preStart = "mkdir -p /run/worker";
          command = "${pkgs.bash}/bin/bash -c 'while true; do echo \"[worker] tick $(date)\"; sleep 10; done'";
        };

        # Health check: confirm the service process is alive by checking its
        # pidfile or a sentinel file written by the worker script.
        healthChecks.worker = {
          # Write /run/worker/healthy from your script to signal readiness.
          healthCmd = "${pkgs.bash}/bin/bash -c 'test -f /run/worker/healthy'";
          healthIntervalSecs = 10;
          healthTimeoutSecs = 5;
        };
      };
    };
}
