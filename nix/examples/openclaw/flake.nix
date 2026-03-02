{
  description = "OpenClaw microVM template for mvm";

  inputs = {
    mvm.url = "path:../../";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);

      # Wrap the pre-installed OpenClaw package. The pre-build.sh hook
      # installs OpenClaw via the official installer script before nix build
      # runs, placing it at /opt/openclaw. This derivation wraps those files.
      openclawFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.callPackage ./pkgs/openclaw.nix {};

      # Build a guest image for a given OpenClaw role.
      #
      # Uses mkGuest (busybox init, no systemd) for fast boot and small
      # images.  Shell scripts live in ./scripts/ and get variable
      # substitution via pkgs.substituteAll at build time.
      mkRole = system: { role, tmpfsSizeMib ? 1024 }:
        let
          pkgs = import nixpkgs { inherit system; };
          openclaw = openclawFor system;
          serviceName = "openclaw-${role}";

          setupScript = pkgs.substituteAll {
            src = ./scripts/setup.sh;
            isExecutable = true;
            socat = "${pkgs.socat}";
            tmpfsSize = toString tmpfsSizeMib;
          };

          commandScript = pkgs.substituteAll {
            src = ./scripts/start.sh;
            isExecutable = true;
            openclaw = "${openclaw}";
            inherit role;
          };
        in
        mvm.lib.${system}.mkGuest {
          name = "openclaw";
          hostname = "openclaw";
          packages = [ openclaw ];

          users.openclaw = {
            home = "/var/lib/openclaw";
          };

          services.${serviceName} = {
            preStart = "${setupScript}";
            command = "${commandScript}";
            user = "openclaw";
          };

          healthChecks.${serviceName} = {
            healthCmd = "nc -z 127.0.0.1 3000";
            healthIntervalSecs = 10;
            healthTimeoutSecs = 5;
          };
        };
    in {
      packages = eachSystem (system: {
        # Gateway variant — lightweight MCP proxy, no persistent data disk.
        tenant-gateway = mkRole system { role = "gateway"; tmpfsSizeMib = 1024; };

        # Worker variant — agent execution, uses persistent data disk.
        tenant-worker = mkRole system { role = "worker"; tmpfsSizeMib = 2048; };

        # Default = gateway (backward compatible, lower resource requirement).
        default = mkRole system { role = "gateway"; tmpfsSizeMib = 1024; };
      });
    };
}
