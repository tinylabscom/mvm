{
  description = "OpenClaw microVM template for mvm";

  inputs = {
    mvm.url = "path:../../";
    # Unstable required — pnpm_10.fetchDeps is only in nixpkgs-unstable.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);

      # Build the gateway locally instead of using the nix-openclaw overlay,
      # which bundles ML tools (whisper/torch/triton) that fail on aarch64.
      openclawFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.callPackage ./pkgs/openclaw.nix {};

      # Helper: build a guest image for a given OpenClaw role.
      #
      # Uses mkGuest (busybox init, no systemd) for fast boot and small
      # images.  The preStart script creates the tmpfs workspace, merges
      # config, and links persistent storage.  The openclaw user and
      # privilege drop are handled by mkGuest's users/user fields.
      mkRole = system: { role, tmpfsSizeMib ? 1024 }:
        let
          pkgs = import nixpkgs { inherit system; };
          openclaw = openclawFor system;
          serviceName = "openclaw-${role}";

          # Boot-time setup: runs as root before the service starts.
          setupScript = pkgs.writeShellScript "openclaw-setup" ''
            set -eu

            # Scratch workspace (tmpfs — ephemeral, fast).
            # The /var/lib/openclaw mount point is created by the init's
            # user setup (home dir for the openclaw user).
            mount -t tmpfs -o "mode=0755,size=${toString tmpfsSizeMib}m" tmpfs /var/lib/openclaw
            chown openclaw:openclaw /var/lib/openclaw

            # Runtime directories on tmpfs.
            install -d -o openclaw -g openclaw /var/lib/openclaw/config
            install -d -o openclaw -g openclaw /var/lib/openclaw/.state
            install -d -o openclaw -g openclaw /var/lib/openclaw/logs

            # Copy read-only config to a writable location so OpenClaw can
            # update settings at runtime (enable skills, change models, etc.).
            if [ -f /mnt/config/openclaw.json ]; then
              install -o openclaw -g openclaw -m 0644 \
                /mnt/config/openclaw.json /var/lib/openclaw/config/openclaw.json
            else
              # No config provided — write a minimal default so the service
              # can start in local mode without requiring setup.
              cat > /var/lib/openclaw/config/openclaw.json << 'DEFAULTCFG'
            {"gateway":{"mode":"local","port":3000},"version":"1"}
            DEFAULTCFG
              chown openclaw:openclaw /var/lib/openclaw/config/openclaw.json
            fi

            # Persistent storage on the data drive (survives reboots).
            if mountpoint -q /mnt/data 2>/dev/null; then
              install -d -o openclaw -g openclaw /mnt/data/openclaw/skills
              install -d -o openclaw -g openclaw /mnt/data/openclaw/workspace
              install -d -o openclaw -g openclaw /mnt/data/openclaw/sessions

              ln -sfn /mnt/data/openclaw/skills /var/lib/openclaw/skills
              ln -sfn /mnt/data/openclaw/workspace /var/lib/openclaw/workspace
              ln -sfn /mnt/data/openclaw/sessions /var/lib/openclaw/sessions
            else
              # No data drive — use tmpfs (ephemeral, lost on reboot).
              install -d -o openclaw -g openclaw /var/lib/openclaw/skills
              install -d -o openclaw -g openclaw /var/lib/openclaw/workspace
              install -d -o openclaw -g openclaw /var/lib/openclaw/sessions
            fi
          '';

          # Main service command: source env, set defaults, exec openclaw.
          # Runs as the openclaw user (mkGuest's user field handles su).
          commandScript = pkgs.writeShellScript "${serviceName}-start" ''
            set -eu

            # Source optional environment overrides.
            [ -f /mnt/config/openclaw.env ] && . /mnt/config/openclaw.env
            [ -f /mnt/secrets/openclaw-secrets.env ] && . /mnt/secrets/openclaw-secrets.env

            # Set defaults (env files may override these).
            : "''${OPENCLAW_CONFIG_PATH:=/var/lib/openclaw/config/openclaw.json}"
            : "''${OPENCLAW_HOME:=/var/lib/openclaw}"
            : "''${OPENCLAW_STATE_DIR:=/var/lib/openclaw/.state}"
            export OPENCLAW_CONFIG_PATH OPENCLAW_HOME OPENCLAW_STATE_DIR

            cd /var/lib/openclaw
            exec ${openclaw}/bin/openclaw ${role} --allow-unconfigured
          '';
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
            healthCmd = "pgrep -f 'openclaw ${role}' >/dev/null";
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
