# OpenClaw gateway — single-service microVM role.
#
# OpenClaw is a self-hosted MCP gateway for Claude AI (Node.js).
# There is one daemon: `openclaw gateway`.  Per-tenant configuration
# is injected at runtime by mvm via config and secrets drives:
#
#   /mnt/config/  (read-only)
#     - config.json      — mvm instance metadata
#     - openclaw.json    — OpenClaw gateway config (port, auth, models)
#     - openclaw.env     — environment overrides
#
#   /mnt/secrets/ (read-only, ephemeral)
#     - secrets.json     — mvm tenant secrets
#     - openclaw-secrets.env — API keys (ANTHROPIC_API_KEY, etc.)
#
#   /mnt/data/   (read-write, persistent — optional)
#     - Persistent OpenClaw state: skills, memory, session history.
#       Present when pool spec has data_disk_mib > 0.
#
# Directory layout at runtime:
#   /var/lib/openclaw/           tmpfs workspace (scratch, logs, runtime)
#   /var/lib/openclaw/config/    writable copy of config (merged at boot)
#   /var/lib/openclaw/.state/    runtime state dir
#   /mnt/data/openclaw/          persistent storage (skills, memory, sessions)

{ pkgs, openclaw, ... }:
{
  imports = [ ../../nix/modules/guest-integrations.nix ];

  networking.hostName = "openclaw";
  networking.firewall.enable = false;

  # Health monitoring via mvm guest agent.
  services.mvm-integrations = {
    enable = true;
    integrations.openclaw-gateway = {
      healthCmd = "${pkgs.systemd}/bin/systemctl is-active openclaw-gateway.service";
      healthIntervalSecs = 10;
      healthTimeoutSecs = 5;
    };
  };

  users.groups.openclaw = { };
  users.users.openclaw = {
    isSystemUser = true;
    group = "openclaw";
    home = "/var/lib/openclaw";
    createHome = true;
  };

  # Scratch workspace (tmpfs — ephemeral, fast).
  fileSystems."/var/lib/openclaw" = {
    fsType = "tmpfs";
    device = "tmpfs";
    options = [ "mode=0755" "size=1024m" ];
  };

  # --- Boot-time setup: merge config + link persistent storage ---
  systemd.services.openclaw-init = {
    description = "Prepare OpenClaw directories and config";
    before = [ "openclaw-gateway.service" ];
    requiredBy = [ "openclaw-gateway.service" ];
    after = [ "mnt-config.mount" "mnt-secrets.mount" "mnt-data.mount" ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "openclaw";
      Group = "openclaw";
    };

    script = ''
      set -eu

      # Runtime directories on tmpfs.
      mkdir -p /var/lib/openclaw/{config,.state,logs}

      # Copy read-only config to a writable location so OpenClaw can
      # update settings at runtime (enable skills, change models, etc.).
      if [ -f /mnt/config/openclaw.json ]; then
        cp /mnt/config/openclaw.json /var/lib/openclaw/config/openclaw.json
      fi

      # Persistent storage on the data drive (survives reboots).
      # If /mnt/data is mounted, create and symlink persistent dirs.
      if mountpoint -q /mnt/data 2>/dev/null; then
        mkdir -p /mnt/data/openclaw/{skills,workspace,sessions}

        # Skills persist across reboots so they don't need re-installing.
        ln -sfn /mnt/data/openclaw/skills /var/lib/openclaw/skills

        # Workspace holds SOUL.md, USER.md, MEMORY.md — agent identity.
        ln -sfn /mnt/data/openclaw/workspace /var/lib/openclaw/workspace

        # Session history for continuity.
        ln -sfn /mnt/data/openclaw/sessions /var/lib/openclaw/sessions
      else
        # No data drive — use tmpfs (ephemeral, lost on reboot).
        mkdir -p /var/lib/openclaw/{skills,workspace,sessions}
      fi
    '';
  };

  systemd.services.openclaw-gateway = {
    description = "OpenClaw Gateway";
    after = [ "network-online.target" "openclaw-init.service" ];
    wants = [ "network-online.target" ];
    requires = [ "openclaw-init.service" ];
    wantedBy = [ "multi-user.target" ];

    startLimitBurst = 3;
    startLimitIntervalSec = 30;

    serviceConfig = {
      Type = "simple";
      User = "openclaw";
      Group = "openclaw";
      Restart = "on-failure";
      RestartSec = "2s";
      WorkingDirectory = "/var/lib/openclaw";
      TimeoutStopSec = "30s";
      KillMode = "mixed";

      ExecStartPre = [
        "${pkgs.coreutils}/bin/test -f /mnt/config/config.json"
        "${pkgs.coreutils}/bin/test -f /mnt/secrets/secrets.json"
      ];

      EnvironmentFile = [
        "-/mnt/config/openclaw.env"
        "-/mnt/secrets/openclaw-secrets.env"
      ];

      ExecStart = pkgs.writeShellScript "openclaw-start" ''
        set -eu
        # Writable config copy (merged by openclaw-init).
        export OPENCLAW_CONFIG_PATH="''${OPENCLAW_CONFIG_PATH:-/var/lib/openclaw/config/openclaw.json}"
        export OPENCLAW_HOME="''${OPENCLAW_HOME:-/var/lib/openclaw}"
        export OPENCLAW_STATE_DIR="''${OPENCLAW_STATE_DIR:-/var/lib/openclaw/.state}"
        exec ${openclaw}/bin/openclaw gateway
      '';

      # Hardening
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/openclaw" "/mnt/data" ];
      MemoryMax = "2G";
      TasksMax = 1024;
    };
  };
}
