# OpenClaw worker — agent execution service.
#
# Workers run long-lived agent sessions, tool invocations, and MCP
# interactions.  They use the persistent data disk (/mnt/data) for
# state that survives reboots: skills, workspace identity, and
# session history.
#
# Runtime config injected by mvm:
#   /mnt/config/config.json        — instance metadata
#   /mnt/config/openclaw.json      — worker config
#   /mnt/config/openclaw.env       — environment overrides
#   /mnt/secrets/secrets.json      — tenant secrets
#   /mnt/secrets/openclaw-secrets.env — API keys (ANTHROPIC_API_KEY, etc.)
#   /mnt/data/openclaw/            — persistent storage (skills, workspace, sessions)

{ pkgs, openclaw, ... }:

{
  imports = [
    (import ./common.nix { serviceName = "openclaw-worker"; tmpfsSizeMib = 2048; })
  ];

  services.mvm-integrations = {
    enable = true;
    integrations.openclaw-worker = {
      healthCmd = "${pkgs.systemd}/bin/systemctl is-active openclaw-worker.service";
      healthIntervalSecs = 10;
      healthTimeoutSecs = 5;
    };
  };

  systemd.services.openclaw-worker = {
    description = "OpenClaw Worker";
    after = [ "systemd-networkd.service" "openclaw-init.service" ];
    wants = [ "systemd-networkd.service" ];
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

      ExecStart = pkgs.writeShellScript "openclaw-worker-start" ''
        set -eu
        export OPENCLAW_CONFIG_PATH="''${OPENCLAW_CONFIG_PATH:-/var/lib/openclaw/config/openclaw.json}"
        export OPENCLAW_HOME="''${OPENCLAW_HOME:-/var/lib/openclaw}"
        export OPENCLAW_STATE_DIR="''${OPENCLAW_STATE_DIR:-/var/lib/openclaw/.state}"
        exec ${openclaw}/bin/openclaw worker --allow-unconfigured
      '';

      # Hardening — higher limits than gateway for compute workloads.
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = "read-only";
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/openclaw" "/mnt/data" ];
      MemoryMax = "4G";
      TasksMax = 2048;
    };
  };
}
