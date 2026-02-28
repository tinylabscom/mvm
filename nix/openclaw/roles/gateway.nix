# OpenClaw gateway — MCP gateway service for Claude AI.
#
# Lightweight proxy that routes MCP tool calls to the appropriate
# backend.  No persistent data disk needed; state lives in the
# upstream services the gateway connects to.
#
# Runtime config injected by mvm:
#   /mnt/config/config.json        — instance metadata
#   /mnt/config/openclaw.json      — gateway config (port, auth, models)
#   /mnt/config/openclaw.env       — environment overrides
#   /mnt/secrets/secrets.json      — tenant secrets
#   /mnt/secrets/openclaw-secrets.env — API keys (ANTHROPIC_API_KEY, etc.)

{ pkgs, openclaw, ... }:

{
  imports = [
    (import ./common.nix { serviceName = "openclaw-gateway"; tmpfsSizeMib = 1024; })
  ];

  services.mvm-integrations = {
    enable = true;
    integrations.openclaw-gateway = {
      healthCmd = "${pkgs.systemd}/bin/systemctl is-active openclaw-gateway.service";
      healthIntervalSecs = 10;
      healthTimeoutSecs = 5;
    };
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
      ReadWritePaths = [ "/var/lib/openclaw" ];
      MemoryMax = "2G";
      TasksMax = 1024;
    };
  };
}
