# Worker role — systemd service for the OpenClaw worker.
#
# Multi-tenant design:
#   The same microVM image runs for every tenant. Per-tenant configuration
#   is injected at runtime by mvm via two Firecracker drives:
#
#   /mnt/config/  (label: mvm-config, read-only)
#     - config.json    — mvm instance metadata (tenant_id, instance_id, guest_ip, etc.)
#     - worker.toml    — app config (listen addr, task queue, etc.)
#     - worker.env     — environment overrides
#
#   /mnt/secrets/ (label: mvm-secrets, read-only, ephemeral)
#     - secrets.json   — mvm tenant secrets
#     - worker-secrets.env — app secrets (API keys, credentials, etc.)
#
#   The operator populates these files in the tenant's secrets store and pool
#   config before starting instances. mvm handles creating the drives and
#   mounting them into the Firecracker VM.

{ pkgs, ... }:
{
  users.groups.openclaw = { };
  users.users.openclaw = {
    isSystemUser = true;
    group = "openclaw";
    home = "/var/lib/openclaw";
    createHome = true;
  };

  systemd.services.openclaw-worker = {
    description = "OpenClaw Worker";
    after = [ "network-online.target" "mnt-config.mount" "mnt-secrets.mount" ];
    wants = [ "network-online.target" "mnt-config.mount" "mnt-secrets.mount" ];
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

      # Verify config and secrets drives are mounted with expected files
      ExecStartPre = [
        "${pkgs.coreutils}/bin/test -f /mnt/config/config.json"
        "${pkgs.coreutils}/bin/test -f /mnt/config/worker.toml"
        "${pkgs.coreutils}/bin/test -f /mnt/secrets/secrets.json"
      ];

      EnvironmentFile = [
        "-/mnt/config/worker.env"
        "-/mnt/secrets/worker-secrets.env"
      ];

      ExecStart = pkgs.writeShellScript "openclaw-worker-start" ''
        set -eu
        export OPENCLAW_CONFIG_PATH="''${OPENCLAW_CONFIG_PATH:-/mnt/config/worker.toml}"
        export OPENCLAW_STATE_DIR="''${OPENCLAW_STATE_DIR:-/var/lib/openclaw/.state}"
        export OPENCLAW_MVM_CONFIG="/mnt/config/config.json"
        exec openclaw worker
      '';
    };
  };
}
