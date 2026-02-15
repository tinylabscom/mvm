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
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      User = "openclaw";
      Group = "openclaw";
      Restart = "always";
      RestartSec = "2s";
      WorkingDirectory = "/var/lib/openclaw";
      ExecStartPre = [
        "${pkgs.coreutils}/bin/test -d /mnt/config"
        "${pkgs.coreutils}/bin/test -d /mnt/secrets"
        "${pkgs.coreutils}/bin/test -f /mnt/config/worker.toml"
        "${pkgs.coreutils}/bin/test -f /mnt/config/worker.env"
        "${pkgs.coreutils}/bin/test -f /mnt/secrets/worker-secrets.env"
      ];
      EnvironmentFile = [
        "/mnt/config/worker.env"
        "/mnt/secrets/worker-secrets.env"
      ];
      ExecStart = pkgs.writeShellScript "openclaw-worker-start" ''
        set -eu
        # Template placeholder process for worker role.
        # Replace with the real OpenClaw worker binary invocation.
        exec ${pkgs.bash}/bin/bash -lc 'while true; do sleep 3600; done'
      '';
    };
  };
}
