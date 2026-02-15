
{ pkgs, ... }:
{
  users.groups.openclaw = { };
  users.users.openclaw = {
    isSystemUser = true;
    group = "openclaw";
    home = "/var/lib/openclaw";
    createHome = true;
  };

  systemd.services.openclaw-gateway = {
    description = "OpenClaw Gateway";
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
        "${pkgs.coreutils}/bin/test -f /mnt/config/gateway.toml"
        "${pkgs.coreutils}/bin/test -f /mnt/config/gateway.env"
        "${pkgs.coreutils}/bin/test -f /mnt/secrets/gateway-secrets.env"
      ];
      EnvironmentFile = [
        "/mnt/config/gateway.env"
        "/mnt/secrets/gateway-secrets.env"
      ];
      ExecStart = pkgs.writeShellScript "openclaw-gateway-start" ''
        set -eu
        # Template placeholder process for gateway role.
        # Replace with the real OpenClaw gateway binary invocation.
        exec ${pkgs.bash}/bin/bash -lc 'while true; do sleep 3600; done'
      '';
    };
  };
}
