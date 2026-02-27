# Shared configuration for all OpenClaw roles.
#
# This is a parameterized function, not a standalone NixOS module.
# Each role module (gateway.nix, worker.nix) imports it with its own
# service name and resource settings:
#
#   imports = [
#     (import ./common.nix { serviceName = "openclaw-gateway"; tmpfsSizeMib = 1024; })
#   ];
#
# Provides:
#   - openclaw user/group
#   - tmpfs workspace at /var/lib/openclaw
#   - openclaw-init oneshot (config merge + persistent storage links)
#   - guest-integrations.nix import (for health check registration)

{ serviceName, tmpfsSizeMib ? 1024 }:

{ pkgs, ... }:
{
  imports = [ ../../../nix/modules/guest-integrations.nix ];

  networking.hostName = "openclaw";
  networking.firewall.enable = false;

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
    options = [ "mode=0755" "size=${toString tmpfsSizeMib}m" ];
  };

  # --- Boot-time setup: merge config + link persistent storage ---
  systemd.services.openclaw-init = {
    description = "Prepare OpenClaw directories and config";
    before = [ "${serviceName}.service" ];
    requiredBy = [ "${serviceName}.service" ];
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
}
