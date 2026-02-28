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
    after = [ "mnt-config.mount" "mnt-secrets.mount" ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      # Runs as root so it can set ownership of the tmpfs mount.
      # All created files are chowned to openclaw at the end.
    };

    script = ''
      set -eu

      # The tmpfs at /var/lib/openclaw mounts as root — fix ownership.
      chown openclaw:openclaw /var/lib/openclaw

      # Runtime directories on tmpfs.
      install -d -o openclaw -g openclaw /var/lib/openclaw/{config,.state,logs}

      # Copy read-only config to a writable location so OpenClaw can
      # update settings at runtime (enable skills, change models, etc.).
      if [ -f /mnt/config/openclaw.json ]; then
        install -o openclaw -g openclaw -m 0644 \
          /mnt/config/openclaw.json /var/lib/openclaw/config/openclaw.json
      else
        # No config provided — write a minimal default so the gateway
        # can start in local mode without requiring `openclaw setup`.
        cat > /var/lib/openclaw/config/openclaw.json << 'DEFAULTCFG'
      {"gateway":{"mode":"local","port":3000},"version":"1"}
      DEFAULTCFG
        chown openclaw:openclaw /var/lib/openclaw/config/openclaw.json
      fi

      # Persistent storage on the data drive (survives reboots).
      # The data drive is noauto in fstab — try to mount it if the device exists.
      if [ -b /dev/vdd ] && ! mountpoint -q /mnt/data 2>/dev/null; then
        mount /mnt/data || true
      fi
      if mountpoint -q /mnt/data 2>/dev/null; then
        install -d -o openclaw -g openclaw /mnt/data/openclaw/{skills,workspace,sessions}

        # Skills persist across reboots so they don't need re-installing.
        ln -sfn /mnt/data/openclaw/skills /var/lib/openclaw/skills

        # Workspace holds SOUL.md, USER.md, MEMORY.md — agent identity.
        ln -sfn /mnt/data/openclaw/workspace /var/lib/openclaw/workspace

        # Session history for continuity.
        ln -sfn /mnt/data/openclaw/sessions /var/lib/openclaw/sessions
      else
        # No data drive — use tmpfs (ephemeral, lost on reboot).
        install -d -o openclaw -g openclaw /var/lib/openclaw/{skills,workspace,sessions}
      fi
    '';
  };
}
