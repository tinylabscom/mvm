# Baseline NixOS configuration for mvm Firecracker guests.
#
# This module configures the guest OS for Firecracker:
# - Minimal kernel for VM boot
# - Console on ttyS0 (Firecracker serial)
# - Root filesystem on /dev/vda (ext4, the Nix-built rootfs image)
# - Network via systemd-networkd, IP passed from host via kernel cmdline
# - Mount points for mvm drives (config, secrets, data) by device path
# - Automatic init of the NixOS system on boot
#
# mvm's drive model:
#   /dev/vda  = rootfs (ext4, read-write) — always present, contains NixOS + nix store
#   /dev/vd*  = config drive (ext4, label=mvm-config, read-only) — per-instance metadata
#   /dev/vd*  = data drive (ext4, label=mvm-data, read-write) — optional persistent storage
#   /dev/vd*  = secrets drive (ext4, label=mvm-secrets, read-only) — ephemeral tenant secrets
#
# Drives are mounted by device path (not filesystem label) because the
# minimal initrd doesn't include udev rules for /dev/disk/by-label/.
# Firecracker drive ordering is deterministic, so device paths are stable.
#
# Networking:
#   The host assigns each VM a static IP and passes it via Firecracker
#   kernel boot args: mvm.ip=<cidr> mvm.gw=<gateway>.  A one-shot
#   systemd service reads /proc/cmdline and writes a networkd config
#   before systemd-networkd starts.  No DHCP needed.

{ lib, pkgs, ... }:
{
  system.stateVersion = "24.11";

  # --- Boot ---
  boot.loader.grub.enable = false;
  boot.kernelParams = [
    "console=ttyS0"
    "reboot=k"
    "panic=1"
    # Force classic eth0 naming — Firecracker with --enable-pci would
    # otherwise assign predictable names (enp0s2) which are harder to
    # configure statically.
    "net.ifnames=0"
    # Only initialize 1 UART (Firecracker only has 1 serial)
    "8250.nr_uarts=1"
    # Reduce kernel log verbosity during boot
    "quiet"
    "loglevel=4"
  ];

  # Only include the virtio drivers we actually need.
  # Setting includeDefaultModules = false prevents NixOS from pulling in
  # hundreds of modules (dm_mod, ata, usb, etc.) that don't exist in FC.
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_net" ];
  boot.initrd.kernelModules = [ "virtio_pci" "virtio_blk" "virtio_net" ];

  # --- Minimize boot time ---
  documentation.enable = false;
  boot.tmp.useTmpfs = true;
  boot.swraid.enable = false;
  services.timesyncd.enable = false;
  security.audit.enable = false;
  systemd.tpm2.enable = false;
  system.switch.enable = false;

  # Skip fsck — these are ephemeral VMs, rootfs is rebuilt on every deploy
  boot.initrd.checkJournalingFS = false;

  # --- Root filesystem ---
  # The rootfs ext4 image (built by make-ext4-fs.nix) is presented as /dev/vda.
  # It contains the complete NixOS system closure including /nix/store.
  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
    options = [ "noatime" ];
  };

  # --- Console ---
  systemd.services."serial-getty@ttyS0".enable = true;

  # --- Networking (systemd-networkd + kernel cmdline IP) ---
  # The host passes mvm.ip=<cidr> and mvm.gw=<ip> in Firecracker boot args.
  # A one-shot service reads these from /proc/cmdline and writes a networkd
  # .network file before networkd starts.  This avoids the 90s device-wait
  # timeout that legacy networking.interfaces generates.
  networking.useNetworkd = true;
  networking.useDHCP = false;
  systemd.network.enable = true;
  systemd.network.wait-online.enable = false;

  systemd.services.mvm-network-config = {
    description = "Configure network from mvm kernel parameters";
    before = [ "systemd-networkd.service" ];
    wantedBy = [ "systemd-networkd.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      # Pure shell — no grep dependency, much faster than grep -oP
      ExecStart = pkgs.writeShellScript "mvm-network-config" ''
        CMDLINE=$(cat /proc/cmdline)
        IP= GW=
        for arg in $CMDLINE; do
          case "$arg" in
            mvm.ip=*) IP="''${arg#mvm.ip=}" ;;
            mvm.gw=*) GW="''${arg#mvm.gw=}" ;;
          esac
        done
        if [ -n "$IP" ] && [ -n "$GW" ]; then
          mkdir -p /run/systemd/network
          cat > /run/systemd/network/10-eth0.network << EOF
        [Match]
        Name=eth0

        [Network]
        Address=$IP
        Gateway=$GW
        DNS=$GW
        EOF
        fi
      '';
    };
  };

  # --- mvm drives (config, secrets, data) ---
  # Firecracker drive ordering is deterministic:
  #   /dev/vda = rootfs (always present)
  #   /dev/vdb = config drive (per-instance metadata)
  #   /dev/vdc = secrets drive (ephemeral tenant secrets)
  #   /dev/vdd = data drive (optional persistent storage)
  #
  # We use device paths instead of by-label because our minimal initrd
  # (includeDefaultModules = false) doesn't include the udev rules that
  # create /dev/disk/by-label/ symlinks for post-boot block devices.
  fileSystems."/mnt/config" = {
    device = "/dev/vdb";
    fsType = "ext4";
    options = [ "ro" "noexec" "nosuid" "nodev" "nofail" ];
    neededForBoot = true;
  };

  fileSystems."/mnt/secrets" = {
    device = "/dev/vdc";
    fsType = "ext4";
    options = [ "ro" "noexec" "nosuid" "nodev" "nofail" ];
    neededForBoot = true;
  };

  # Data drive is optional — only present when pool spec has data_disk_mib > 0.
  # Use a short timeout so boot isn't blocked when the drive doesn't exist.
  fileSystems."/mnt/data" = {
    device = "/dev/vdd";
    fsType = "ext4";
    options = [ "noexec" "nosuid" "nodev" "nofail" "x-systemd.device-timeout=1s" ];
    neededForBoot = false;
  };

  # --- Minimal packages ---
  environment.systemPackages = with pkgs; [
    curl
    jq
  ];

  # --- Security hardening ---
  # microVMs are headless workloads — no SSH, no interactive login.
  # Communication is via Firecracker vsock only.
  security.sudo.enable = false;
  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
}
