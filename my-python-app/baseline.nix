# Baseline NixOS configuration for mvm Firecracker guests.
#
# This module configures the guest OS for Firecracker:
# - Minimal kernel for VM boot
# - Console on ttyS0 (Firecracker serial)
# - Root filesystem on /dev/vda (ext4, the Nix-built rootfs image)
# - No guest NIC; workload egress uses the authenticated vsock channel
# - Mount points for mvm drives (config, secrets, data) by filesystem label
# - Automatic init of the NixOS system on boot
#
# mvm's drive model:
#   /dev/vda  = rootfs (ext4, read-write) — always present, contains NixOS + nix store
#   /dev/vd*  = config drive (ext4, label=mvm-config, read-only) — per-instance metadata
#   /dev/vd*  = data drive (ext4, label=mvm-data, read-write) — optional persistent storage
#   /dev/vd*  = secrets drive (ext4, label=mvm-secrets, read-only) — ephemeral tenant secrets
#
# Drives are mounted by filesystem label (not device path) so the guest
# config is independent of Firecracker drive ordering.
#
{ lib, pkgs, ... }:
{
  system.stateVersion = "24.11";

  # --- Boot ---
  boot.loader.grub.enable = false;
  boot.kernelParams = [
    "console=ttyS0"
    "reboot=k"
    "panic=1"
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
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" ];
  boot.initrd.kernelModules = [ "virtio_pci" "virtio_blk" ];

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
