# Baseline NixOS configuration for mvm Firecracker guests.
#
# This module configures the guest OS for running inside Firecracker:
# - Minimal kernel with only virtio drivers
# - Console on ttyS0 (Firecracker serial)
# - Root filesystem on /dev/vda (ext4, the Nix-built rootfs image)
# - Network via systemd-networkd, IP passed from host via kernel cmdline
# - Mount points for mvm drives (config, secrets, data) by device path
# - Security hardening: no SSH, no sudo, no mutable users
#
# mvm's drive model:
#   /dev/vda  = rootfs (ext4, read-write) — always present, contains NixOS + nix store
#   /dev/vdb  = config drive (ext4, label=mvm-config, read-only) — per-instance metadata
#   /dev/vdc  = secrets drive (ext4, label=mvm-secrets, read-only) — ephemeral tenant secrets
#   /dev/vdd  = data drive (ext4, label=mvm-data, read-write) — optional persistent storage
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

{ pkgs, lib, ... }:
{
  system.stateVersion = "25.11";

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
    # Trust CPU for entropy — avoid blocking on random seed in Firecracker
    "random.trust_cpu=on"
    # Suppress systemd status lines on serial (synchronous = slow)
    "systemd.show_status=false"
    "rd.systemd.show_status=false"
    # Mask services that are useless inside Firecracker.
    # udevd: scans for hardware — FC has exactly 3 virtio devices, no scanning needed.
    # We mount by device path (/dev/vda, /dev/vdb) not by-label, so udev is unnecessary.
    "systemd.mask=systemd-udevd.service"
    "systemd.mask=systemd-udevd-control.socket"
    "systemd.mask=systemd-udevd-kernel.socket"
    "systemd.mask=systemd-udev-trigger.service"
    "systemd.mask=systemd-udev-settle.service"
    # random-seed: no persistent storage for seed in ephemeral VMs
    "systemd.mask=systemd-random-seed.service"
    # utmp: no login accounting in headless VMs
    "systemd.mask=systemd-update-utmp.service"
    # Skip keyboard controller probes (x86 only, harmless on aarch64)
    "i8042.noaux"
    "i8042.nomux"
    "i8042.nopnp"
    "i8042.nokbd"
  ];

  # Only include the virtio drivers we actually need.
  # Setting includeDefaultModules = false prevents NixOS from pulling in
  # hundreds of modules (dm_mod, ata, usb, etc.) that don't exist in FC.
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_net" ];
  boot.initrd.kernelModules = [ "virtio_pci" "virtio_blk" "virtio_net" ];

  # Explicitly disable the systemd initrd.  NixOS 25.11 defaults to
  # boot.initrd.systemd.enable = true, but the systemd initrd requires
  # initrd-find-nixos-closure.service and initrd-nixos-activation, which
  # fail because our make-ext4-fs.nix rootfs lacks the NixOS profile
  # symlinks the systemd initrd expects.  The scripted stage-1 works
  # fine — it simply mounts /dev/vda and pivots root.
  boot.initrd.systemd.enable = false;

  # --- Custom kernel ---
  # Firecracker-optimized kernel is in firecracker-kernel.nix (included by
  # mkGuest in flake.nix). Uses Firecracker's upstream aarch64 guest config
  # with linuxManualConfig for a monolithic ~8 MB kernel.

  # --- Minimize boot time ---
  documentation.enable = false;
  boot.tmp.useTmpfs = true;
  boot.swraid.enable = false;
  services.timesyncd.enable = false;
  security.audit.enable = false;
  systemd.tpm2.enable = false;
  system.switch.enable = false;
  services.nscd.enable = false;
  system.nssModules = pkgs.lib.mkForce [];
  services.logrotate.enable = false;
  programs.command-not-found.enable = false;
  nix.enable = false;  # no nix-daemon inside the microVM

  # Replace slow Perl update-users-groups.pl with native C systemd-sysusers.
  systemd.sysusers.enable = true;

  # Short timeouts — don't wait 90s for anything in an ephemeral VM.
  systemd.settings.Manager = {
    DefaultTimeoutStartSec = "10s";
    DefaultTimeoutStopSec = "10s";
    DefaultDeviceTimeoutSec = "5s";
  };

  # Skip fsck — these are ephemeral VMs, rootfs is rebuilt on every deploy
  boot.initrd.checkJournalingFS = false;

  # --- Root filesystem ---
  # The rootfs ext4 image (built by make-ext4-fs.nix) is presented as /dev/vda.
  # It contains the complete NixOS system closure including /nix/store.
  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
    # nobarrier: skip write barriers — safe for ephemeral VMs (data isn't precious).
    # commit=60: batch journal commits (reduce I/O during boot).
    options = [ "noatime" "nobarrier" "commit=60" ];
    neededForBoot = true;
  };

  # --- Console ---
  systemd.services."serial-getty@ttyS0".enable = true;
  boot.consoleLogLevel = 0;  # minimize synchronous serial output during boot
  # Volatile journal — no disk flush for ephemeral VMs.
  # Forward to serial console so `mvmctl logs` still shows service errors.
  services.journald.storage = "volatile";
  services.journald.extraConfig = ''
    ForwardToConsole=yes
    MaxLevelConsole=info
    RuntimeMaxUse=8M
  '';

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
  # `noauto` prevents systemd from waiting for /dev/vdd at boot (which produces
  # noisy timeout errors when the drive isn't attached).  Services that need
  # persistent storage should `mount /mnt/data` explicitly or check with
  # `mountpoint -q /mnt/data`.
  fileSystems."/mnt/data" = {
    device = "/dev/vdd";
    fsType = "ext4";
    options = [ "noexec" "nosuid" "nodev" "nofail" "noauto" ];
    neededForBoot = false;
  };

  # Ensure the mount point exists even when the data drive is not attached,
  # so services with ReadWritePaths = [ "/mnt/data" ] don't fail namespace setup.
  systemd.tmpfiles.rules = [ "d /mnt/data 0755 root root -" ];

  # --- Minimal packages ---
  # Keep the system closure small — only include what's needed at the base level.
  # Role-specific tools (curl, jq) should be added in the role module's service PATH.
  environment.systemPackages = [ ];

  # --- Security hardening ---
  # microVMs are headless workloads — no SSH, no interactive login.
  # Communication is via Firecracker vsock only.
  security.sudo.enable = false;
  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
}
