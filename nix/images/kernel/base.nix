# Shared kernel-config foundation for mvm's custom microVM kernels.
#
# One source of truth for the slim, all-built-in (`CONFIG_MODULES=n`)
# Linux config that every mvm guest boots. Two kernels are derived from
# it via `mkKernel`'s `extra{Enables,Disables}` deltas:
#
#   - workloadKernel = mkKernel { }                  (base only)
#   - builderKernel  = mkKernel { extraEnables = …;} (base + builder infra)
#
# The base set is the minimal config a *sealed workload guest* needs to
# boot under libkrun / Firecracker and reach the host over virtio +
# vsock. The builder VM is a superset: it additionally mounts virtio-fs
# host shares, overlays a persistent `/nix` store, runs the nix-build
# sandbox (user namespaces + cgroups), and installs an iptables egress
# lockdown — none of which a workload guest needs. Those land in the
# builder's `extraEnables` (see `nix/images/kernel/builder.nix`).
#
# Why slim / all-built-in: a stock `pkgs.linuxPackages.kernel` ships
# the features we need as `=m`, forcing every consumer to ship a
# `/lib/modules/<kver>/` tree and modprobe each one at the right moment
# (overlay before mount, vsock before socket(), iptables before rule
# install). Each `=m` is a silent-failure surface. Flipping everything
# we need to `=y` makes modprobe a no-op and deletes the module tree.
# Five distinct ways the module contract broke during validation drove
# this decision.
#
# Why no TSI patches: builder-VM networking moved to passt (Linux) /
# gvproxy (macOS) over virtio-net. The TSI syscall-hijack path is gone
# from every VM, and the vendored 22-file patch series was dropped.
#
# Tradeoff — first build compiles from source: because the `.config` is
# novel, `cache.nixos.org` has no substitute, so a fresh machine
# compiles the kernel once (3-5 min on Apple Silicon, ~10 min slower).
# Sharing the base means the builder and workload kernels reuse most of
# the same closure, and `mvmctl kernel build` (+ the hash-keyed GHA
# prebuilt) move that cost out of the hot `dev up` loop.

{ pkgs }:

let
  kernelArch =
    if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86_64";

  # ── Base: minimal feature set common to every mvm microVM kernel ──
  #
  # Each entry becomes a `scripts/config --enable CONFIG_<name>`.
  # `make olddefconfig` fills in transitive dependencies, so this names
  # only what we directly require.
  baseEnables = [
    # virtio bus + transport (sans virtio-fs — that's builder-only;
    # a sealed workload mounts no host shares).
    "VIRTIO" "VIRTIO_MENU" "VIRTIO_PCI" "VIRTIO_MMIO"
    "VIRTIO_BLK" "VIRTIO_NET" "VIRTIO_CONSOLE"
    "VSOCKETS" "VIRTIO_VSOCKETS" "VIRTIO_BALLOON"
    "HW_RANDOM" "HW_RANDOM_VIRTIO"
    "PCI" "PCI_MSI"

    # filesystems. OVERLAY_FS stays in base: the guest agent lands on
    # an overlay. FUSE_FS is builder-only (it backs virtio-fs).
    # dm-verity (Claim 3 — verified boot) is a
    # *workload-only* delta, not base: the builder boots `root=/dev/vda
    # ro` with no roothash and never opens a dm device (its veritysetup
    # only runs `format` in userspace). `mkWorkloadKernel` adds it.
    "BLOCK" "EXT4_FS" "OVERLAY_FS"
    "TMPFS" "TMPFS_POSIX_ACL" "TMPFS_XATTR"
    "DEVTMPFS" "DEVTMPFS_MOUNT" "PROC_FS" "SYSFS"

    # process basics
    "BINFMT_ELF" "BINFMT_SCRIPT" "FUTEX" "EPOLL" "SIGNALFD"
    "EVENTFD" "TIMERFD" "SYSVIPC"
    "MULTIUSER" "SYSCTL" "PRINTK" "PRINTK_TIME" "KALLSYMS" "BUG"
    "RTC_CLASS" "HIGH_RES_TIMERS" "NO_HZ_IDLE"

    # seccomp — Claim 1 (per-service seccomp `standard` default). Base
    # because it confines the workload, not just the builder. The
    # heavier namespace + cgroup cluster the nix sandbox needs is a
    # builder-only delta.
    "SECCOMP" "SECCOMP_FILTER"

    # net core
    "NET" "INET" "PACKET" "UNIX" "TCP_CONG_CUBIC"

    # NLS (UTF-8 + ASCII only)
    "NLS" "NLS_UTF8" "NLS_ASCII"
  ];

  # ── Base disables ──
  #
  # `make defconfig` for arm64 is the multi-platform vendor defconfig —
  # it enables every SoC family upstream supports. We boot only under
  # libkrun (Apple Silicon virt) or Firecracker (Linux KVM virt), never
  # real SoC hardware, so the disables are aggressive. These apply to
  # workload and builder kernels alike. Additions derived empirically
  # from `nix build .#…-kernel-configfile`.
  baseDisables = [
    "MODULES"        # everything built-in; no /lib/modules tree
    "MODULE_SIG"     # NOP without MODULES; explicit
    "IPV6"           # no v6 path in any current mvm VM
    # Force-dropped (not merely absent from enables) so `olddefconfig`
    # drops a defconfig default instead of leaving it `=y`.
    "EXT4_USE_FOR_EXT2"  # nothing mounts ext2/ext3; ext4 only
    # POSIX message queues: guests talk over vsock; neither the agent, a
    # sealed workload, nor the nix-build sandbox open mq_*. Force-dropped to
    # delete the mq_open/mq_timedsend/… syscall surface (defconfig has it =y).
    "POSIX_MQUEUE"

    # Userspace-visible classes we don't need.
    "DRM" "SOUND" "USB" "WIRELESS" "BT" "FB"

    # ARM64 SoC platform clusters — disabling each parent cascades to
    # its PCIe host controllers, irqchip, clk, pinctrl, and SoC drivers
    # via olddefconfig. Leave ARCH_VIRT enabled.
    "ARCH_ACTIONS" "ARCH_AGILEX5" "ARCH_AIROHA" "ARCH_ALPINE"
    "ARCH_APPLE" "ARCH_BCM" "ARCH_BCM_IPROC" "ARCH_BCM2835"
    "ARCH_BCMBCA" "ARCH_BERLIN" "ARCH_BLAIZE" "ARCH_BRCMSTB"
    "ARCH_EXYNOS" "ARCH_HISI" "ARCH_INTEL_SOCFPGA" "ARCH_K3"
    "ARCH_KEEMBAY" "ARCH_LAYERSCAPE" "ARCH_LG1K" "ARCH_MEDIATEK"
    "ARCH_MESON" "ARCH_MMP" "ARCH_MVEBU" "ARCH_NPCM" "ARCH_NUVOTON"
    "ARCH_NXP" "ARCH_PENSANDO" "ARCH_PHYTIUM" "ARCH_QCOM"
    "ARCH_REALTEK" "ARCH_RENESAS" "ARCH_ROCKCHIP" "ARCH_S32"
    "ARCH_S5PV210" "ARCH_SEATTLE" "ARCH_SOPHGO" "ARCH_SPARX5"
    "ARCH_SPRD" "ARCH_STM32" "ARCH_SUNPLUS" "ARCH_SUNXI"
    "ARCH_SYNQUACER" "ARCH_TEGRA" "ARCH_TESLA_FSD" "ARCH_THUNDER"
    "ARCH_THUNDER2" "ARCH_UNIPHIER" "ARCH_VEXPRESS" "ARCH_VISCONTI"
    "ARCH_XGENE" "ARCH_ZYNQMP"

    # Storage / device classes that have no virtio path.
    "MTD" "PARPORT" "ATA" "SCSI" "INFINIBAND"
    "STAGING" "MEDIA_SUPPORT"

    # Device-driver *menus* with no hardware behind them under libkrun /
    # Firecracker. defconfig enables each as a whole menu, and disabling
    # the protocol stack alone (SOUND/WIRELESS/USB above) leaves the
    # device subtree compiling — the umbrella menu symbol gates the
    # drivers/<x>/ directory, so it must go too. Each parent cascades its
    # vendor subtree via olddefconfig. We carry only VIRTIO_NET; every
    # vendor NIC, WLAN, WWAN, and CAN driver is dead weight.
    "ETHERNET"             # drivers/net/ethernet — keep NETDEVICES + VIRTIO_NET
    "WLAN" "WWAN" "CAN"    # drivers/net/{wireless,wwan,can}
    "USB_SUPPORT"          # USB host + gadget umbrella (CONFIG_USB only hit hosts)
    "HID_SUPPORT"          # no virtio-input/HID; console is hvc0 + vsock
    "RC_CORE"              # remote-control core + the keymap blob it builds
    "IIO"                  # industrial-I/O sensors
    "XEN"                  # never a Xen guest
    "MMC" "MMC_BLOCK"      # no SD/eMMC behind virtio
    "REGULATOR" "POWER_SUPPLY" "THERMAL"  # SoC power plumbing defconfig drags in
    "NEW_LEDS" "LEDS_CLASS"
  ] ++ pkgs.lib.optionals (kernelArch == "arm64") [
    # arm64 boots from the FDT libkrun / Firecracker hand us; ACPI is
    # never consulted, so drop the ACPICA interpreter and the whole
    # drivers/acpi tree (~390 files). x86 keeps ACPI deliberately — it
    # has no devicetree fallback and the hypervisor presents an ACPI/MADT
    # for SMP bringup, so disabling it there would not boot.
    "ACPI"
  ];

  # Realize a `.config` from base + the caller's deltas. `runCommandCC`
  # (not `runCommand`) so the derivation runs under `stdenv` proper —
  # gcc + binutils on PATH for `scripts/basic/fixdep` and the kernel's
  # host-side tooling. `runCommand` (stdenvNoCC) bails with
  # `gcc: command not found` at the first `make defconfig`.
  mkConfigfile = { extraEnables ? [ ], extraDisables ? [ ] }:
    pkgs.runCommandCC "mvm-kernel-config" {
      nativeBuildInputs = with pkgs; [
        gnumake bison flex bc perl pkg-config openssl
      ];
      enableList = pkgs.lib.concatStringsSep " " (baseEnables ++ extraEnables);
      disableList = pkgs.lib.concatStringsSep " " (baseDisables ++ extraDisables);
    } ''
      set -euo pipefail

      mkdir -p linux
      tar -xf ${pkgs.linux_6_12.src} -C linux --strip-components=1
      cd linux
      chmod -R u+w .

      export ARCH=${kernelArch}

      # `scripts/config` ships `#!/usr/bin/env bash`; the Nix sandbox has
      # no `/usr/bin/env`. patchShebangs rewrites to the sandbox bash.
      patchShebangs scripts/

      # Base on `defconfig`, not `tinyconfig`: tinyconfig strips
      # arch_timer, GIC, OF/devicetree, PL011 serial, TTY, HVC_DRIVER —
      # the platform support libkrun's virtual hardware emits, leaving a
      # kernel that builds but writes zero bytes on hvc0. `defconfig` is
      # the upstream recommended starting point; we carve it down via
      # the disables below.
      make defconfig

      # Enables first, then disables — a disable must win over a
      # defconfig-implied enable. Symbols within each pass are distinct,
      # so intra-pass order is irrelevant.
      for s in $enableList; do
        ./scripts/config --enable "$s"
      done
      for s in $disableList; do
        ./scripts/config --disable "$s"
      done

      make olddefconfig

      cp .config $out
    '';

  # Build a kernel from base + deltas. `allowImportFromDerivation =
  # false` keeps `nix flake check --no-build` (CI "Nix flake check"
  # lane) working: --no-build won't realize the configfile derivation,
  # and IFD from linuxManualConfig would then fail with
  # `path '…-kernel-config.drv' is not valid`. We pass
  # version/modDirVersion/src explicitly from pkgs.linux_6_12, so the
  # configfile content is needed only at build time, not eval time.
  mkKernel = { extraEnables ? [ ], extraDisables ? [ ] }:
    pkgs.linuxManualConfig {
      inherit (pkgs.linux_6_12) src version modDirVersion;
      configfile = mkConfigfile { inherit extraEnables extraDisables; };
      allowImportFromDerivation = false;
    };

in
{
  inherit kernelArch baseEnables baseDisables mkConfigfile mkKernel;
}
