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

  # Pin the exact upstream point release rather than inheriting nixpkgs'
  # `linux_6_12`, which is gated by the release channel's cadence and lags
  # kernel.org's LTS point releases (where the CVE backports land). We already
  # build from the vanilla tarball and apply no distro kernel patches, so
  # fetching the source directly — the same way libkrunfw pins its bundled
  # kernel — lets both of mvm's kernels track the latest point release exactly
  # and keeps the two pins from drifting apart. Bump `kernelVersion` + `hash`
  # together (the tarball's own sha256, e.g. via `nix store prefetch-file`).
  kernelVersion = "6.12.98";
  kernelSrc = pkgs.fetchurl {
    url = "mirror://kernel/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
    hash = "sha256-pitqLSB/9yUQ5fRxVrcHjh5xeXNXQSQRuOT/+X/I9Mc=";
  };
  # The builder's overlay filesystem triggers a GNU tar directory-metadata
  # race while unpacking this archive. Materialize the source with bsdtar once
  # and pass the resulting directory to all kernel derivations.
  kernelSourceTree = pkgs.runCommand "linux-${kernelVersion}-source" {
    nativeBuildInputs = [ pkgs.libarchive ];
  } ''
    mkdir -p "$out"
    ${pkgs.libarchive}/bin/bsdtar -xf ${kernelSrc} -C "$out" --strip-components=1
  '';

  # ── Base: minimal feature set common to every mvm microVM kernel ──
  #
  # Each entry becomes a `scripts/config --enable CONFIG_<name>`.
  # `make olddefconfig` fills in transitive dependencies, so this names
  # only what we directly require.
  baseEnables = [
    # virtio bus + BOTH transports (sans virtio-fs — that's builder-only; a
    # sealed workload mounts no host shares). Both transports are required
    # because the backends differ: libkrun/Firecracker present virtio over
    # MMIO, but **vz (Apple Virtualization.framework) presents virtio over
    # PCI**. A kernel without PCI/VIRTIO_PCI boots blind under vz — no
    # virtio-console (zero bytes on hvc0), no virtio-net, no virtio-block — so
    # the vz builder + workload VMs hang at boot. PCI + PCI_MSI + VIRTIO_PCI
    # therefore stay enabled; do not drop them as "MMIO-only dead weight" (that
    # regression broke every vz boot on macOS). The generic ECAM PCI host
    # controller AVF's bus needs comes from `make defconfig` once PCI is on.
    "VIRTIO" "VIRTIO_MENU" "VIRTIO_MMIO" "VIRTIO_PCI"
    "PCI" "PCI_MSI"
    "VIRTIO_BLK" "VIRTIO_NET" "VIRTIO_CONSOLE"
    "HVC_DRIVER"
    "VSOCKETS" "VIRTIO_VSOCKETS" "VIRTIO_BALLOON"
    "HW_RANDOM" "HW_RANDOM_VIRTIO"

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
  ] ++ pkgs.lib.optionals (kernelArch == "x86_64") [
    # KVM paravirt clock. libkrun's x86 device model exposes no PIT/HPET, so a
    # guest that doesn't detect the hypervisor has no usable early clocksource
    # and stalls in setup_arch before the console registers. HYPERVISOR_GUEST +
    # KVM_GUEST make the kernel detect KVM and use kvm-clock; PARAVIRT is their
    # prerequisite. arm64 boots under the architected timer and needs none of it.
    "HYPERVISOR_GUEST" "PARAVIRT" "KVM_GUEST"

    # libkrun on x86 has no device tree (aarch64) and no PCI enumeration (vz):
    # it advertises its virtio-mmio devices *only* through
    # `virtio_mmio.device=<size>@<addr>:<irq>` kernel-cmdline params. Without
    # VIRTIO_MMIO_CMDLINE_DEVICES the guest ignores them, the root virtio-blk
    # never binds, /dev/vda never appears, and boot hangs forever at "Waiting
    # for root device /dev/vda". arm64 discovers the same devices via FDT, so it
    # neither needs nor compiles this in (keeping it off the arm64 built-in
    # symbol budget).
    "VIRTIO_MMIO_CMDLINE_DEVICES"
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
    # mvm's audit path is the userspace, chain-signed host-services flow
    # (`host.audit.v1`, hostd, verifier), not Linux kernel audit or audit
    # netlink. The guest/runtime path and the builder path do not ship
    # `auditd`/`auditctl`, and no admitted workload contract consumes
    # NETLINK_AUDIT or syscall-audit records.
    "AUDIT"
    # Linux 6.12 keeps the core `BPF` interpreter built-in once `NET` is on,
    # and the current workload contract still needs `NET` for AF_VSOCK,
    # loopback helpers, and netlink route setup. The JIT path is separate:
    # it is an optional speedup for loaded BPF programs, not a requirement for
    # seccomp's cBPF filters or the in-kernel interpreter. Neither the sealed
    # workload nor the builder path ships a BPF loader, touches
    # `/proc/sys/net/core/bpf_jit_*`, or uses xt_bpf/classifier programs, so
    # keep the interpreter and drop the native-code JIT surface.
    "BPF_JIT" "BPF_JIT_DEFAULT_ON"
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

    # Shrink batch 1 — leaf driver subsystems defconfig pulls in that a
    # headless virtio microVM never touches (console is hvc0 + vsock; no
    # firmware blobs, no input devices, no host sensors/watchdog). None are
    # transitive deps of the keep-set (virtio/vsock/ext4/overlay/dm-verity).
    "FW_LOADER"            # request_firmware infra — no driver here loads blobs
    "FIREWIRE"             # IEEE-1394 host stack
    "INPUT" "SERIO"        # input core + PS/2 serial-IO; no virtio-input/keyboard
    "HWMON"                # hardware monitoring sensors
    "WATCHDOG"             # watchdog timers

    # Shrink batch 2 — self-contained subsystems + SoC bus/pin/PMIC drivers
    # defconfig drags in. The SoC `ARCH_*` clusters are already off; these are
    # the orthogonal driver menus that survive that. None are on the virtio
    # microVM boot path (no GPIO/I2C/pinctrl/PMIC hardware; FDT boot, not EFI;
    # not a ChromeOS board). Netfilter is NOT cut here — the builder kernel
    # needs it for its egress lockdown; the workload kernel drops it on its
    # own (workload.nix extraDisables), since base is shared by both.
    "CHROME_PLATFORMS"     # ChromeOS embedded-controller drivers
    "EFI"                  # arm64 boots from the FDT, never the EFI stub/runtime
    "I2C"                  # no I2C buses behind virtio
    "GPIOLIB"              # no GPIO controllers
    "PINCTRL"              # SoC pin-mux
    "MFD_CORE"             # multi-function (PMIC) device core

    # NOTE: PCI is intentionally NOT disabled — vz (Apple
    # Virtualization.framework) presents virtio over PCI, so PCI + VIRTIO_PCI
    # are in the enable list above. libkrun/Firecracker (MMIO) simply don't
    # probe it. Dropping PCI here is what broke every vz boot on macOS.

    # Shrink batch 4 — more whole subsystems a sealed virtio microVM never
    # uses. Each cascades its family (drivers + helpers) via olddefconfig.
    "NFS_FS"               # no network filesystems mounted
    "PHYLIB" "MDIO_DEVICE" # ethernet PHY mgmt — virtio-net has no PHY
    "VFIO"                 # device passthrough — unused (no PCI passthrough)
    "IPMI_HANDLER"         # no BMC / out-of-band mgmt
    "CPU_FREQ" "CPU_IDLE"  # no DVFS/idle-governor in a guest
    "SPI"                  # no SPI buses behind virtio (drops SPI flash/RTC/…)
    "NVMEM"                # no on-board NVMEM providers
    "PWM"                  # no PWM controllers

    # Shrink batch 5 — subsystems the proven-minimal libkrun guest also drops.
    # Console stays: 8250 + AMBA PL011 + virtio-console are kept; only the SoC
    # vendor UARTs go. IOMMU is safe to drop — virtio rides MMIO with direct
    # DMA, no translation unit.
    "CORESIGHT"            # ARM hardware trace/debug — never wired in a guest
    "VIRTUALIZATION"       # a guest doesn't host nested VMs (drops KVM)
    "REMOTEPROC"           # no remote-processor/RPMSG coprocessors
    "IOMMU_SUPPORT"        # virtio-mmio uses direct DMA; no SMMU present
    "SERIAL_XILINX_PS_UART" "SERIAL_FSL_LPUART" "SERIAL_FSL_LINFLEXUART"
    "SERIAL_MCTRL_GPIO" "SERIAL_DEV_BUS"  # SoC/serdev UARTs — console is PL011

    # Shrink batch 6 — block-device *clients* defconfig builds in that no mvm
    # backend can ever drive. Every guest boots one virtio-blk disk (`vda`,
    # kept via VIRTIO_BLK above); libkrun / vz / Firecracker present no NBD
    # server and no NVMe controller, so these drivers register phantom devices
    # (nbd0–15) and idle rescuer workqueue threads (16× kworker/R-nbd*, 3×
    # kworker/R-nvme) with nothing behind them. A workload *cannot* reach them —
    # there is no host-side device — so dropping them is pure attack-surface +
    # thread-count reduction with zero functional loss on any boot path.
    # Only NBD/NVMe live here (shared base): they are universally dead — no
    # host-side device exists on any backend, so neither the builder nor a
    # workload can reach them. The sibling block-driver drops BLK_DEV_LOOP and
    # BLK_DEV_MD are scoped to workload.nix instead: the builder kernel may
    # loop-mount while assembling images, and BLK_DEV_MD only materialises where
    # the CONFIG_MD umbrella is enabled (workload's dm-verity delta). See
    # workload.nix.
    "BLK_DEV_NBD"          # network block device — no NBD server on any backend
    "BLK_DEV_NVME" "NVME_CORE"  # NVMe — no NVMe controller behind virtio
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
      cp -a --reflink=auto ${kernelSourceTree}/. linux/
      cd linux
      chmod -R u+w .

      export ARCH=${kernelArch}
      export SHELL=${pkgs.bash}/bin/bash
      export CONFIG_SHELL=${pkgs.bash}/bin/bash

      # Linux Kconfig's `$(shell,...)` helper goes through `popen()`, which
      # hardwires `/bin/sh -c ...` instead of respecting PATH or Kbuild's
      # `CONFIG_SHELL`. The Nix build sandbox does not guarantee `/bin/sh`,
      # so provide one explicitly before the first `make defconfig` shell
      # probe (compiler/linker presence, cc-version, etc.).
      if [ ! -x /bin/sh ]; then
        mkdir -p /bin
        ln -s ${pkgs.bash}/bin/sh /bin/sh
      fi

      # `scripts/config` ships `#!/usr/bin/env bash`; the Nix sandbox has
      # no `/usr/bin/env`. patchShebangs rewrites to the sandbox bash.
      patchShebangs scripts/

      # Base on `defconfig`, not `tinyconfig`: tinyconfig strips
      # arch_timer, GIC, OF/devicetree, PL011 serial, TTY, HVC_DRIVER —
      # the platform support libkrun's virtual hardware emits, leaving a
      # kernel that builds but writes zero bytes on hvc0. `defconfig` is
      # the upstream recommended starting point; we carve it down via
      # the disables below.
      make SHELL="$SHELL" defconfig

      # Enables first, then disables — a disable must win over a
      # defconfig-implied enable. Symbols within each pass are distinct,
      # so intra-pass order is irrelevant.
      for s in $enableList; do
        ./scripts/config --enable "$s"
      done
      for s in $disableList; do
        ./scripts/config --disable "$s"
      done

      make SHELL="$SHELL" olddefconfig

      # Guard: every requested enable must survive olddefconfig. When a
      # symbol's Kconfig `depends on` isn't met — e.g. a shrink disabled a
      # hidden dependency of a still-needed driver — olddefconfig silently
      # drops it and the build still succeeds, yielding a kernel missing the
      # driver with zero signal. That is the #1 silent-failure mode of
      # kernel shrinking. Assert each requested enable is `=y` in the final
      # config and fail loud, naming the casualties, so a dropped dependency
      # is caught here instead of at a guest's failed mount/boot.
      missing=""
      for s in $enableList; do
        if ! grep -q "^CONFIG_$s=y\$" .config; then
          missing="$missing $s"
        fi
      done
      if [ -n "$missing" ]; then
        echo "ERROR: requested kernel enables were dropped by olddefconfig:$missing" >&2
        echo "Each dropped symbol has an unmet Kconfig dependency, or a disable removed a symbol it needs. Investigate — do not suppress." >&2
        exit 1
      fi

      cp .config $out
    '';

  # Build a kernel from base + deltas. `allowImportFromDerivation =
  # false` keeps `nix flake check --no-build` (CI "Nix flake check"
  # lane) working: --no-build won't realize the configfile derivation,
  # and IFD from linuxManualConfig would then fail with
  # `path '…-kernel-config.drv' is not valid`. We pass the pinned
  # version/modDirVersion/src explicitly, so the configfile content is
  # needed only at build time, not eval time. `modDirVersion` matches the
  # pinned version even though CONFIG_MODULES=n leaves the module tree empty.
  mkKernel = { extraEnables ? [ ], extraDisables ? [ ] }:
    pkgs.linuxManualConfig {
      src = kernelSourceTree;
      version = kernelVersion;
      modDirVersion = kernelVersion;
      configfile = mkConfigfile { inherit extraEnables extraDisables; };
      allowImportFromDerivation = false;
    };

in
{
  inherit kernelArch kernelVersion baseEnables baseDisables mkConfigfile mkKernel;
}
