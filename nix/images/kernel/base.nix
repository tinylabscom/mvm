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
# Why no TSI patches: builder-VM networking moved to vsock. The TSI
# syscall-hijack path is gone
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
  kernelArch = if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86_64";

  # Pin the exact upstream point release rather than inheriting nixpkgs'
  # `linux_6_12`, which is gated by the release channel's cadence and lags
  # kernel.org's LTS point releases (where the CVE backports land). We already
  # build from the vanilla tarball and apply no distro kernel patches, so
  # fetching the source directly — the same way libkrunfw pins its bundled
  # kernel — lets both of mvm's kernels track the latest point release exactly
  # and keeps the two pins from drifting apart. Bump `kernelVersion` + `hash`
  # together (the tarball's own sha256, e.g. via `nix store prefetch-file`).
  kernelVersion = "6.12.105";
  kernelSrc = pkgs.fetchurl {
    url = "mirror://kernel/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
    hash = "sha256-6zaAHhGVKbE1E8NFncIOKjL3BTYp86q7Y+pQGk2I9j0=";
  };
  # The builder's overlay filesystem triggers a GNU tar directory-metadata
  # race while unpacking this archive. Materialize the source with bsdtar once
  # and pass the resulting directory to all kernel derivations.
  kernelSourceTree =
    pkgs.buildPackages.runCommand "linux-${kernelVersion}-source"
      {
        nativeBuildInputs = [ pkgs.buildPackages.libarchive ];
      }
      ''
        mkdir -p "$out"
        ${pkgs.buildPackages.libarchive}/bin/bsdtar -xf ${kernelSrc} -C "$out" --strip-components=1
      '';

  # ── Base: minimal feature set common to every mvm microVM kernel ──
  #
  # Each entry becomes a `scripts/config --enable CONFIG_<name>`.
  # `make olddefconfig` fills in transitive dependencies, so this names
  # only what we directly require.
  baseEnables = [
    # virtio bus + BOTH transports (sans virtio-fs — that's builder-only; a
    # sealed workload mounts no host shares). Both transports are required
    # because the backends differ: libkrun/Firecracker/HVF present virtio over
    # MMIO, but **QEMU attaches its devices over PCI** (`virtio-net-pci`,
    # `vhost-vsock-pci` — see the QEMU driver's device arguments). A kernel
    # without PCI/VIRTIO_PCI boots blind there — no virtio-console (zero bytes
    # on hvc0), no virtio-net, no virtio-block — so those VMs hang at boot.
    # PCI + PCI_MSI + VIRTIO_PCI therefore stay enabled; do not drop them as
    # "MMIO-only dead weight" (dropping them has broken every boot on a
    # PCI-attached backend before). The generic ECAM PCI host controller that
    # bus needs comes from `make defconfig` once PCI is on.
    "VIRTIO"
    "VIRTIO_MENU"
    "VIRTIO_MMIO"
    "VIRTIO_PCI"
    "PCI"
    "PCI_MSI"
    "VIRTIO_BLK"
    "VIRTIO_NET"
    "VIRTIO_CONSOLE"
    "HVC_DRIVER"
    "VSOCKETS"
    "VIRTIO_VSOCKETS"
    "VIRTIO_BALLOON"
    "HW_RANDOM"
    "HW_RANDOM_VIRTIO"

    # filesystems. OVERLAY_FS stays in base: the guest agent lands on
    # an overlay. FUSE_FS is builder-only (it backs virtio-fs).
    # dm-verity (Claim 3 — verified boot) is a
    # *workload-only* delta, not base: the builder boots `root=/dev/vda
    # ro` with no roothash and never opens a dm device (its veritysetup
    # only runs `format` in userspace). `mkWorkloadKernel` adds it.
    "BLOCK"
    "EXT4_FS"
    "OVERLAY_FS"
    "TMPFS"
    "TMPFS_POSIX_ACL"
    "TMPFS_XATTR"
    "DEVTMPFS"
    "DEVTMPFS_MOUNT"
    "PROC_FS"
    "SYSFS"

    # process basics. EXPERT exposes default-on compatibility features such as
    # VT so a headless appliance kernel can explicitly turn them off.
    "EXPERT"
    "BINFMT_ELF"
    "BINFMT_SCRIPT"
    "FUTEX"
    "EPOLL"
    "SIGNALFD"
    "EVENTFD"
    "TIMERFD"
    "SYSVIPC"
    "MULTIUSER"
    "SYSCTL"
    "PRINTK"
    "PRINTK_TIME"
    "BUG"
    "RTC_CLASS"
    "HIGH_RES_TIMERS"
    "NO_HZ_IDLE"

    # seccomp — Claim 1 (per-service seccomp `standard` default). Base
    # because it confines the workload, not just the builder. The
    # heavier namespace + cgroup cluster the nix sandbox needs is a
    # builder-only delta.
    "SECCOMP"
    "SECCOMP_FILTER"

    # net core
    "NET"
    "INET"
    "UNIX"
    "TCP_CONG_CUBIC"

  ]
  ++ pkgs.lib.optionals (kernelArch == "x86_64") [
    # KVM paravirt clock. libkrun's x86 device model exposes no PIT/HPET, so a
    # guest that doesn't detect the hypervisor has no usable early clocksource
    # and stalls in setup_arch before the console registers. HYPERVISOR_GUEST +
    # KVM_GUEST make the kernel detect KVM and use kvm-clock; PARAVIRT is their
    # prerequisite. arm64 boots under the architected timer and needs none of it.
    "HYPERVISOR_GUEST"
    "PARAVIRT"
    "KVM_GUEST"

    # libkrun on x86 has no device tree (as on aarch64) and no PCI enumeration
    # (as under QEMU): it advertises its virtio-mmio devices *only* through
    # `virtio_mmio.device=<size>@<addr>:<irq>` kernel-cmdline params. Without
    # VIRTIO_MMIO_CMDLINE_DEVICES the guest ignores them, the root virtio-blk
    # never binds, /dev/vda never appears, and boot hangs forever at "Waiting
    # for root device /dev/vda". arm64 discovers the same devices via FDT, so it
    # neither needs nor compiles this in (keeping it off the arm64 built-in
    # symbol budget).
    "VIRTIO_MMIO_CMDLINE_DEVICES"
  ]
  ++ pkgs.lib.optionals (kernelArch == "arm64") [
    # Firecracker exposes an 8250 serial device on both supported host
    # architectures. Keep that console alongside PL011 (QEMU virt) and hvc0
    # (libkrun) so one published arm64 workload kernel remains observable on
    # every backend. SERIAL_OF_PLATFORM binds the DT-described UART on ARM.
    "SERIAL_8250"
    "SERIAL_8250_CONSOLE"
    "SERIAL_OF_PLATFORM"
  ];

  # ── Base disables ──
  #
  # `make defconfig` for arm64 is the multi-platform vendor defconfig —
  # it enables every SoC family upstream supports. We boot only under
  # libkrun (Apple Silicon virt) or Firecracker (Linux KVM virt), never
  # real SoC hardware, so the disables are aggressive. These apply to
  # workload and builder kernels alike. Additions derived empirically
  # from `nix build .#…-kernel-configfile`.
  requiredDisables = [
    # Resolved-config audit: default configs retain these device families even
    # though no supported VMM presents matching hardware.
    "NFC"
    "RFKILL"
    "VIRTIO_INPUT"
    "SOUNDWIRE"
    "MEDIA_CEC_SUPPORT"
    "TEE"
    "FPGA"
    "GNSS"
    "PPS"
    "PTP_1588_CLOCK"
    "STM"
    "STM_SOURCE"
    "MAILBOX"
    "HWSPINLOCK"
    "RESET_CONTROLLER"
    "SOC_TI"
    "EXTCON"
    "CRYPTO_HW"
    "CRYPTO_TEST"
    "CRYPTO_MANAGER_EXTRA_TESTS"

    # Selectors that otherwise pull disabled driver families back in during
    # olddefconfig. The console is serial/virtio-console and interactive shells
    # use UNIX98 ptys, never virtual terminals, keyboards, mice, or PHY-backed
    # Ethernet devices.
    "ARCH_MA35"
    "VT"
    "VT_CONSOLE"
    "KEYBOARD_ATKBD"
    "MOUSE_PS2"
    "PHYLINK"
    "NET_DSA"
    "PCS_XPCS"
    "MFD_HI6421_PMIC"
    "MFD_MT6397"
    "MFD_VEXPRESS_SYSREG"
    "MFD_WCD934X"
    "RTC_NVMEM"

    # Filesystems and network plumbing outside the guest contract. Both guest
    # variants use ext4, overlayfs, tmpfs, proc/sysfs, and virtio-fs only.
    "AUTOFS_FS"
    "MSDOS_FS"
    "VFAT_FS"
    "FAT_FS"
    "ISO9660_FS"
    "SQUASHFS"
    "QUOTA"
    "BRIDGE"
    "MACVLAN"
    "XFRM_USER"
    "XFRM_ALGO"
    "NET_IPVTI"
    "XFRM"
    "INET_DIAG"
    "NETLABEL"
    "NETWORK_SECMARK"

    # No backend provisions swap, huge pages, NVRAM, alternate binary-format
    # handlers, or a storage topology that benefits from a guest I/O scheduler.
    # The builder and workload both use a single virtio block device.
    "SWAP"
    "HUGETLBFS"
    "HUGETLB_PAGE"
    "BINFMT_MISC"
    "NVRAM"
    "SYNC_FILE"
    "DMA_SHARED_BUFFER"
    "IOSCHED_BFQ"
    "MQ_IOSCHED_DEADLINE"
    "MQ_IOSCHED_KYBER"

    # Traffic-control classifiers, actions and qdiscs are not part of the
    # guest networking contract. The opt-in TUN path needs only the network
    # device and IP stack; policy and relay enforcement live on the host.
    "NET_SCHED"

    # Every supported VMM exposes one uniform guest-memory node and direct
    # virtio DMA. There is no physical contiguous-memory consumer, Qualcomm
    # IPC transport, SCSI-generic block endpoint, or raw link-layer device
    # behind the host-mediated network boundary. UDP-Lite remains because Linux
    # builds it as part of the required INET core rather than behind a Kconfig
    # selector.
    "NUMA"
    "CMA"
    "QRTR"
    "BLK_DEV_BSG_COMMON"
    "BLK_DEV_BSGLIB"
    "PACKET"

    # No guest agent consumes process accounting, file-handle syscalls, the
    # obsolete sysfs syscall, or cross-process comparison. Keep core process,
    # procfs, coredump, AIO and io_uring support intact.
    "TASKSTATS"
    "TASK_DELAY_ACCT"
    "TASK_XACCT"
    "TASK_IO_ACCOUNTING"
    "FHANDLE"
    "SYSFS_SYSCALL"
    "KCMP"

    # A microVM is rebooted, stopped, snapshotted, and diagnosed by the host;
    # it does not kexec, kdump, hibernate, expose debugfs, or run kernel tracers.
    "KEXEC"
    "KEXEC_FILE"
    "CRASH_DUMP"
    "HIBERNATION"
    "DEBUG_FS"
    "KALLSYMS"
    "KALLSYMS_ALL"
    "SUSPEND"
    "PM_SLEEP"
    "RCU_TRACE"
    "NETCONSOLE"
    "NETPOLL"
    "LEGACY_PTYS"
    "FTRACE"
    "FUNCTION_TRACER"
    "FUNCTION_GRAPH_TRACER"
    "STACK_TRACER"
    "DYNAMIC_FTRACE"
    "FTRACE_SYSCALLS"
    "KPROBE_EVENTS"
    "UPROBE_EVENTS"
    "KPROBES"
    "PROFILING"
    "SECURITY_SELINUX"
    "SECURITY_APPARMOR"
    "SECURITY_SMACK"
    "SECURITY_TOMOYO"
    "SECURITYFS"

    # Module signatures, kexec verification, IMA/EVM and in-kernel TLS are all
    # absent, so no guest path consumes the keyring or asymmetric-certificate
    # parser stack. dm-verity trusts the admitted root hash directly.
    "KEYS"
    "ASYMMETRIC_KEY_TYPE"
    "SYSTEM_TRUSTED_KEYRING"
    "SYSTEM_DATA_VERIFICATION"
    "SECONDARY_TRUSTED_KEYRING"
    "PKCS7_MESSAGE_PARSER"
    "X509_CERTIFICATE_PARSER"
    "CRYPTO_USER"
    "CRYPTO_USER_API"

    # ext4 and virtio-fs preserve filenames as byte strings and do not use the
    # legacy filesystem charset tables. x86 ACPI selects the small NLS core,
    # but no shipped filesystem consumes either table.
    "NLS_UTF8"
    "NLS_ASCII"

    # dm-verity needs SHA-2 and CRC; TLS is implemented in userspace. Drop
    # legacy and foreign cipher families that no mvm kernel path consumes.
    "CRYPTO_DES"
    "CRYPTO_SM4"
    "CRYPTO_SM3"
    "CRYPTO_CAMELLIA"
    "CRYPTO_SERPENT"
    "CRYPTO_TWOFISH"
    "CRYPTO_ARIA"
    "CRYPTO_BLOWFISH"
    "CRYPTO_CAST5"
    "CRYPTO_CAST6"
    "CRYPTO_SEED"
    "CRYPTO_TEA"
    "CRYPTO_KHAZAD"
    "CRYPTO_ANUBIS"
    "CRYPTO_WP512"
    "CRYPTO_FCRYPT"
    "CRYPTO_STREEBOG"
    "CRYPTO_MD4"
    "CRYPTO_SM4_GENERIC"
    "CRYPTO_SM3_GENERIC"
    "CRYPTO_SM3_ARM64_CE"

    # Only gzip-compressed initramfs artifacts are shipped.
    "RD_BZIP2"
    "RD_LZMA"
    "RD_XZ"
    "RD_LZO"
    "RD_LZ4"
    "RD_ZSTD"

    # The final boot image is stripped, and no guest uses BPF CO-RE. Avoid the
    # build-time DWARF/BTF pass as well as its compile-time and closure cost.
    "DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT"
    "DEBUG_INFO_DWARF5"
    "DEBUG_INFO_DWARF4"
    "DEBUG_INFO_BTF"

    # Kernel debug instrumentation a sealed workload guest has no reader for:
    # nothing collects a stack-depth report out of it, and a W+X finding there
    # would be a fact about the image we built rather than about anything the
    # guest did.
    #
    # This buys size, NOT boot time, and the distinction is recorded here
    # because the console log makes it look otherwise. Their messages sit on
    # the two largest inter-timestamp gaps of an x86_64 guest boot — `x86/mm:
    # Checked W+X mappings` twice for ~71 ms, `used greatest stack depth` for
    # ~43 ms — which reads as a third of guest boot waiting to be reclaimed.
    # It is not. Measured on the Linux/Firecracker host, 12 launches per arm:
    # dispatch window 495.5 ms with them on and 504.0 ms with them off,
    # `driver_boot` 435.7 ms against 436.8 ms. No change beyond noise.
    #
    # The gap before a console line is not the cost of the work that line
    # names; on a serial console it is dominated by emitting the output before
    # it. Do not size a kernel change from those gaps — measure the launch.
    "DEBUG_WX"
    "DEBUG_STACK_USAGE"
  ]
  ++ pkgs.lib.optionals (kernelArch == "x86_64") [
    # x86 defconfig carries physical-PC, laptop, and foreign-hypervisor
    # support. Keep ACPI core, KVM paravirtualization, PCI, and the platform
    # 8250 console; none of these leaves exists in an mvm guest.
    "X86_PLATFORM_DEVICES"
    "HYPERV"
    "VMWARE_VMCI"
    "VMWARE_BALLOON"
    "VMWARE_PVSCSI"
    "EDAC"
    "VGA_CONSOLE"
    "VGA_ARB"
    "VGA_SWITCHEROO"
    "AGP"
    "ACPI_BATTERY"
    "ACPI_FAN"
    "ACPI_THERMAL"
    "ACPI_VIDEO"
    "ACPI_DOCK"
    "ACPI_AC"
    "ACPI_WMI"
    "ACPI_PROCESSOR"
    "ACPI_PROCESSOR_AGGREGATOR"
    "SERIAL_8250_PCI"
    "SERIAL_8250_EXTENDED"

    # Guest vCPUs have no host DVFS/ITMT topology. SCHED_MC_PRIO otherwise
    # selects the x86 pstate/CPPC/PCC chain and pulls CPU_FREQ + MAILBOX back in.
    "SCHED_MC_PRIO"
    "PCMCIA"
    "INTEL_IDLE"
    "CPU_IDLE"
    "THERMAL"
    "PERF_EVENTS_INTEL_RAPL"
    "X86_PKG_TEMP_THERMAL"
    "INTEL_POWERCLAMP"
    "INTEL_TCC_COOLING"
    "INTEL_SOC_DTS_THERMAL"
    "INTEL_PCH_THERMAL"
    "INTEL_HFI_THERMAL"
  ]
  ++ pkgs.lib.optionals (kernelArch == "arm64") [
    # The ARM vendor defconfig enables desktop scheduler autogrouping and all
    # AF_ALG userspace crypto families. Their selectors otherwise restore the
    # workload's required CGROUPS and CRYPTO_USER_API cuts.
    "SCHED_AUTOGROUP"
    # ARM guests expose no VGA device, error-reporting controller, or SCMI
    # firmware transport. PL011, virtio-console, and Firecracker's 8250 UART
    # are retained above.
    "VGA_ARB"
    "EDAC"
    "ARM_SCMI_PROTOCOL"
    "CRYPTO_USER_API_HASH"
    "CRYPTO_USER_API_SKCIPHER"
    "CRYPTO_USER_API_RNG"
    "CRYPTO_USER_API_RNG_CAVP"
    "CRYPTO_USER_API_AEAD"
    "CRYPTO_USER_API_ENABLE_OBSOLETE"
  ];

  baseDisables = [
    "MODULES" # everything built-in; no /lib/modules tree
    "MODULE_SIG" # NOP without MODULES; explicit
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
    "BPF_JIT"
    "BPF_JIT_DEFAULT_ON"
    # Force-dropped (not merely absent from enables) so `olddefconfig`
    # drops a defconfig default instead of leaving it `=y`.
    "EXT4_USE_FOR_EXT2" # nothing mounts ext2/ext3; ext4 only
    # POSIX message queues: guests talk over vsock; neither the agent, a
    # sealed workload, nor the nix-build sandbox open mq_*. Force-dropped to
    # delete the mq_open/mq_timedsend/… syscall surface (defconfig has it =y).
    "POSIX_MQUEUE"

    # Userspace-visible classes we don't need.
    "DRM"
    "SOUND"
    "USB"
    "WIRELESS"
    "BT"
    "FB"

    # ARM64 SoC platform clusters — disabling each parent cascades to
    # its PCIe host controllers, irqchip, clk, pinctrl, and SoC drivers
    # via olddefconfig. Leave ARCH_VIRT enabled.
    "ARCH_ACTIONS"
    "ARCH_AGILEX5"
    "ARCH_AIROHA"
    "ARCH_ALPINE"
    "ARCH_APPLE"
    "ARCH_BCM"
    "ARCH_BCM_IPROC"
    "ARCH_BCM2835"
    "ARCH_BCMBCA"
    "ARCH_BERLIN"
    "ARCH_BLAIZE"
    "ARCH_BRCMSTB"
    "ARCH_EXYNOS"
    "ARCH_HISI"
    "ARCH_INTEL_SOCFPGA"
    "ARCH_K3"
    "ARCH_KEEMBAY"
    "ARCH_LAYERSCAPE"
    "ARCH_LG1K"
    "ARCH_MEDIATEK"
    "ARCH_MESON"
    "ARCH_MMP"
    "ARCH_MVEBU"
    "ARCH_NPCM"
    "ARCH_NUVOTON"
    "ARCH_NXP"
    "ARCH_PENSANDO"
    "ARCH_PHYTIUM"
    "ARCH_QCOM"
    "ARCH_REALTEK"
    "ARCH_RENESAS"
    "ARCH_ROCKCHIP"
    "ARCH_S32"
    "ARCH_S5PV210"
    "ARCH_SEATTLE"
    "ARCH_SOPHGO"
    "ARCH_SPARX5"
    "ARCH_SPRD"
    "ARCH_STM32"
    "ARCH_SUNPLUS"
    "ARCH_SUNXI"
    "ARCH_SYNQUACER"
    "ARCH_TEGRA"
    "ARCH_TESLA_FSD"
    "ARCH_THUNDER"
    "ARCH_THUNDER2"
    "ARCH_UNIPHIER"
    "ARCH_VEXPRESS"
    "ARCH_VISCONTI"
    "ARCH_XGENE"
    "ARCH_ZYNQMP"

    # Storage / device classes that have no virtio path.
    "MTD"
    "PARPORT"
    "ATA"
    "SCSI"
    "INFINIBAND"
    "STAGING"
    "MEDIA_SUPPORT"

    # Device-driver *menus* with no hardware behind them under libkrun /
    # Firecracker. defconfig enables each as a whole menu, and disabling
    # the protocol stack alone (SOUND/WIRELESS/USB above) leaves the
    # device subtree compiling — the umbrella menu symbol gates the
    # drivers/<x>/ directory, so it must go too. Each parent cascades its
    # vendor subtree via olddefconfig. We carry only VIRTIO_NET; every
    # vendor NIC, WLAN, WWAN, and CAN driver is dead weight.
    "ETHERNET" # drivers/net/ethernet — keep NETDEVICES + VIRTIO_NET
    "WLAN"
    "WWAN"
    "CAN" # drivers/net/{wireless,wwan,can}
    "USB_SUPPORT" # USB host + gadget umbrella (CONFIG_USB only hit hosts)
    "HID_SUPPORT" # no virtio-input/HID; console is hvc0 + vsock
    "RC_CORE" # remote-control core + the keymap blob it builds
    "IIO" # industrial-I/O sensors
    "XEN" # never a Xen guest
    "MMC"
    "MMC_BLOCK" # no SD/eMMC behind virtio
    "REGULATOR"
    "POWER_SUPPLY"
    "THERMAL" # SoC power plumbing defconfig drags in
    "NEW_LEDS"
    "LEDS_CLASS"

    # Shrink batch 1 — leaf driver subsystems defconfig pulls in that a
    # headless virtio microVM never touches (console is hvc0 + vsock; no
    # firmware blobs, no input devices, no host sensors/watchdog). None are
    # transitive deps of the keep-set (virtio/vsock/ext4/overlay/dm-verity).
    "FW_LOADER" # request_firmware infra — no driver here loads blobs
    "FIREWIRE" # IEEE-1394 host stack
    "INPUT"
    "SERIO" # input core + PS/2 serial-IO; no virtio-input/keyboard
    "HWMON" # hardware monitoring sensors
    "WATCHDOG" # watchdog timers

    # Shrink batch 2 — self-contained subsystems + SoC bus/pin/PMIC drivers
    # defconfig drags in. The SoC `ARCH_*` clusters are already off; these are
    # the orthogonal driver menus that survive that. None are on the virtio
    # microVM boot path (no GPIO/I2C/pinctrl/PMIC hardware; FDT boot, not EFI;
    # not a ChromeOS board). Netfilter is NOT cut here — the builder kernel
    # needs it for its egress lockdown; the workload kernel drops it on its
    # own (workload.nix extraDisables), since base is shared by both.
    "CHROME_PLATFORMS" # ChromeOS embedded-controller drivers
    "EFI" # arm64 boots from the FDT, never the EFI stub/runtime
    "I2C" # no I2C buses behind virtio
    "GPIOLIB" # no GPIO controllers
    "PINCTRL" # SoC pin-mux
    "MFD_CORE" # multi-function (PMIC) device core

    # NOTE: PCI is intentionally NOT disabled — QEMU attaches virtio over PCI,
    # so PCI + VIRTIO_PCI are in the enable list above. libkrun/Firecracker/HVF
    # (MMIO) simply don't probe it. Dropping PCI here has broken boot on a
    # PCI-attached backend before.

    # Shrink batch 4 — more whole subsystems a sealed virtio microVM never
    # uses. Each cascades its family (drivers + helpers) via olddefconfig.
    "NFS_FS" # no network filesystems mounted
    "PHYLIB"
    "MDIO_DEVICE" # ethernet PHY mgmt — virtio-net has no PHY
    "VFIO" # device passthrough — unused (no PCI passthrough)
    "IPMI_HANDLER" # no BMC / out-of-band mgmt
    "CPU_FREQ"
    "CPU_IDLE" # no DVFS/idle-governor in a guest
    "SPI" # no SPI buses behind virtio (drops SPI flash/RTC/…)
    "NVMEM" # no on-board NVMEM providers
    "PWM" # no PWM controllers

    # Shrink batch 5 — subsystems the proven-minimal libkrun guest also drops.
    # Console stays: x86 keeps 8250; ARM keeps PL011; both keep virtio-console.
    # Only the SoC vendor UARTs go here. IOMMU is safe to drop — virtio rides
    # MMIO with direct DMA, no translation unit.
    "CORESIGHT" # ARM hardware trace/debug — never wired in a guest
    "VIRTUALIZATION" # a guest doesn't host nested VMs (drops KVM)
    "REMOTEPROC" # no remote-processor/RPMSG coprocessors
    "IOMMU_SUPPORT" # virtio-mmio uses direct DMA; no SMMU present
    "SERIAL_XILINX_PS_UART"
    "SERIAL_FSL_LPUART"
    "SERIAL_FSL_LINFLEXUART"
    "SERIAL_MCTRL_GPIO"
    "SERIAL_DEV_BUS" # SoC/serdev UARTs — console is PL011

    # Shrink batch 6 — block-device *clients* defconfig builds in that no mvm
    # backend can ever drive. Every guest boots one virtio-blk disk (`vda`,
    # kept via VIRTIO_BLK above); libkrun / HVF / Firecracker present no NBD
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
    "BLK_DEV_NBD" # network block device — no NBD server on any backend
    "BLK_DEV_NVME"
    "NVME_CORE" # NVMe — no NVMe controller behind virtio

  ]
  ++ requiredDisables
  ++ pkgs.lib.optionals (kernelArch == "arm64") [
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
  mkConfigfile =
    {
      extraEnables ? [ ],
      extraDisables ? [ ],
      requiredExtraDisables ? [ ],
    }:
    pkgs.buildPackages.runCommandCC "mvm-kernel-config"
      {
        nativeBuildInputs = with pkgs.buildPackages; [
          gnumake
          bison
          flex
          bc
          perl
          pkg-config
          openssl
        ];
        enableList = pkgs.lib.concatStringsSep " " (baseEnables ++ extraEnables);
        disableList = pkgs.lib.concatStringsSep " " (
          baseDisables ++ extraDisables ++ requiredExtraDisables
        );
        requiredDisableList = pkgs.lib.concatStringsSep " " (requiredDisables ++ requiredExtraDisables);
      }
      ''
        set -euo pipefail

        mkdir -p linux
        cp -a --reflink=auto ${kernelSourceTree}/. linux/
        cd linux
        chmod -R u+w .

        export ARCH=${kernelArch}
        export SHELL=${pkgs.buildPackages.bash}/bin/bash
        export CONFIG_SHELL=${pkgs.buildPackages.bash}/bin/bash

        # Linux Kconfig's `$(shell,...)` helper goes through `popen()`, which
        # hardwires `/bin/sh -c ...` instead of respecting PATH or Kbuild's
        # `CONFIG_SHELL`. The Nix build sandbox does not guarantee `/bin/sh`,
        # so provide one explicitly before the first `make defconfig` shell
        # probe (compiler/linker presence, cc-version, etc.).
        if [ ! -x /bin/sh ]; then
          mkdir -p /bin
          ln -s ${pkgs.buildPackages.bash}/bin/sh /bin/sh
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

        # Every audited cut must survive olddefconfig. A selector can silently
        # turn a disabled symbol back on; fail here instead of publishing a
        # kernel that only appears to have shed the subsystem.
        required_reverted=""
        for s in $requiredDisableList; do
          if grep -q "^CONFIG_$s=y\$" .config; then
            required_reverted="$required_reverted $s"
          fi
        done
        if [ -n "$required_reverted" ]; then
          echo "ERROR: required kernel disables were reverted by olddefconfig:$required_reverted" >&2
          exit 1
        fi

        # Report older best-effort disables that olddefconfig re-enabled through
        # a selector. These are leads for the next subtraction pass.
        reverted=""
        for s in $disableList; do
          if grep -q "^CONFIG_$s=y\$" .config; then
            reverted="$reverted $s"
          fi
        done
        if [ -n "$reverted" ]; then
          echo "NOTE: requested kernel disables were reverted by olddefconfig:$reverted" >&2
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
  mkKernel =
    {
      extraEnables ? [ ],
      extraDisables ? [ ],
      requiredExtraDisables ? [ ],
    }:
    (pkgs.linuxManualConfig {
      src = kernelSourceTree;
      version = kernelVersion;
      modDirVersion = kernelVersion;
      configfile = mkConfigfile {
        inherit extraEnables extraDisables requiredExtraDisables;
      };
      allowImportFromDerivation = false;
    }).overrideAttrs
      (old: pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isx86_64 {
        # nixpkgs installs only the compressed image: on x86_64 that is
        # `bzImage`, and nothing here ever emitted an ELF. Every consumer then
        # copied the bzImage to a file named `vmlinux`, which is the name
        # Firecracker's loader is documented against — and its x86_64 loader
        # takes an uncompressed ELF and nothing else. A release built this way
        # publishes a kernel that fails with "Invalid Elf magic number" before
        # init runs, which is what v0.17.0 shipped.
        #
        # The ELF is not lost, only compressed inside the bzImage, and the
        # kernel tree ships the extractor for exactly this. Emit it beside the
        # bzImage so the format is available rather than inferred from a name.
        nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
          pkgs.buildPackages.gzip
          pkgs.buildPackages.xz
          pkgs.buildPackages.lz4
          pkgs.buildPackages.zstd
          pkgs.buildPackages.lzop
          pkgs.buildPackages.binutils
        ];
        postInstall = (old.postInstall or "") + ''
          bash ${kernelSourceTree}/scripts/extract-vmlinux "$out/bzImage" > "$out/vmlinux"
          magic=$(od -An -tx1 -N4 "$out/vmlinux" | tr -d ' \n')
          if [ "$magic" != "7f454c46" ]; then
            echo "ERROR: extract-vmlinux did not yield an ELF (magic=0x$magic)." >&2
            echo "Firecracker's x86_64 loader takes an uncompressed ELF vmlinux only." >&2
            exit 1
          fi
        '';
      });

in
{
  inherit
    kernelArch
    kernelVersion
    baseEnables
    baseDisables
    mkConfigfile
    mkKernel
    ;
}
