# Builder-VM kernel — slim custom Linux 6.12.
#
# Built via `pkgs.linuxManualConfig` from a `.config` we generate
# inside this expression by running `make tinyconfig` on the
# kernel source, layering our `enables` / `disables` lists via
# `scripts/config`, and reconciling with `make olddefconfig`.
#
# Source of truth = the `enables` / `disables` lists below. No
# `.config` file is checked in.
#
# Why slim:
#   The stock `pkgs.linuxPackages.kernel` ships hundreds of `=m`
#   modules we never load. With a stock kernel, `mvm-host-vm-init`
#   has to modprobe each module it needs at the right time (overlay
#   before mount, vsock before socket(), iptables before rule
#   install) and the guest needs a `/lib/modules/<kver>/` tree
#   shipped alongside. Each `=m` is one more thing that can fail
#   silently. Slim build flips every feature we need to `=y`
#   (built-in); modprobes become no-ops, no module tree needed.
#
# Why no TSI patches:
#   Plan 87 / Plan 88 / ADR-055 moved builder-VM networking to
#   passt (Linux) / gvproxy (macOS) via virtio-net. The TSI
#   syscall-hijack path is no longer used in any builder VM.
#
# Why no `CONFIG_MODULES`:
#   `disables = [ "MODULES" ]` (plus disabling subsystems that
#   would otherwise force `=m`). Everything we need is `=y`. The
#   rootfs ships no `/lib/modules` tree; mkGuest's
#   `copy_module_closure` is unused for the builder-VM rootfs.
#
# Why no dm-verity / netfilter conntrack:
#   This is the *builder VM* kernel — a dev-tier image (ADR-002
#   dev-vs-prod tiers). It boots `root=/dev/vda ro` with no roothash
#   and never opens a dm-verity device; verified boot is a
#   workload-kernel concern, and the `veritysetup` the builder ships
#   only runs `format` (userspace Merkle hashing, no kernel `dm`
#   target). The egress lockdown (mvm-host-vm-init `network.rs`) is an
#   OUTPUT owner-match + default-DROP ruleset with no conntrack/state/
#   mark match. So MD/BLK_DEV_DM/DM_VERITY and the netfilter conntrack
#   symbols live in `disables`, not `enables`. Audited against
#   crates/mvm-host-vm-init.

{ pkgs }:

let
  kernelArch =
    if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86_64";

  # Built-in features the builder VM requires. Each entry becomes a
  # `scripts/config --enable CONFIG_<name>` invocation. `make
  # olddefconfig` fills in transitive dependencies, so the list
  # below names only what we directly touch.
  enables = [
    # virtio bus + transport
    "VIRTIO" "VIRTIO_MENU" "VIRTIO_PCI" "VIRTIO_MMIO"
    "VIRTIO_BLK" "VIRTIO_NET" "VIRTIO_CONSOLE" "VIRTIO_FS"
    "VSOCKETS" "VIRTIO_VSOCKETS" "VIRTIO_BALLOON"
    "HW_RANDOM" "HW_RANDOM_VIRTIO"
    "PCI" "PCI_MSI"

    # filesystems
    "BLOCK" "EXT4_FS" "OVERLAY_FS" "FUSE_FS"
    "TMPFS" "TMPFS_POSIX_ACL" "TMPFS_XATTR"
    "DEVTMPFS" "DEVTMPFS_MOUNT" "PROC_FS" "SYSFS"

    # process basics
    "BINFMT_ELF" "BINFMT_SCRIPT" "FUTEX" "EPOLL" "SIGNALFD"
    "EVENTFD" "TIMERFD" "POSIX_MQUEUE" "SYSVIPC"
    "MULTIUSER" "SYSCTL" "PRINTK" "PRINTK_TIME" "KALLSYMS" "BUG"
    "RTC_CLASS" "HIGH_RES_TIMERS" "NO_HZ_IDLE"

    # namespaces + cgroups v2 + seccomp (nix build sandbox)
    "NAMESPACES" "UTS_NS" "IPC_NS" "USER_NS" "PID_NS" "NET_NS"
    "CGROUPS" "MEMCG" "BLK_CGROUP" "CGROUP_SCHED" "FAIR_GROUP_SCHED"
    "CGROUP_PIDS" "CGROUP_FREEZER" "CGROUP_DEVICE" "CGROUP_CPUACCT"
    "CPUSETS"
    "SECCOMP" "SECCOMP_FILTER"

    # net core
    "NET" "INET" "PACKET" "UNIX" "TCP_CONG_CUBIC"

    # iptables-legacy (egress lockdown, ADR-047 / Plan 73 B.2.y).
    # Only the OUTPUT owner-match + default-DROP ruleset is used
    # (mvm-host-vm-init `network.rs` install_egress_lockdown): no
    # conntrack/state/mark match, so those symbols are in `disables`.
    "NETFILTER" "NETFILTER_ADVANCED" "NETFILTER_XTABLES"
    "IP_NF_IPTABLES" "IP_NF_FILTER" "IP_NF_TARGET_REJECT"
    "NETFILTER_XT_MATCH_OWNER"

    # NLS (kept minimal — UTF-8 + ASCII only)
    "NLS" "NLS_UTF8" "NLS_ASCII"
  ];

  # Features `make defconfig` enables (or that `make olddefconfig` would
  # propagate in) and we explicitly do not want. `make defconfig` for
  # arm64 is the multi-platform vendor defconfig — it enables every
  # SoC family upstream supports, so the disables list has to be
  # aggressive to keep the build slim. Plan 95 §W3 — derive
  # additions empirically from `nix build .#kernel-configfile`.
  disables = [
    "MODULES"        # everything built-in; no /lib/modules tree
    "MODULE_SIG"     # NOP without MODULES; explicit
    "IPV6"           # builder VM has no v6 path

    # Confirmed-unused in the builder VM (audited against
    # crates/mvm-host-vm-init). Listed here, not merely absent from
    # `enables`, so `olddefconfig` actually drops them instead of
    # leaving a defconfig default `=y`. See the header "Why no
    # dm-verity / netfilter conntrack" note.
    "MD" "BLK_DEV_DM" "DM_VERITY"   # no dm-verity device opened; format-only
    "NF_CONNTRACK" "NF_DEFRAG_IPV4" # egress lockdown is owner-match +
    "NETFILTER_XT_MATCH_STATE"      # default-DROP only — no conntrack/
    "NETFILTER_XT_MATCH_CONNTRACK"  # state/mark match invoked
    "NETFILTER_XT_MARK"
    "EXT4_USE_FOR_EXT2"             # nothing mounts ext2/ext3; only ext4

    # Userspace-visible classes we don't need.
    "DRM" "SOUND" "USB" "WIRELESS" "BT" "FB"

    # Plan 95 §W3 — ARM64 SoC platform clusters. We boot only under
    # libkrun (Apple Silicon virt) or Firecracker (Linux KVM virt) —
    # never real SoC hardware. Disabling each parent symbol cascades
    # to its PCIe host controllers, irqchip, clk, pinctrl, and SoC
    # support drivers via `olddefconfig`. Leave `ARCH_VIRT` enabled.
    # First-pass list expanded after observing residual DTB compilation
    # in Stage 0 (microchip/sparx5, nuvoton/ma35d1, airoha/en7581).
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
  ];

  # `runCommandCC` (rather than `runCommand`) so the derivation runs
  # under `stdenv` proper — gcc + binutils available on PATH for
  # `scripts/basic/fixdep` and the rest of the kernel's host-side
  # tooling. `runCommand` uses `stdenvNoCC` by default and would
  # bail with `gcc: command not found` at the first `make tinyconfig`
  # invocation.
  configfile = pkgs.runCommandCC "mvm-builder-vm-kernel-config" {
    nativeBuildInputs = with pkgs; [
      gnumake bison flex bc perl pkg-config openssl
    ];
    enableList = pkgs.lib.concatStringsSep " " enables;
    disableList = pkgs.lib.concatStringsSep " " disables;
  } ''
    set -euo pipefail

    mkdir -p linux
    tar -xf ${pkgs.linux_6_12.src} -C linux --strip-components=1
    cd linux
    chmod -R u+w .

    export ARCH=${kernelArch}

    # `scripts/config` ships with `#!/usr/bin/env bash` shebang.
    # Nix sandbox has no `/usr/bin/env`. `patchShebangs` rewrites
    # the shebang to the absolute path of the sandbox's bash.
    patchShebangs scripts/

    # Base on `defconfig` not `tinyconfig`. tinyconfig is "everything
    # off except what the kernel literally cannot start without" —
    # for arm64 it strips arch_timer, GIC, OF/devicetree, PL011
    # serial, TTY, HVC_DRIVER, and the rest of the platform support
    # libkrun's virtual hardware emits. Result: a kernel image that
    # builds cleanly but emits zero bytes on hvc0 because nothing
    # below the userspace stack is wired up.
    #
    # `defconfig` is the upstream arm64/x86_64 recommended starting
    # point — boots on real hardware, builds in 3-5 min, and we
    # carve it down via the `disables` list below.
    make defconfig

    for s in $enableList; do
      ./scripts/config --enable "$s"
    done
    for s in $disableList; do
      ./scripts/config --disable "$s"
    done

    make olddefconfig

    cp .config $out
  '';

in
# `allowImportFromDerivation = false` keeps `nix flake check --no-build`
# (CI lane "Nix flake check (Linux eval)") working: `--no-build` will
# not realize the configfile derivation, and any IFD from linuxManualConfig
# would then fail with `path '…-kernel-config.drv' is not valid`. We pass
# `version`/`modDirVersion`/`src` explicitly from `pkgs.linux_6_12`, so
# the configfile content isn't needed at eval time — only at build time.
pkgs.linuxManualConfig {
  inherit (pkgs.linux_6_12) src version modDirVersion;
  inherit configfile;
  allowImportFromDerivation = false;
}
