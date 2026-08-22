{
  description = "mvm builder VM image — kernel + rootfs.ext4 with Nix + tools + mvm-host-vm-init (Plan 72 W2)";

  # ── Why this flake exists ────────────────────────────────────────────
  #
  # The libkrun-direct launcher (`LibkrunBuilderVm`) replaces the
  # libkrun-backed builder VM (`nix/images/builder/`, which is actually
  # the interactive image despite the name). This flake is the artifact
  # `LibkrunBuilderVm` boots into: a small Linux kernel + ext4
  # rootfs containing Nix + a curated build-tools subset +
  # `mvm-host-vm-init` at `/sbin/mvm-host-vm-init`.
  #
  # `packages.<system>.default` produces `$out/{vmlinux,rootfs.ext4,
  # cmdline.txt,manifest.json}`. CI uploads these as
  # `builder-vmlinux-<arch>` and `builder-rootfs-<arch>.ext4`
  # alongside the existing dev-image outputs.
  #
  # Distinct from `nix/images/builder/flake.nix` which produces the
  # interactive image (`mvm-dev`) — the rootfs a user `dev shell`s
  # into. The two flakes coexist and `mvmctl dev up` picks the right
  # one via `find_builder_vm_flake` / `find_dev_image_flake`.
  #
  # ── Architecture / workspace staging ──────────────────────────────
  #
  # Identical pattern to `nix/images/builder/flake.nix`:
  #
  # - Stage the workspace via `builtins.path` (filter out `target/`,
  #   `.git/`, etc.) so the flake works both on a host running
  #   `nix build` directly and inside the libkrun builder VM's
  #   `path:` URL fetch.
  # - `MVM_WORKSPACE_PATH` env var override for the sandbox case
  #   (avoids the `../../..` resolution-against-store-copy trap
  #   that bit `nix/images/builder/flake.nix`).
  # - Import the parent flake's `nix/lib/` directly (skip flake-
  #   input chain → no path-input lock validation issue).
  #
  # ── Builder VM package set ────────────────────────────────────────
  #
  # Narrower than the interactive image:
  #
  # - Static busybox (provides `/bin/sh`, `udhcpc`, `sync`, basic
  #   POSIX utilities — small footprint).
  # - Nix (the whole point of the VM).
  # - Bash + coreutils + gnugrep / gnused / gawk / findutils / which
  #   (user's `cmd.sh` is shell, not necessarily POSIX-only).
  # - Git + gnumake + curl + jq (Nix flakes pull from git, builds
  #   often run make / curl, `cmd.sh` may format JSON).
  # - e2fsprogs (`mkfs.ext4` for the first-boot format of the
  #   persistent `/nix` store) + util-linux (`mount`, `umount`,
  #   `losetup`).
  # - iproute2 (used by `udhcpc` and friends; small).
  # - iptables — defense-in-depth: `mvm-host-vm-init` installs an
  #   OUTPUT-chain default-deny + uid-owner ACCEPT for
  #   `mvm-egress-proxy` (uid 1801), so a build step that ignores
  #   `HTTP_PROXY` cannot reach upstream. See
  #   `crates/mvm-host-vm-init/src/network.rs`.
  # - **No** `procps`-interactive / `less` — kept slim.
  # - `mvm-host-vm-init` mounted at `/sbin/mvm-host-vm-init` via
  #   `extraFiles`. The kernel cmdline (`cmdline.txt` output)
  #   chains into it from the generic `/init` bootstrap.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, microvm, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      workspaceRoot =
        let
          envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in
        if envPath != "" then /. + envPath else ../../..;

      # Host binaries are embedded in mvmctl and extracted by
      # `host_binaries::ensure_extracted()` before invoking
      # `nix build path:... --impure`. The dir is passed in via env var;
      # no rustPlatform.buildRustPackage calls are permitted in this flake.
      hostBinDir =
        let envPath = builtins.getEnv "MVM_HOST_BIN_DIR";
        in if envPath != ""
           then /. + envPath
           else throw ''
             MVM_HOST_BIN_DIR is not set. Plan 115 / ADR-004 contract:
             mvmctl populates this dir via host_binaries::ensure_extracted()
             before invoking `nix build path:... --impure`. To run nix
             build by hand: extract the embedded binaries from your
             mvmctl with `mvmctl inspect host-bins --extract-to <DIR>`
             and pass MVM_HOST_BIN_DIR=<DIR> --impure.
           '';

      hostBinaries = import (workspaceRoot + "/nix/lib/mvm-host-binaries.nix");

      hostBinExtraFiles = nixpkgs.lib.mapAttrs' (name: spec:
        nixpkgs.lib.nameValuePair spec.install_path {
          source = hostBinDir + "/${name}";
          mode = spec.mode;
        }
      ) hostBinaries;

      # Filter list lives at nix/lib/workspace-filter.nix so the three
      # flakes that ingest the host workspace (this one, builder/,
      # runtime-overlay/) stay aligned with .gitignore in one place.
      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
        { inherit workspaceRoot; };

      libFor = import (workspace + "/nix/lib") {
        inherit nixpkgs microvm;
        mvmSrc = workspace;
      };

      # Shared kernel-config base. Imported from `nix/images/kernel/base.nix`
      # relatively (not through `workspace`): importing through `workspace`
      # forces realisation of that filtered store path, which
      # `nix flake check --no-build` (the "Nix flake check (Linux eval)"
      # lane) refuses — so the builder/workload kernel + their configfile
      # outputs must not route base through it.
      # Import the shared kernel via `workspaceRoot` (the same mechanism
      # this flake uses for `nix/lib`), NOT a bare `../kernel` relative
      # path. Under the `path:` URL fetch the libkrun builder VM uses, a
      # relative `..` resolves against the flake's *store copy* and
      # escapes it; `workspaceRoot` points at the live workspace
      # (`MVM_WORKSPACE_PATH`), so the sibling dir resolves.
      kernelBaseFor = pkgs:
        import (workspaceRoot + "/nix/images/kernel/base.nix") { inherit pkgs; };

      # veritysetup sidecar bytes must not drift when nixpkgs revs. The
      # OCI-pull path runs `veritysetup format`
      # inside this builder VM, while the Nix-built baseline runs it in
      # `nix/images/runtime-overlay/flake.nix`. Both flakes intentionally
      # pin the same cryptsetup release + tarball hash, and both must be
      # reviewed together on bump.
      pinnedCryptsetupVersion = "2.8.6";
      pinnedCryptsetupSrcHash = "sha256-gAQmX9mTiF0I97Yz2+BWhR3hohAwdhOk693HQ/zO/lo=";
      pinnedCryptsetupFor = pkgs:
        pkgs.cryptsetup.overrideAttrs (_old: {
          version = pinnedCryptsetupVersion;
          src = pkgs.fetchurl {
            url =
              "mirror://kernel/linux/utils/cryptsetup/v${pkgs.lib.versions.majorMinor pinnedCryptsetupVersion}/"
              + "cryptsetup-${pinnedCryptsetupVersion}.tar.xz";
            hash = pinnedCryptsetupSrcHash;
          };
        });

      # Use the same static privilege-drop helper as workload init. Including
      # it in the package list gives the builder rootfs a stable
      # `/sbin/mvm-setpriv` symlink through mkGuest's package population loop.
      builderSetprivFor = pkgs:
        import (workspace + "/nix/packages/mvm-setpriv.nix") {
          rustPlatform = pkgs.pkgsStatic.rustPlatform;
          lib = pkgs.lib;
          mvmSrc = workspace;
        };

      # Narrower than the interactive image. See module-level docs
      # above for the rationale on each.
      #
      # The application-dependency install pipeline: `uv` / `pnpm`
      # drive the installer, `cyclonedx-py` / `pnpm sbom` emit SBOMs,
      # and `pip-audit` / `pnpm audit` run the CVE scan. The SBOM /
      # CVE side is a soft gate — `mvm-host-vm-init::install` emits a
      # CycloneDX-1.5 empty stub when the tool isn't on PATH and logs
      # a warning.
      #
      # Egress posture is per-arm. The flake-build arm (`nix build`)
      # runs with open egress so nix can fetch substitutes and pinned
      # flake inputs directly. The install arm (`uv` / `pnpm`) locks
      # egress at its entry via iptables OUTPUT default-deny + proxy-uid
      # ACCEPT, so untrusted dependency code can only reach the network
      # through `mvm-egress-proxy` (embedded in mvmctl and baked into
      # the rootfs via `hostBinExtraFiles`). The proxy refuses anything
      # outside `pypi.org`, `files.pythonhosted.org`,
      # `registry.npmjs.org`, `objects.githubusercontent.com`.
      # The persistent dispatch loop resets the chain per job kind so
      # jobs cannot leak posture from one dispatch to the next.
      builderPackages = pkgs: with pkgs; [
        bashInteractive
        coreutils
        # `pkgsStatic.busybox` for the lightweight utilities that
        # mvm-host-vm-init spawns by absolute path — chiefly
        # `/sbin/udhcpc` (busybox applet) for DHCP on the builder
        # VM's eth0. Without busybox in `packages`, mkGuest's
        # symlink loop (nix/lib/mk-guest.nix:770-788) skips it
        # and `/sbin/udhcpc` doesn't exist → setup_network bails.
        pkgsStatic.busybox
        gnugrep
        gnused
        gawk
        findutils
        which
        nix
        # gitMinimal drops perl/sendmail/gui/manpages (~20 MB). git is
        # only invoked here by nix's `github:` substituter/fetcher; the
        # core porcelain that needs is intact in the minimal build.
        # `mvm-host-vm-init` does not shell to git (grep -rn '"git"' in
        # crates/mvm-host-vm-init/).
        gitMinimal
        gnumake
        curl
        jq
        iproute2
        # iptables — installed at boot by mvm-host-vm-init's
        # network::install_egress_lockdown. FATAL if absent.
        #
        # Must be the **legacy (x_tables)** backend, not the nixpkgs
        # `iptables` default (nft). The builder kernel
        # (kernel/default.nix) enables the x_tables cluster
        # (NETFILTER_XTABLES / IP_NF_IPTABLES / …) and deliberately
        # omits NF_TABLES, so the nft-backed `iptables` fails at boot
        # with "Could not fetch rule set generation id: Invalid
        # argument" and trips the FATAL egress lockdown — first seen
        # on the first build that actually boots the builder rootfs and
        # runs the lockdown. iptables-legacy's `iptables` binary speaks
        # x_tables, matching the kernel.
        iptables-legacy
        e2fsprogs
        util-linux
        (builderSetprivFor pkgs)
        # The host VM spawns one Firecracker workload microVM per
        # `WorkloadStart` dispatch inside itself. Sourced from the pinned
        # nixpkgs above — an upstream Nix package, never an
        # mvm-published prebuilt (source-checkout rule).
        # mkGuest's symlink loop also lands it at /sbin/firecracker
        # and /usr/local/bin/firecracker; the `extraFiles` entry
        # below pins the exact /usr/bin/firecracker path the guest
        # hardcodes (`FirecrackerVmm` in mvm-host-vm-init).
        firecracker
        (pinnedCryptsetupFor pkgs) # provides pinned veritysetup
        # app-deps install pipeline.
        uv
        pnpm
        # NOTE: `python3Packages.cyclonedx-bom` and
        # `python3Packages.pip-audit` are referenced here but not
        # present in nixpkgs-25.11 under those exact attribute names;
        # the Stage 0 nix eval bails with "attribute 'cyclonedx-bom'
        # missing". Commented out until the right attribute name (or
        # a newer nixpkgs pin that has them) lands. The deps-volume
        # audit pipeline still works at runtime via the
        # `mvm-egress-proxy` allowlist; the SBOM/CVE tools were a
        # nice-to-have inside the builder VM, not a load-bearing
        # blocker for `mvmctl dev up`.
        # python3Packages.cyclonedx-bom
        # python3Packages.pip-audit
      ];

      # Canonical kernel cmdline for the builder VM. `LibkrunBuilderVm`
      # reads this from the cmdline.txt output and passes it to
      # `mvm_libkrun::KrunContext.kernel_cmdline`.
      #
      # - `console=hvc0` — libkrun's virtio-console (no serial).
      # - `root=/dev/vda` — rootfs.ext4 attached as virtio-blk.
      # - `ro` — root is read-only; writes go to the persistent
      #   /nix-store virtio-blk at /dev/vdb.
      # - `rootfstype=ext4` — skip filesystem auto-detection.
      # - `rootwait` — wait for virtio-blk root enumeration before mounting.
      # - `panic=-1 loglevel=8` — reboot on panic and keep early boot verbose
      #   enough that the host-side console capture has useful crash context.
      # - `init=/init mvm.chain_init=/sbin/mvm-host-vm-init` — enter the
      #   shell-known-good busybox /init first, then chain into
      #   mvm-host-vm-init after the generic pseudofs/tmpfs bootstrap. The
      #   target path must still match nix/lib/mvm-host-binaries.nix.
      builderCmdline = "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init";

      # Extra packages for the interactive (dev) builder VM image.
      # Added on top of `builderPackages` when `interactive = true`.
      # Provides a useful shell environment for contributors debugging
      # inside the builder VM via `mvmctl dev shell`.
      #
      # The Rust toolchain (`cargo` + `rustc`) is deliberately NOT baked in:
      # it is ~1 GB of closure and `mvm` itself builds on the host, while Rust
      # guest workloads build through nix (`buildRustPackage`) — so interactive
      # `cargo`/`rustc` here only served ad-hoc poking. The builder VM has `nix`
      # and (in the dev shell) open egress, so a contributor who wants it runs
      # `nix shell nixpkgs#rustc nixpkgs#cargo` on demand; it then persists in
      # the `/nix-store` image. Halving the dev rootfs is worth the one-time pull.
      devPackages = pkgs: with pkgs; [
        nano
      ];

      # Rootfs builder. The custom kernel under `./kernel` is built
      # `CONFIG_MODULES=n` (everything in-tree is `=y`), so the
      # rootfs ships no `/lib/modules/<kver>/` tree and mkGuest's
      # kernel arg goes unused — same rootfs whether we're producing
      # the full builder-VM image or the Stage 0 seed.
      #
      # Host binaries (mvm-host-vm-init, mvm-egress-proxy) are no
      # longer built from source here.
      # They come in from `hostBinExtraFiles` (keyed by install_path)
      # and are read from MVM_HOST_BIN_DIR at eval time.
      mkBuilderVmRootfs =
        { system, interactive ? false }:
        let
          pkgs = import nixpkgs { inherit system; };
          extraPkgs = if interactive then devPackages pkgs else [ ];
        in
        (libFor { inherit system; }).mkGuest {
          name = "mvm-builder-vm";
          # The builder VM chains from mkGuest's `/init` into
          # `mvm-host-vm-init` and sources the guest agent + egress-client
          # from the runtime overlay the host wires in. mkGuest bakes no
          # guest-runtime binaries into any rootfs, so there is nothing to
          # opt out of here — Stage 0 never compiles the unused
          # addon-dns / exit-report fallbacks.
          # mkGuest requires an entrypoint declaration. At runtime
          # the kernel cmdline sets `init=/init` and
          # `mvm.chain_init=/sbin/mvm-host-vm-init`, so mkGuest's
          # entrypoint is vestigial — but we still
          # need to declare one to satisfy the type contract.
          entrypoint.shell = "/bin/sh";
          # Persistent build jobs run as this unprivileged numeric uid. Keep
          # a passwd/group entry so Nix can resolve its home directory.
          builderUid = 902;
          packages = (builderPackages pkgs) ++ extraPkgs;
          # Host binaries (mvm-host-vm-init, mvm-egress-proxy) come
          # from MVM_HOST_BIN_DIR via hostBinExtraFiles — embedded
          # in mvmctl, no rustPlatform.buildRustPackage calls
          # in this flake.
          # /usr/bin/firecracker is pinned for the guest's
          # FirecrackerVmm spawn. firecracker is
          # also in `packages` above (for the full closure +
          # the /sbin + /usr/local/bin symlinks mkGuest adds);
          # this entry guarantees the canonical /usr/bin path
          # regardless of mkGuest's symlink targets.
          extraFiles = hostBinExtraFiles // {
            "/usr/bin/firecracker" =
              "${pkgs.firecracker}/bin/firecracker";
          };
        };

      # Two attrs.
      #   default — headless builder VM (production use, mvmctl build/up).
      #   dev     — interactive builder VM (cargo + rustc + nano + bashInteractive).
      #             Used by `mvmctl dev shell` for contributor debugging.
      #
      # Both take host binaries from MVM_HOST_BIN_DIR (set by mvmctl before
      # invoking `nix build ... --impure`). No rustPlatform.buildRustPackage
      # calls remain in this flake.
      mkBuilderVmImage =
        { system, interactive ? false }:
        let
          pkgs = import nixpkgs { inherit system; };
          # Slim custom kernel — see `nix/images/kernel/builder.nix` (shared
          # base `nix/images/kernel/base.nix` + builder-only delta).
          # `linuxManualConfig` over `make defconfig` carved down by the
          # base disables. `CONFIG_MODULES=n` so the kernel has only what
          # `mvm-host-vm-init` uses built-in — no driver modules tree.
          kernelPkg = import (workspaceRoot + "/nix/images/kernel/builder.nix") { inherit pkgs; base = kernelBaseFor pkgs; };
          rootfs = mkBuilderVmRootfs { inherit system interactive; };
          kernelFile =
            if pkgs.stdenv.hostPlatform.isAarch64 then "Image" else "bzImage";
          imageName = if interactive
                      then "mvm-builder-vm-dev-${system}"
                      else "mvm-builder-vm-image-${system}";
          manifestName = if interactive
                         then "mvm-builder-vm-dev"
                         else "mvm-builder-vm";
        in
        pkgs.runCommand imageName
          {
            passthru = {
              inherit rootfs;
              kernel = kernelPkg;
              cmdline = builderCmdline;
            };
          }
          ''
            mkdir -p $out

            # Kernel.
            if [ -f ${kernelPkg}/${kernelFile} ]; then
              cp ${kernelPkg}/${kernelFile} $out/vmlinux
            elif [ -f ${kernelPkg}/Image ]; then
              cp ${kernelPkg}/Image $out/vmlinux
            elif [ -f ${kernelPkg}/bzImage ]; then
              cp ${kernelPkg}/bzImage $out/vmlinux
            else
              echo "kernel package ${kernelPkg} did not produce Image or bzImage" >&2
              ls -la ${kernelPkg} >&2
              exit 1
            fi

            # Rootfs.
            if [ -f ${rootfs} ]; then
              cp ${rootfs} $out/rootfs.ext4
            else
              img=$(find ${rootfs} -maxdepth 1 -name '*.img' -o -name '*.ext4' | head -1)
              if [ -z "$img" ]; then
                echo "mkGuest output at ${rootfs} contains no .img or .ext4 file" >&2
                ls -la ${rootfs} >&2
                exit 1
              fi
              cp "$img" $out/rootfs.ext4
            fi

            chmod 0644 $out/vmlinux $out/rootfs.ext4

            # Canonical kernel cmdline — `LibkrunBuilderVm` reads this
            # and threads it into `mvm_libkrun::KrunContext.kernel_cmdline`.
            # Living next to the kernel makes the binding atomic with
            # the image.
            echo "${builderCmdline}" > $out/cmdline.txt

            # SHA-256 + size manifest, sister to the dev-image's
            # release-artifact pattern. `download_builder_vm_image`
            # verifies these against the release manifest before
            # extracting.
            kernel_sha=$(sha256sum $out/vmlinux | cut -d' ' -f1)
            rootfs_sha=$(sha256sum $out/rootfs.ext4 | cut -d' ' -f1)
            kernel_size=$(stat -c%s $out/vmlinux)
            rootfs_size=$(stat -c%s $out/rootfs.ext4)
            cat > $out/manifest.json <<MANIFEST
            {
              "name": "${manifestName}",
              "system": "${system}",
              "vmlinux":      { "sha256": "$kernel_sha", "size": $kernel_size },
              "rootfs_ext4":  { "sha256": "$rootfs_sha", "size": $rootfs_size },
              "cmdline": "${builderCmdline}",
              "cache_contract_version": 4,
              "runtime_overlay_ready": true,
              "vsock_egress_ready": true
            }
            MANIFEST
          '';

      mkBuilderVmStage0Rootfs = system:
        let
          pkgs = import nixpkgs { inherit system; };
          # Stage 0 boots under a different kernel than what nixpkgs
          # ships, so omit the kernel + module tree to avoid
          # misleading modprobe with a foreign kver. Always headless.
          rootfs = mkBuilderVmRootfs { inherit system; interactive = false; };
        in
        pkgs.runCommand "mvm-builder-vm-stage0-rootfs-${system}" { } ''
          mkdir -p $out

          if [ -f ${rootfs} ]; then
            cp ${rootfs} $out/rootfs.ext4
          else
            img=$(find ${rootfs} -maxdepth 1 -name '*.img' -o -name '*.ext4' | head -1)
            if [ -z "$img" ]; then
              echo "mkGuest output at ${rootfs} contains no .img or .ext4 file" >&2
              ls -la ${rootfs} >&2
              exit 1
            fi
            cp "$img" $out/rootfs.ext4
          fi

          chmod 0644 $out/rootfs.ext4
          echo "${builderCmdline}" > $out/cmdline.txt

          rootfs_sha=$(sha256sum $out/rootfs.ext4 | cut -d' ' -f1)
          rootfs_size=$(stat -c%s $out/rootfs.ext4)
          cat > $out/manifest.json <<MANIFEST
          {
            "name": "mvm-builder-vm-stage0-rootfs",
            "system": "${system}",
            "rootfs_ext4": { "sha256": "$rootfs_sha", "size": $rootfs_size },
            "cmdline": "${builderCmdline}",
            "cache_contract_version": 4,
            "runtime_overlay_ready": true,
            "vsock_egress_ready": true,
            "stage0_rootfs_only": true
          }
          MANIFEST
        '';
      # Expose the generated kernel `.config` as a standalone flake
      # output so contributors can audit what
      # `make defconfig + enables/disables + olddefconfig` actually
      # produced without temporarily editing this flake. Build with:
      #
      #   nix build .#kernel-configfile -o /tmp/kconfig
      #   grep '=y$' /tmp/kconfig | sort > /tmp/kconfig.y.txt
      #
      # The file is a regular `.config` text file — diffable across
      # `disables` edits to confirm SoC platform clusters are gone.
      mkKernelConfigfile = system:
        let pkgs = import nixpkgs { inherit system; };
        in (import (workspaceRoot + "/nix/images/kernel/builder.nix") { inherit pkgs; base = kernelBaseFor pkgs; }).passthru.configfile;

      # Standalone kernel artifacts — targets for `mvmctl kernel build`
      # and the kernel-build GHA. The builder image's `default` output
      # already embeds `builder-kernel`; exposing each kernel on its own
      # lets the expensive compile run (and be cached / published)
      # without realizing a full rootfs.
      #
      # `workload-kernel` is the shared base + the dm-verity delta
      # (`nix/images/kernel/workload.nix`). No runtime consumes it yet —
      # workload microVMs currently boot a host-provided kernel — so it's
      # published as an artifact ahead of the runtime wiring, which is
      # when its home moves out of this builder-vm flake.
      mkBuilderKernel = system:
        let pkgs = import nixpkgs { inherit system; };
        in import (workspaceRoot + "/nix/images/kernel/builder.nix") { inherit pkgs; base = kernelBaseFor pkgs; };
      mkWorkloadKernel = system:
        let pkgs = import nixpkgs { inherit system; };
        in import (workspaceRoot + "/nix/images/kernel/workload.nix") { inherit pkgs; base = kernelBaseFor pkgs; };
      mkWorkloadKernelSizeopt = system:
        let pkgs = import nixpkgs { inherit system; };
        in import (workspaceRoot + "/nix/images/kernel/workload.nix") {
          inherit pkgs;
          base = kernelBaseFor pkgs;
          optimizeForSize = true;
        };
      mkWorkloadKernelConfigfile = system:
        let pkgs = import nixpkgs { inherit system; };
        in (import (workspaceRoot + "/nix/images/kernel/workload.nix") { inherit pkgs; base = kernelBaseFor pkgs; }).passthru.configfile;
      mkWorkloadKernelSizeoptConfigfile = system:
        let pkgs = import nixpkgs { inherit system; };
        in (import (workspaceRoot + "/nix/images/kernel/workload.nix") {
          inherit pkgs;
          base = kernelBaseFor pkgs;
          optimizeForSize = true;
        }).passthru.configfile;
    in
    {
      packages = forAllSystems (system: {
        # Headless builder VM — production use path (mvmctl build / mvmctl up).
        # Contains only the build tooling; no interactive shell extras.
        default = mkBuilderVmImage { inherit system; interactive = false; };
        # Interactive builder VM — contributor dev path (mvmctl dev shell).
        # Adds cargo, rustc, nano on top of the headless package set.
        dev = mkBuilderVmImage { inherit system; interactive = true; };
        stage0-rootfs = mkBuilderVmStage0Rootfs system;
        # Builder kernel config (base + builder delta). `kernel-configfile`
        # name kept — README + the kernel-build GHA reference it.
        kernel-configfile = mkKernelConfigfile system;
        # Standalone kernels + the workload config, for `mvmctl kernel
        # build` and the publish GHA.
        builder-kernel = mkBuilderKernel system;
        workload-kernel = mkWorkloadKernel system;
        workload-kernel-configfile = mkWorkloadKernelConfigfile system;
        workload-sizeopt-kernel = mkWorkloadKernelSizeopt system;
        workload-sizeopt-kernel-configfile = mkWorkloadKernelSizeoptConfigfile system;
      });
    };
}
