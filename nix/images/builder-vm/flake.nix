{
  description = "mvm builder VM image — kernel + rootfs.ext4 with Nix + tools + mvm-host-vm-init (Plan 72 W2)";

  # ── Why this flake exists ────────────────────────────────────────────
  #
  # Plan 72 (ADR-046) replaces the libkrun-backed builder VM
  # (`nix/images/builder/`, which is actually the dev-shell image
  # despite the name) with a libkrun-direct launcher
  # (`LibkrunBuilderVm`, Plan 72 W1). This flake is the artifact
  # `LibkrunBuilderVm` boots into: a small Linux kernel + ext4
  # rootfs containing Nix + a curated build-tools subset +
  # `mvm-host-vm-init` (Plan 72 W3) at `/sbin/mvm-host-vm-init`.
  #
  # `packages.<system>.default` produces `$out/{vmlinux,rootfs.ext4,
  # cmdline.txt,manifest.json}`. CI (Plan 72 W2 release-workflow
  # follow-up) uploads these as `builder-vmlinux-<arch>` and
  # `builder-rootfs-<arch>.ext4` alongside the existing dev-image
  # outputs.
  #
  # Distinct from `nix/images/builder/flake.nix` which produces the
  # dev-shell image (`mvm-dev`) — the rootfs a user `dev shell`s
  # into. The names will reshuffle in Plan 72 W6 hygiene; for now
  # the two flakes coexist and `mvmctl dev up` will pick the right
  # one via `find_builder_vm_flake` / `find_dev_image_flake`.
  #
  # ── Architecture / workspace staging ──────────────────────────────
  #
  # Identical pattern to `nix/images/builder/flake.nix`:
  #
  # - Stage the workspace via `builtins.path` (filter out `target/`,
  #   `.git/`, etc.) so the flake works both on a host running
  #   `nix build` directly and inside the libkrun builder VM's
  #   `path:` URL fetch (W4).
  # - `MVM_WORKSPACE_PATH` env var override for the sandbox case
  #   (avoids the `../../..` resolution-against-store-copy trap
  #   that bit `nix/images/builder/flake.nix` in Plan 72 W0).
  # - Import the parent flake's `nix/lib/` directly (skip flake-
  #   input chain → no path-input lock validation issue).
  #
  # ── Builder VM package set ────────────────────────────────────────
  #
  # Per Plan 72 §W2, narrower than the dev-shell image:
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
  # - iptables — Plan 73 Followup B.2.y / ADR-047 defense-in-
  #   depth: `mvm-host-vm-init` installs an OUTPUT-chain
  #   default-deny + uid-owner ACCEPT for `mvm-egress-proxy`
  #   (uid 1801), so a build step that ignores `HTTP_PROXY`
  #   cannot reach upstream. See
  #   `crates/mvm-host-vm-init/src/network.rs`.
  # - **No** `procps`-interactive / `less` per the plan's
  #   slimming directive.
  # - `mvm-host-vm-init` mounted at `/sbin/mvm-host-vm-init` via
  #   `extraFiles`. The kernel cmdline (`cmdline.txt` output)
  #   sets `init=/sbin/mvm-host-vm-init` so this becomes PID 1.

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

      # ADR-065 / Plan 115: host binaries are embedded in mvmctl and
      # extracted by `host_binaries::ensure_extracted()` before invoking
      # `nix build path:... --impure`. The dir is passed in via env var;
      # no rustPlatform.buildRustPackage calls are permitted in this flake.
      hostBinDir =
        let envPath = builtins.getEnv "MVM_HOST_BIN_DIR";
        in if envPath != ""
           then /. + envPath
           else throw ''
             MVM_HOST_BIN_DIR is not set. Plan 115 / ADR-065 contract:
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

      # Shared kernel-config base. Lives under `nix/lib/` (outside this
      # flake's source tree), so it's resolved through `workspace` — the
      # same mechanism as `libFor`, never a `../../lib` escape that
      # wouldn't exist in the flake's store copy.
      kernelBaseFor = pkgs:
        import (workspace + "/nix/lib/kernel/base.nix") { inherit pkgs; };

      # ADR-050 / issue #223 — veritysetup sidecar bytes must not drift
      # when nixpkgs revs. The OCI-pull path runs `veritysetup format`
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

      # Per Plan 72 §W2 — narrower than the dev-shell image.
      # See module-level docs above for the rationale on each.
      #
      # Plan 73 Followup B.2 adds the application-dependency
      # install pipeline (ADR-047): `uv` / `pnpm` drive the
      # installer, `cyclonedx-py` / `pnpm sbom` emit SBOMs, and
      # `pip-audit` / `pnpm audit` run the CVE scan. Each is
      # currently a soft gate — `mvm-host-vm-init::install`
      # emits a CycloneDX-1.5 empty stub when the SBOM / CVE
      # tool isn't on PATH and logs a warning. B.2.x will
      # hard-gate the SBOM + CVE side once the egress allowlist
      # lands.
      #
      # Plan 73 Followup B.2.x closed the egress side: the
      # builder VM runs `mvm-egress-proxy`, embedded in mvmctl
      # at its own build time (Plan 115 / ADR-065) and baked
      # into the rootfs via `hostBinExtraFiles` (read from
      # `MVM_HOST_BIN_DIR` under `--impure`) at the install
      # path declared in `nix/lib/mvm-host-binaries.nix`.
      # `mvm-host-vm-init::install::run_install` spawns it
      # before the installer + injects `HTTPS_PROXY` /
      # `HTTP_PROXY` on `uv` / `pnpm`'s env. The proxy refuses
      # anything outside ADR-047's four hostnames:
      # `pypi.org`, `files.pythonhosted.org`,
      # `registry.npmjs.org`, `objects.githubusercontent.com`.
      # Complementary iptables drop-rule defense-in-depth is
      # B.2.y (not in this slice).
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
        # network::install_egress_lockdown (Plan 73 Followup
        # B.2.y / ADR-047). FATAL if absent.
        iptables
        e2fsprogs
        util-linux
        # Plan 107 A2.1 — the host VM spawns one Firecracker
        # workload microVM per `WorkloadStart` dispatch inside
        # itself (Approach A, ADR-057). Sourced from the pinned
        # nixpkgs above — an upstream Nix package, never an
        # mvm-published prebuilt (ADR-046 source-checkout rule).
        # mkGuest's symlink loop also lands it at /sbin/firecracker
        # and /usr/local/bin/firecracker; the `extraFiles` entry
        # below pins the exact /usr/bin/firecracker path the guest
        # hardcodes (`FirecrackerVmm` in mvm-host-vm-init).
        firecracker
        (pinnedCryptsetupFor pkgs) # provides pinned veritysetup
        # Plan 73 Followup B.2 — app-deps install pipeline.
        uv
        pnpm
        # NOTE (Plan 72 W5.D unblock): `python3Packages.cyclonedx-bom`
        # and `python3Packages.pip-audit` are referenced here but not
        # present in nixpkgs-25.11 under those exact attribute names;
        # the Stage 0 nix eval bails with "attribute 'cyclonedx-bom'
        # missing". Commented out until the right attribute name (or
        # a newer nixpkgs pin that has them) lands. Plan 73's
        # deps-volume audit pipeline still works at runtime via the
        # `mvm-egress-proxy` allowlist; the SBOM/CVE tools were a
        # nice-to-have inside the builder VM, not a load-bearing
        # blocker for `mvmctl dev up`.
        # python3Packages.cyclonedx-bom
        # python3Packages.pip-audit
      ];

      # Canonical kernel cmdline for the builder VM. `LibkrunBuilderVm`
      # (Plan 72 W4) reads this from the cmdline.txt output and
      # passes it to `mvm_libkrun::KrunContext.kernel_cmdline`.
      #
      # - `console=hvc0` — libkrun's virtio-console (no serial).
      # - `root=/dev/vda` — rootfs.ext4 attached as virtio-blk.
      # - `ro` — root is read-only; writes go to the persistent
      #   /nix-store virtio-blk at /dev/vdb (Plan 72 W4 wires it).
      # - `rootfstype=ext4` — skip filesystem auto-detection.
      # - `init=/sbin/mvm-host-vm-init` — the `mvm-host-vm-init` binary
      #   as PID 1. Its install path (`/sbin/mvm-host-vm-init`) must
      #   match the manifest in nix/lib/mvm-host-binaries.nix; the
      #   binary is statically linked, so no dynamic loader is needed in
      #   this rootfs.
      builderCmdline = "console=hvc0 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init";

      # Extra packages for the interactive (dev) builder VM image.
      # Added on top of `builderPackages` when `interactive = true`.
      # Provides a useful shell environment for contributors debugging
      # inside the builder VM via `mvmctl dev shell`.
      devPackages = pkgs: with pkgs; [
        cargo
        rustc
        nano
      ];

      # Rootfs builder. The custom kernel under `./kernel` is built
      # `CONFIG_MODULES=n` (everything in-tree is `=y`), so the
      # rootfs ships no `/lib/modules/<kver>/` tree and mkGuest's
      # kernel arg goes unused — same rootfs whether we're producing
      # the full builder-VM image or the Stage 0 seed.
      # Plan 92 — `specs/plans/92-minimal-builder-vm-kernel.md`.
      #
      # ADR-065 / Plan 115: host binaries (mvm-host-vm-init,
      # mvm-egress-proxy) are no longer built from source here.
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
          # Skip the addon-dns bake. The builder VM's PID 1 is
          # `mvm-host-vm-init` (set via `extraFiles` + the
          # `init=/sbin/mvm-host-vm-init` kernel cmdline), so
          # mkGuest's initScript-side addon-dns activation block
          # never runs and the binary would just sit unused at
          # /usr/local/bin/mvm-addon-dns. The win is in Stage 0:
          # not building `mvm-addon-dns` removes a parallel rustc
          # run that competed with the kernel compile and pushed
          # the tmpfs-bound build into OOM territory.
          bakeAddonDns = false;
          # mkGuest requires an entrypoint declaration. At runtime
          # the kernel cmdline sets `init=/sbin/mvm-host-vm-init`,
          # so mkGuest's entrypoint is vestigial — but we still
          # need to declare one to satisfy the type contract.
          entrypoint.shell = "/bin/sh";
          packages = (builderPackages pkgs) ++ extraPkgs;
          # ADR-065 / Plan 115: host binaries
          # (mvm-host-vm-init, mvm-egress-proxy) come from
          # MVM_HOST_BIN_DIR via hostBinExtraFiles — embedded
          # in mvmctl, no rustPlatform.buildRustPackage calls
          # in this flake.
          # Plan 107 A2.1: /usr/bin/firecracker is pinned for
          # the guest's FirecrackerVmm spawn. firecracker is
          # also in `packages` above (for the full closure +
          # the /sbin + /usr/local/bin symlinks mkGuest adds);
          # this entry guarantees the canonical /usr/bin path
          # regardless of mkGuest's symlink targets.
          extraFiles = hostBinExtraFiles // {
            "/usr/bin/firecracker" =
              "${pkgs.firecracker}/bin/firecracker";
          };
        };

      # ADR-065 / Plan 115: two attrs.
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
          # Slim custom kernel — see `./kernel/default.nix` (shared
          # base `nix/lib/kernel/base.nix` + builder-only delta).
          # `linuxManualConfig` over `make defconfig` carved down by the
          # base disables. `CONFIG_MODULES=n` so the kernel has only what
          # `mvm-host-vm-init` uses built-in — no driver modules tree.
          # Plan 92 — `specs/plans/92-minimal-builder-vm-kernel.md`.
          kernelPkg = import ./kernel { inherit pkgs; base = kernelBaseFor pkgs; };
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

            # Canonical kernel cmdline — Plan 72 W4's
            # `LibkrunBuilderVm` reads this and threads it into
            # `mvm_libkrun::KrunContext.kernel_cmdline`. Living next
            # to the kernel makes the binding atomic with the image.
            echo "${builderCmdline}" > $out/cmdline.txt

            # SHA-256 + size manifest, sister to the dev-image's
            # release-artifact pattern. `download_builder_vm_image`
            # (Plan 72 W5) verifies these against the release
            # manifest before extracting.
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
              "cmdline": "${builderCmdline}"
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
            "stage0_rootfs_only": true
          }
          MANIFEST
        '';
      # Plan 95 W2 — expose the generated kernel `.config` as a
      # standalone flake output so contributors can audit what
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
        in (import ./kernel { inherit pkgs; base = kernelBaseFor pkgs; }).passthru.configfile;

      # Standalone kernel artifacts — targets for `mvmctl kernel build`
      # and the kernel-build GHA. The builder image's `default` output
      # already embeds `builder-kernel`; exposing each kernel on its own
      # lets the expensive compile run (and be cached / published)
      # without realizing a full rootfs.
      #
      # `workload-kernel` is the shared base alone (no builder infra). No
      # runtime consumes it yet — workload microVMs currently boot a
      # host-provided kernel — so it's published as an artifact ahead of
      # the runtime wiring, which is when its home moves out of this
      # builder-vm flake.
      # The workload kernel's one delta over the shared base: dm-verity
      # (Claim 3 — verified boot of the workload rootfs). The builder
      # force-drops these (it boots `ro`, no roothash); workloads keep
      # them. Shared between the kernel + its configfile output.
      workloadKernelEnables = [ "MD" "BLK_DEV_DM" "DM_VERITY" ];
      mkBuilderKernel = system:
        let pkgs = import nixpkgs { inherit system; };
        in import ./kernel { inherit pkgs; base = kernelBaseFor pkgs; };
      mkWorkloadKernel = system:
        let pkgs = import nixpkgs { inherit system; };
        in (kernelBaseFor pkgs).mkKernel { extraEnables = workloadKernelEnables; };
      mkWorkloadKernelConfigfile = system:
        let pkgs = import nixpkgs { inherit system; };
        in (kernelBaseFor pkgs).mkConfigfile { extraEnables = workloadKernelEnables; };
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
      });
    };
}
