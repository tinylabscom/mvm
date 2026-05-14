{
  description = "mvm libkrun builder VM image — Linux kernel + ext4 rootfs with Nix + mvm-builder-init. Plan 71 W2.";

  # ── Why this flake exists ────────────────────────────────────────────
  #
  # The libkrun-backed `LibkrunBuilderVm` (`crates/mvm-build/src/
  # libkrun_builder.rs`, plan 71 W1) needs an image to boot. This
  # flake produces that artifact. It is *separate* from the existing
  # `nix/images/builder/flake.nix` (which is the dev-shell image
  # users SSH/console into) — Plan 71 W5 ("Cutover") renames the
  # paths to match the canonical CLAUDE.md layout
  # (`nix/images/builder-vm/` + `nix/images/dev-shell/`); W2 lands
  # the new flake alongside so the cutover is a path-rename rather
  # than a content rewrite.
  #
  # ── Scaffolding-pending-hardware-validation ─────────────────────────
  #
  # Per the plan's "Implementation discipline" — this PR ships the
  # flake structure with the documented package set and outputs, but
  # has *not* been validated against an actual `nix build` on a
  # Linux runner. The W2 acceptance gates (kernel + rootfs produced,
  # qemu-system-aarch64 smoke boots into `mvm-builder-init`, image
  # size budget ≤ 300 MiB compressed / ≤ 1.2 GiB uncompressed) land
  # with a follow-up PR that has access to a Linux + Nix runner.
  # Until that PR lands, downstream code (`find_builder_vm_flake`,
  # `download_builder_vm_image`, `LibkrunBuilderVm::run_build`'s
  # image-resolution step) is intentionally not wired up — the
  # libkrun crate's `Error::NotYetWired` and the builder's
  # `BuilderVmError::NotYetImplemented` keep the call sites failing
  # closed rather than half-booting an unvalidated artifact.
  #
  # ── Architecture: parallel to nix/images/builder/flake.nix ──────────
  #
  # Same path-input-free pattern: stage the workspace via
  # `builtins.path`, import `nix/lib/default.nix` directly with
  # `mvmSrc` pointing at the staged tree. Documented at length in
  # the sibling flake; only the package set + output shape differ
  # here.

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

      # Workspace staging — same dance as the sibling flake. The
      # filter excludes large/irrelevant dirs so `builtins.path`
      # doesn't store-copy `target/`, `.git`, worktrees, etc.
      workspaceRoot =
        let
          envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in
        if envPath != "" then /. + envPath else ../../..;
      workspace = builtins.path {
        path = workspaceRoot;
        name = "mvm-workspace";
        filter =
          path: _type:
          let
            base = baseNameOf path;
          in
          !(builtins.elem base [
            "target"
            ".git"
            "result"
            "node_modules"
            ".direnv"
            ".cargo"
            ".claude"
            ".worktrees"
          ])
          && !(nixpkgs.lib.hasPrefix "result-" base);
      };

      libFor = import (workspace + "/nix/lib") {
        inherit nixpkgs microvm;
        mvmSrc = workspace;
      };

      # Builder VM closure. Plan 71 W2 §"Inputs" lists exactly this
      # set: no iptables, no `procps` interactive bits, no `less`.
      # The libkrun builder VM is headless — there's no human shell
      # session — so anything past "Nix can build, the init can
      # report results, network is up enough for cache.nixos.org" is
      # dead weight in the rootfs.
      builderVmPackages = pkgs: with pkgs; [
        bash coreutils gnugrep gnused gawk findutils
        nix git gnumake curl jq
        e2fsprogs util-linux
        # udhcpc for network bring-up (`mvm-builder-init` invokes
        # this at W3 boot step 3).
        busybox
      ];

      # mvm-builder-init derivation — built per target system so the
      # binary runs on the VM's architecture (libkrun host can be
      # aarch64-darwin pulling an aarch64-linux artifact; same for
      # x86_64 cross).
      builderInitPkg = pkgs: pkgs.callPackage ../../packages/mvm-builder-init.nix {
        mvmSrc = workspace;
      };

      mkBuilderVmImage = system:
        let
          pkgs = import nixpkgs { inherit system; };
          initPkg = builderInitPkg pkgs;
          rootfs = (libFor { inherit system; }).mkGuest {
            name = "mvm-builder-vm";
            # The libkrun builder VM is headless: the kernel jumps
            # straight to `init=/sbin/mvm-builder-init` (see
            # `mvm_build::libkrun_builder::builder_kernel_cmdline()`).
            # The entrypoint here is never invoked — mkGuest requires
            # *some* value, so we point at bash for the off-chance a
            # human shells in via vsock for debugging.
            entrypoint.shell = "/bin/sh";
            packages = (builderVmPackages pkgs) ++ [ initPkg ];
          };
          kernelPkg = pkgs.linuxPackages.kernel;
          kernelFile =
            if pkgs.stdenv.hostPlatform.isAarch64
            then "Image"
            else "bzImage";
        in
        pkgs.runCommand "mvm-builder-vm-image-${system}"
          {
            passthru = {
              inherit rootfs;
              kernel = kernelPkg;
              builderInit = initPkg;
            };
          }
          ''
            mkdir -p $out

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

            # Emit manifest.json — sha256 + size for the kernel
            # and rootfs. Mirrors the dev-image's downstream
            # `*-checksums-sha256.txt` shape so the release pipeline
            # can verify both layers with one parser. Hex output
            # only; consumers do their own decoding.
            vmlinux_sha=$(${pkgs.coreutils}/bin/sha256sum $out/vmlinux | ${pkgs.coreutils}/bin/cut -d' ' -f1)
            rootfs_sha=$(${pkgs.coreutils}/bin/sha256sum $out/rootfs.ext4 | ${pkgs.coreutils}/bin/cut -d' ' -f1)
            vmlinux_size=$(${pkgs.coreutils}/bin/stat -c%s $out/vmlinux)
            rootfs_size=$(${pkgs.coreutils}/bin/stat -c%s $out/rootfs.ext4)

            cat > $out/manifest.json <<MANIFEST
            {
              "schema_version": 1,
              "system": "${system}",
              "kernel": {
                "filename": "vmlinux",
                "sha256": "$vmlinux_sha",
                "size_bytes": $vmlinux_size
              },
              "rootfs": {
                "filename": "rootfs.ext4",
                "sha256": "$rootfs_sha",
                "size_bytes": $rootfs_size
              }
            }
            MANIFEST
            chmod 0644 $out/manifest.json
          '';
    in
    {
      packages = forAllSystems (system: {
        default = mkBuilderVmImage system;
      });
    };
}
