{
  description = "mvm bundled default microVM image (Plan 158) — dev + prod (verity-sealed) variants";

  # Plan 158 Task 1. Both variants build-validated (aarch64-linux) via
  # nix-in-docker on the authoring host: `default`/`prod` emits
  # {vmlinux, rootfs.ext4, rootfs.verity, rootfs.roothash, mvm-meta.json} with a
  # valid 64-hex verity roothash and a `sealed:true, accessible:false,
  # overlayAware:true, rootlessEntrypoint:true` sidecar; `dev` emits
  # {vmlinux, rootfs.ext4, mvm-meta.json} with `sealed:false, accessible:true`.
  # The x86_64-linux build + the actual VM boot run in CI / on a runtime host.
  # See specs/plans/158-restore-default-microvm-image.md.
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

      # Same impure workspace-path override the sibling image flakes use.
      workspaceRoot =
        let envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in if envPath != "" then /. + envPath else ../../..;

      # Filtered workspace (mirrors builder-vm/runtime-overlay) for mkGuest.
      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
        { inherit workspaceRoot; };

      libFor = system:
        (import (workspace + "/nix/lib") {
          inherit nixpkgs microvm;
          mvmSrc = workspace;
        }) { inherit system; };

      # Workload kernel base — built-in DM_VERITY (no module tree), matching
      # builder-vm's `workload-kernel` (nix/images/builder-vm/flake.nix:480-486).
      # Imports the base through the raw workspaceRoot (not the filtered
      # `workspace`), mirroring builder-vm's relative `./kernel/base.nix` import.
      kernelBaseFor = pkgs:
        import (workspaceRoot + "/nix/images/builder-vm/kernel/base.nix")
          { inherit pkgs; };
      workloadKernelEnables = [ "MD" "BLK_DEV_DM" "DM_VERITY" ];
      mkWorkloadKernel = pkgs:
        (kernelBaseFor pkgs).mkKernel { extraEnables = workloadKernelEnables; };

      # Verity determinism — copied verbatim from runtime-overlay
      # (nix/images/runtime-overlay/flake.nix:180-203). MUST stay in lockstep
      # with `mvm_build::oci_to_rootfs::verity::VeritysetupOptions::default` and
      # `mvm-verity-init`'s DATA_BLOCK_SIZE.
      verityDataBlockSize = 1024;
      verityHashBlockSize = 4096;
      veritySalt = "0000000000000000000000000000000000000000000000000000000000000000";
      verityHashAlgorithm = "sha256";
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

      # Serialize mkGuest's `passthru.mvm` into the GuestSidecar wire shape
      # (crates/mvm-base/src/runtime_meta.rs, #[serde(rename_all="camelCase")]).
      sidecarJson = mvm:
        builtins.toJSON {
          inherit (mvm)
            name accessible sealed entrypointKind initSystem
            expectedBootMs agentBinary rootlessEntrypoint hypervisor overlayAware;
        };

      # One variant. `sealed = true` → prod (verity-sealed, rootless, no
      # do_exec); `sealed = false` → dev (accessible, exec-able).
      mkVariant = { system, sealed }:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = libFor system;
          kernelPkg = mkWorkloadKernel pkgs;
          kernelFile = if pkgs.stdenv.hostPlatform.isAarch64 then "Image" else "bzImage";
          imageName = if sealed then "mvm-default-microvm" else "mvm-default-microvm-dev";
          rootfsPkg = lib.mkGuest {
            name = imageName;
            # command form → sealed/prod; shell form → dev/accessible.
            entrypoint =
              if sealed
              then { command = [ "/bin/sleep" "infinity" ]; }
              else { shell = "/bin/sh"; };
            packages = [ pkgs.busybox ];
            # mkGuest's `kernel` arg supplies the in-rootfs module tree; the
            # workload kernel is module-free (DM_VERITY built-in), passed for
            # parity with a real workload image.
            kernel = kernelPkg;
          };
          meta = rootfsPkg.passthru.mvm;
        in
        pkgs.runCommand imageName
          {
            nativeBuildInputs = [ pkgs.e2fsprogs (pinnedCryptsetupFor pkgs) pkgs.coreutils ];
            # Expose the inner mkGuest rootfs as `passthru.rootfs` (the
            # convention builder-vm uses): the builder VM's nix-build cmd.sh
            # emits mvm-meta.json by eval'ing `<attr>.passthru.rootfs.passthru.mvm`
            # for runCommand-wrapped images (builder_vm_runtime.rs). Without
            # this the dev-build path would produce an image admission refuses.
            passthru = { rootfs = rootfsPkg; kernel = kernelPkg; };
          }
          (''
            set -euo pipefail
            mkdir -p $out

            # Kernel → vmlinux (same probe order as builder-vm).
            if   [ -f ${kernelPkg}/${kernelFile} ]; then cp ${kernelPkg}/${kernelFile} $out/vmlinux
            elif [ -f ${kernelPkg}/Image ];        then cp ${kernelPkg}/Image        $out/vmlinux
            elif [ -f ${kernelPkg}/bzImage ];      then cp ${kernelPkg}/bzImage      $out/vmlinux
            else echo "kernel ${kernelPkg} produced no Image/bzImage" >&2; ls -la ${kernelPkg} >&2; exit 1
            fi

            # Rootfs → rootfs.ext4 (mkGuest emits a single ext4).
            if [ -f ${rootfsPkg} ]; then
              cp ${rootfsPkg} $out/rootfs.ext4
            else
              img=$(find ${rootfsPkg} -maxdepth 1 \( -name '*.img' -o -name '*.ext4' \) | head -1)
              [ -n "$img" ] || { echo "mkGuest output ${rootfsPkg} has no .img/.ext4" >&2; ls -la ${rootfsPkg} >&2; exit 1; }
              cp "$img" $out/rootfs.ext4
            fi

            # Overlay-aware sidecar so `admit_overlay_aware` passes.
            cat > $out/mvm-meta.json <<'META'
            ${sidecarJson meta}
            META

            chmod 0644 $out/vmlinux $out/rootfs.ext4 $out/mvm-meta.json
          ''
          + nixpkgs.lib.optionalString sealed ''

            # dm-verity seal (prod only) — runtime-overlay recipe verbatim.
            touch $out/rootfs.verity
            veritysetup_out=$(
              veritysetup format \
                --data-block-size=${toString verityDataBlockSize} \
                --hash-block-size=${toString verityHashBlockSize} \
                --salt=${veritySalt} \
                --hash=${verityHashAlgorithm} \
                $out/rootfs.ext4 \
                $out/rootfs.verity
            )
            echo "$veritysetup_out" \
              | grep -i '^Root hash:' \
              | sed 's/^[Rr]oot [Hh]ash:[[:space:]]*//' \
              | tr 'A-F' 'a-f' \
              > $out/rootfs.roothash
            chmod 0644 $out/rootfs.verity $out/rootfs.roothash
          '');

    in
    {
      packages = forAllSystems (system: {
        # `default` = prod (the variant the release job ships).
        default = mkVariant { inherit system; sealed = true; };
        prod = mkVariant { inherit system; sealed = true; };
        dev = mkVariant { inherit system; sealed = false; };
      });
    };
}
