{
  # Standalone, publishable view of the slim microVM kernel.
  #
  # The builder-VM flake consumes the same `base.nix` / `builder.nix` /
  # `workload.nix` through its `workspaceRoot` import (so the kernel
  # resolves under the `path:` URL the libkrun builder VM fetches). This
  # flake is an ADDITIVE publish surface: it builds the same kernels as
  # first-class outputs plus the size metrics and the content-addressed
  # artifact manifest a release workflow uploads. It does not change how
  # the builder VM gets its kernel — both import the identical files, so
  # the derivations match.
  description = "mvm slim microVM kernel — publishable vmlinux / configfile / metrics / manifest";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # Reusable accessor — callers pass their own pkgs so the nixpkgs
      # pin stays with the consumer, not duplicated here.
      lib.kernelBase = pkgs: import ./base.nix { inherit pkgs; };

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          base = import ./base.nix { inherit pkgs; };
          workload = import ./workload.nix { inherit pkgs base; };
          builder = import ./builder.nix { inherit pkgs base; };

          # "aarch64" / "x86_64" for the published filenames (matches the
          # per-arch checksum-manifest naming the downloader verifies).
          arch = nixpkgs.lib.head (nixpkgs.lib.splitString "-" system);
          kver = base.kernelVersion;

          # vmlinux size + built-in symbol count. Pure measurement; the
          # number is what the "tiny kernel" claim is anchored to.
          metricsFor =
            name: kpkg: cfg:
            pkgs.runCommand "mvm-kernel-metrics-${name}-${arch}" { nativeBuildInputs = [ pkgs.gzip ]; } ''
              mkdir -p $out
              img=$(ls ${kpkg}/Image ${kpkg}/bzImage ${kpkg}/vmlinux 2>/dev/null | head -1)
              y=$(grep -c '=y$' ${cfg})
              raw=$(stat -c%s "$img")
              comp=$(gzip -c "$img" | wc -c)
              printf '{"vmlinux_bytes":%d,"vmlinux_compressed_bytes":%d,"y_symbol_count":%d}\n' \
                "$raw" "$comp" "$y" > $out/metrics.json
              ln -s ${cfg} $out/config
            '';

          resolvedConfigs =
            pkgs.runCommand "mvm-kernel-resolved-configs-${arch}" { } ''
              mkdir -p $out
              ln -s ${builder.passthru.configfile} $out/builder.config
              ln -s ${workload.passthru.configfile} $out/workload.config
            '';

          workloadSizeopt = import ./workload.nix {
            inherit pkgs base;
            optimizeForSize = true;
          };

          # Content-addressed identity: (kernel_version, config_hash,
          # artifact_hash). Field names mirror the KernelArtifactId type
          # the host resolves a kernel pin against. The checksums file
          # follows the existing hash-verified download format.
          # The file the consumer's loader actually takes. `metricsFor` above
          # deliberately keeps the `ls` probe — it measures the compressed
          # image the tiny-kernel claim is anchored to, and the ELF is ~20 MB
          # against the bzImage's ~8 MB, so repointing it would silently
          # restate that claim.
          #
          # This manifest is different: `update.rs::download_kernel` verifies a
          # fetched `vmlinux-<arch>-<variant>` against it and hands the result
          # to a backend as a `vmlinux`. On x86_64 `ls` sorts `bzImage` ahead of
          # `vmlinux`, so the manifest recorded a bzImage's digest under the
          # name `vmlinux` — and since the kernel package now carries both, it
          # picked the wrong one of two present files. The download then
          # verifies green and boots nothing, which is #2594 again: a hash
          # proves provenance and says nothing about format.
          manifestKernelFile = if pkgs.stdenv.hostPlatform.isAarch64 then "Image" else "vmlinux";
          manifestFor =
            kpkg: cfg:
            pkgs.runCommand "mvm-kernel-manifest-${arch}" { } ''
              mkdir -p $out
              img=${kpkg}/${manifestKernelFile}
              if [ ! -f "$img" ]; then
                echo "ERROR: kernel ${kpkg} produced no ${manifestKernelFile}." >&2
                exit 1
              fi

              # Assert the format the name promises, so a manifest cannot
              # publish a digest for bytes the loader will refuse.
              magic0=$(${pkgs.coreutils}/bin/od -An -tx1 -N4 "$img" | tr -d ' \n')
              magic56=$(${pkgs.coreutils}/bin/od -An -c -j56 -N4 "$img" | tr -d ' \n')
              ${
                if pkgs.stdenv.hostPlatform.isAarch64 then ''
                if [ "$magic56" != "ARMd" ]; then
                  echo "ERROR: $img is not an arm64 Image (magic@56='$magic56', want 'ARMd')." >&2
                  exit 1
                fi
                '' else ''
                if [ "$magic0" != "7f454c46" ]; then
                  echo "ERROR: $img is not an ELF kernel (magic@0=0x$magic0, want 0x7f454c46)." >&2
                  echo "The manifest names this artifact 'vmlinux', and Firecracker's x86_64" >&2
                  echo "loader takes an uncompressed ELF only. Publishing a bzImage digest" >&2
                  echo "under that name verifies green and boots nothing." >&2
                  exit 1
                fi
                ''
              }

              ch=$(sha256sum ${cfg} | cut -d' ' -f1)
              ah=$(sha256sum "$img" | cut -d' ' -f1)
              printf '{"kernel_version":"%s","config_hash":"%s","artifact_hash":"%s"}\n' \
                "${kver}" "$ch" "$ah" > $out/kernel-${arch}.json
              printf '%s  vmlinux\n' "$ah" > $out/kernel-${arch}-checksums-sha256.txt
            '';
        in
        {
          workload-vmlinux = workload;
          builder-vmlinux = builder;
          workload-configfile = workload.passthru.configfile;
          builder-configfile = builder.passthru.configfile;
          resolved-configs = resolvedConfigs;
          builder-metrics = metricsFor "builder" builder builder.passthru.configfile;
          workload-metrics = metricsFor "workload" workload workload.passthru.configfile;
          metrics = metricsFor "workload" workload workload.passthru.configfile;
          workload-sizeopt-vmlinux = workloadSizeopt;
          workload-sizeopt-configfile = workloadSizeopt.passthru.configfile;
          workload-sizeopt-metrics =
            metricsFor "workload-sizeopt" workloadSizeopt workloadSizeopt.passthru.configfile;
          artifact-manifest = manifestFor workload workload.passthru.configfile;
        }
      );
    };
}
