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
          kver = pkgs.linux_6_12.version;

          # vmlinux size + built-in symbol count. Pure measurement; the
          # number is what the "tiny kernel" claim is anchored to.
          metricsFor =
            kpkg: cfg:
            pkgs.runCommand "mvm-kernel-metrics-${arch}" { nativeBuildInputs = [ pkgs.gzip ]; } ''
              mkdir -p $out
              img=$(ls ${kpkg}/Image ${kpkg}/bzImage ${kpkg}/vmlinux 2>/dev/null | head -1)
              y=$(grep -c '=y$' ${cfg})
              raw=$(stat -c%s "$img")
              comp=$(gzip -c "$img" | wc -c)
              printf '{"vmlinux_bytes":%d,"vmlinux_compressed_bytes":%d,"y_symbol_count":%d}\n' \
                "$raw" "$comp" "$y" > $out/metrics.json
            '';

          # Content-addressed identity: (kernel_version, config_hash,
          # artifact_hash). Field names mirror the KernelArtifactId type
          # the host resolves a kernel pin against. The checksums file
          # follows the existing hash-verified download format.
          manifestFor =
            kpkg: cfg:
            pkgs.runCommand "mvm-kernel-manifest-${arch}" { } ''
              mkdir -p $out
              img=$(ls ${kpkg}/Image ${kpkg}/bzImage ${kpkg}/vmlinux 2>/dev/null | head -1)
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
          metrics = metricsFor workload workload.passthru.configfile;
          artifact-manifest = manifestFor workload workload.passthru.configfile;
        }
      );
    };
}
