{
  description = "OpenClaw microVM template for mvm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Rust 1.85+ needed for edition 2024.
        rustToolchain = pkgs.rust-bin.stable.latest.minimal;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # mvm guest agent — vsock management agent for all mvm microVMs.
        # Built from the workspace, only the guest-agent binary.
        mvm-guest-agent = import ../../nix/modules/guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ../../.;
        };

        # Build a NixOS guest and package kernel + initrd + rootfs for Firecracker.
        #
        # The output derivation contains:
        #   $out/vmlinux     — uncompressed kernel for Firecracker
        #   $out/initrd      — initial ramdisk (NixOS stage-1 → activation → systemd)
        #   $out/rootfs.ext4 — ext4 root filesystem image
        #
        # At runtime, mvm mounts per-tenant config and secrets as additional
        # Firecracker drives (labeled mvm-config and mvm-secrets). The guest
        # NixOS config (baseline.nix) mounts these by label.
        mkGuest = name: modules:
          let
            eval = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = { inherit mvm-guest-agent; };
              modules = [
                ../../nix/modules/guest-agent.nix
                ./guests/baseline.nix
              ] ++ modules;
            };
            cfg = eval.config;

            kernel = cfg.boot.kernelPackages.kernel;

            # Build an ext4 rootfs from the full NixOS system closure.
            rootfs = pkgs.callPackage (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ cfg.system.build.toplevel ];
              volumeLabel = "nixos";
              populateImageCommands = ''
                mkdir -p ./files/etc
                ln -s ${cfg.system.build.toplevel} ./files/etc/system-toplevel
                mkdir -p ./files/sbin
                ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init

                # NixOS stage-1 (initrd) expects stage-2 init at /init.
                # Use a relative symlink so the initrd can verify the file exists
                # before switch_root (absolute symlinks can't be followed from
                # the initrd because the rootfs is mounted at /mnt-root/).
                ln -s .${cfg.system.build.toplevel}/init ./files/init

                # Markers for the systemd-based initrd.
                # initrd-find-nixos-closure reads NIXOS_CLOSURE as a plain text
                # path (avoiding absolute symlink resolution issues from /sysroot).
                echo "${cfg.system.build.toplevel}" > ./files/etc/NIXOS_CLOSURE
                touch ./files/etc/NIXOS
              '';
            };
          in
          pkgs.runCommand "mvm-${name}" {
            passthru = { inherit eval; config = cfg; };
          } ''
            mkdir -p $out

            # Kernel — Firecracker needs an uncompressed kernel image.
            # On x86_64 it's typically vmlinux; on aarch64 it's Image.
            if [ -f "${kernel}/vmlinux" ]; then
              cp "${kernel}/vmlinux" "$out/vmlinux"
            elif [ -f "${kernel}/Image" ]; then
              cp "${kernel}/Image" "$out/vmlinux"
            elif [ -f "${kernel}/bzImage" ]; then
              cp "${kernel}/bzImage" "$out/kernel"
            else
              echo "ERROR: cannot find kernel image in ${kernel}:" >&2
              ls -la "${kernel}/" >&2
              exit 1
            fi

            # Initrd — NixOS stage-1 handles activation and systemd setup.
            # Without this, systemd starts but can't find default.target.
            cp "${cfg.system.build.initialRamdisk}/initrd" "$out/initrd"

            # Rootfs — ext4 image for Firecracker
            cp "${rootfs}" "$out/rootfs.ext4"

            # Record what system closure this was built from
            echo "${cfg.system.build.toplevel}" > "$out/toplevel-path"
          '';

        gateway = mkGuest "gateway" [
          ./roles/gateway.nix
          ./guests/profiles/gateway.nix
        ];

        worker = mkGuest "worker" [
          ./roles/worker.nix
          ./guests/profiles/worker.nix
        ];
      in
      {
        packages = {
          tenant-gateway = gateway;
          tenant-worker = worker;
          default = worker;
        };

        checks = {
          gateway-eval = gateway.passthru.eval.config.system.build.toplevel;
          worker-eval = worker.passthru.eval.config.system.build.toplevel;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ git nixfmt-rfc-style nil ];
        };
      }
    );
}
