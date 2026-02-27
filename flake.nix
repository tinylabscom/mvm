{
  description = "mvm — Firecracker microVM development tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, microvm, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Rust 1.85+ for edition 2024.
        rustToolchain = pkgs.rust-bin.stable.latest.minimal;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # mvm guest agent — vsock management agent for all mvm microVMs.
        mvm-guest-agent = import ./nix/modules/guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./.;
        };
      in {
        # ── User-facing API ──────────────────────────────────────────
        #
        # mvm.lib.<system>.mkGuest { name, modules, hypervisor? }
        #
        # Builds a NixOS microVM guest image producing:
        #   $out/vmlinux       — uncompressed kernel for Firecracker
        #   $out/initrd        — initial ramdisk (NixOS stage-1)
        #   $out/rootfs.ext4   — ext4 root filesystem image
        #   $out/toplevel-path — NixOS closure reference
        #   $out/bin/          — runner scripts (when microvm.nix provides them)
        #
        lib.mkGuest = { name, modules ? [], hypervisor ? "firecracker" }:
          let
            eval = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = { inherit mvm-guest-agent; };
              modules = [
                microvm.nixosModules.microvm
                ./nix/modules/mvm-guest.nix
                ./nix/modules/guest-agent.nix
                {
                  microvm.hypervisor = hypervisor;
                  # mvm builds a single ext4 rootfs containing the full NixOS
                  # closure (/nix/store included).  Disable microvm.nix's default
                  # separate nix-store volume — it would add a mount for
                  # /dev/disk/by-label/nix-store that doesn't exist.
                  microvm.writableStoreOverlay = null;
                }
              ] ++ modules;
            };
            cfg = eval.config;
            kernel = cfg.boot.kernelPackages.kernel;

            # Build an ext4 rootfs from the full NixOS system closure.
            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ cfg.system.build.toplevel ];
              volumeLabel = "nixos";
              populateImageCommands = ''
                mkdir -p ./files/etc ./files/sbin
                ln -s ${cfg.system.build.toplevel} ./files/etc/system-toplevel
                ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init
                # Relative symlink for initrd switch_root resolution.
                ln -s .${cfg.system.build.toplevel}/init ./files/init
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
            cp "${cfg.system.build.initialRamdisk}/initrd" "$out/initrd"

            # Rootfs — ext4 image for Firecracker
            cp "${rootfs}" "$out/rootfs.ext4"

            # Record what system closure this was built from
            echo "${cfg.system.build.toplevel}" > "$out/toplevel-path"

            # Runner script (for microvm.nix runner backend)
            runner="${cfg.microvm.declaredRunner or ""}"
            if [ -n "$runner" ] && [ -d "$runner/bin" ]; then
              cp -r "$runner/bin" "$out/bin"
            fi
          '';

        # ── NixOS modules (for advanced users) ──────────────────────
        nixosModules = {
          mvm-guest = ./nix/modules/mvm-guest.nix;
          guest-agent = ./nix/modules/guest-agent.nix;
          guest-integrations = ./nix/modules/guest-integrations.nix;
        };

        packages.mvm-guest-agent = mvm-guest-agent;
      }
    );
}
