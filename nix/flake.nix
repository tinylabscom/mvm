{
  description = "mvm — Firecracker microVM guest image builders";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
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

        # Shared kernel — built once, used by both mkGuest and mkNixosGuest.
        firecrackerKernel = import ./lib/firecracker-kernel-pkg.nix { inherit pkgs; };

        # mvm guest agent — vsock management agent for all mvm microVMs.
        mvm-guest-agent = import ./modules/guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./..;
        };

        busybox = pkgs.pkgsStatic.busybox;

        # Shared kernel copy logic.
        copyKernel = kernel: ''
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
        '';
      in {
        # ── mkGuest — Minimal guest (default) ─────────────────────
        #
        # mvm.lib.<system>.mkGuest {
        #   name, packages?, services?, healthChecks?, users?, hostname?
        # }
        #
        # Builds a microVM image with busybox init as PID 1 — no NixOS,
        # no systemd.  Handles mounts, networking, and service supervision
        # via respawn loops.  Uses the shared Firecracker kernel.
        #
        # Services support:
        #   command   — long-running process (supervised with respawn)
        #   preStart  — optional setup script (runs as root)
        #   env       — optional environment variables { KEY = "val"; }
        #   user      — optional user to run as (must exist in `users`)
        #   logFile   — optional log file path (default: /dev/console)
        #
        # Users:
        #   users.<name> = { uid?, group?, home? }
        #   Auto-assigns UIDs from 1000 if not specified.
        #
        # Produces:
        #   $out/vmlinux       — uncompressed kernel for Firecracker
        #   $out/rootfs.ext4   — ext4 root filesystem (no initrd)
        #
        lib.mkGuest = { name, packages ? [], services ? {}, healthChecks ? {},
                        users ? {}, hostname ? name }:
          let
            initScript = import ./lib/minimal-init.nix {
              inherit pkgs hostname users services healthChecks busybox;
              guestAgentPkg = mvm-guest-agent;
            };

            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ initScript mvm-guest-agent ] ++ packages;
              volumeLabel = "mvm";
              populateImageCommands = ''
                mkdir -p ./files/dev ./files/proc ./files/sys
                mkdir -p ./files/bin ./files/sbin
                mkdir -p ./files/etc/mvm/integrations.d
                mkdir -p ./files/tmp ./files/run ./files/var/lib ./files/var/run ./files/var/log
                mkdir -p ./files/root ./files/home
                mkdir -p ./files/mnt/config ./files/mnt/secrets ./files/mnt/data
                ln -s ${initScript} ./files/init
                ln -s ${busybox}/bin/sh ./files/bin/sh
              '';
            };
          in
          pkgs.runCommand "mvm-${name}" {} ''
            mkdir -p $out
            ${copyKernel firecrackerKernel}
            cp "${rootfs}" "$out/rootfs.ext4"
          '';

        # ── mkNixosGuest — Full NixOS guest (legacy) ─────────────
        #
        # mvm.lib.<system>.mkNixosGuest { name, modules? }
        #
        # Builds a full NixOS guest image with systemd.  Use this for
        # complex workloads that need NixOS modules (systemd services,
        # users, tmpfiles, etc.).  Prefer mkGuest for new templates.
        #
        # Produces:
        #   $out/vmlinux       — uncompressed kernel
        #   $out/initrd        — NixOS stage-1 ramdisk
        #   $out/rootfs.ext4   — ext4 root filesystem
        #   $out/toplevel-path — NixOS closure reference
        #
        lib.mkNixosGuest = { name, modules ? [] }:
          let
            eval = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = { inherit mvm-guest-agent; };
              modules = [
                ./modules/mvm-guest.nix
                ./modules/guest-agent.nix
                ./modules/firecracker-kernel.nix
              ] ++ modules;
            };
            cfg = eval.config;
            kernel = cfg.boot.kernelPackages.kernel;

            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ cfg.system.build.toplevel ];
              volumeLabel = "nixos";
              populateImageCommands = ''
                mkdir -p ./files/etc ./files/sbin
                ln -s ${cfg.system.build.toplevel} ./files/etc/system-toplevel
                ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init
                ln -s .${cfg.system.build.toplevel}/init ./files/init
                echo "${cfg.system.build.toplevel}" > ./files/etc/NIXOS_CLOSURE
                touch ./files/etc/NIXOS
              '';
            };
          in
          pkgs.runCommand "mvm-nixos-${name}" {
            passthru = { inherit eval; config = cfg; };
          } ''
            mkdir -p $out
            ${copyKernel kernel}
            cp "${cfg.system.build.initialRamdisk}/initrd" "$out/initrd"
            cp "${rootfs}" "$out/rootfs.ext4"
            echo "${cfg.system.build.toplevel}" > "$out/toplevel-path"
          '';

        # ── NixOS modules (for mkNixosGuest users) ────────────────
        nixosModules = {
          mvm-guest = ./modules/mvm-guest.nix;
          guest-agent = ./modules/guest-agent.nix;
          guest-integrations = ./modules/guest-integrations.nix;
        };

        packages.mvm-guest-agent = mvm-guest-agent;
      }
    );
}
