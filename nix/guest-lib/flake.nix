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

        # Shared kernel — built once, used by mkGuest.
        firecrackerKernel = import ./firecracker-kernel-pkg.nix { inherit pkgs; };

        # mvm guest agent — vsock management agent for all mvm microVMs.
        mvm-guest-agent = import ./guest-agent-pkg.nix {
          inherit pkgs rustPlatform;
          mvmSrc = ./../..;
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
        #   user      — user to run as (default: serviceGroup)
        #   logFile   — optional log file path (default: /dev/console)
        #
        # Users:
        #   users.<name> = { uid?, group?, home? }
        #   Auto-assigns UIDs from 1000 if not specified.
        #   Custom users are automatically added to serviceGroup for secrets access.
        #
        # Produces:
        #   $out/vmlinux       — uncompressed kernel for Firecracker
        #   $out/rootfs.ext4   — ext4 root filesystem (no initrd)
        #
        lib.mkGuest = { name, packages ? [], services ? {}, healthChecks ? {},
                        users ? {}, hostname ? name, serviceGroup ? "mvm",
                        cacert ? pkgs.cacert }:
          let
            initScript = import ./minimal-init.nix {
              inherit pkgs hostname serviceGroup users services healthChecks busybox;
              guestAgentPkg = mvm-guest-agent;
            };

            cacertPaths = pkgs.lib.optionals (cacert != null) [ cacert ];

            rootfs = pkgs.callPackage
              (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
              storePaths = [ initScript mvm-guest-agent ] ++ cacertPaths ++ packages;
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
              '' + pkgs.lib.optionalString (cacert != null) ''
                mkdir -p ./files/etc/ssl/certs
                mkdir -p ./files/etc/pki/tls/certs
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/ssl/certs/ca-bundle.crt
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/ssl/certs/ca-certificates.crt
                ln -s ${cacert}/etc/ssl/certs/ca-bundle.crt ./files/etc/pki/tls/certs/ca-bundle.crt
              '';
            };
          in
          pkgs.runCommand "mvm-${name}" {} ''
            mkdir -p $out
            ${copyKernel firecrackerKernel}
            cp "${rootfs}" "$out/rootfs.ext4"
          '';

        packages.mvm-guest-agent = mvm-guest-agent;
      }
    );
}
