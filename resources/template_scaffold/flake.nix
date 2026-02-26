{
  description = "mvm microVM template";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # mvm source — provides the guest agent and NixOS modules.
    # For local development, override with: mvm-src.url = "path:/path/to/mvm";
    mvm-src = {
      url = "github:auser/mvm";
      flake = false;
    };
  };

  outputs = { nixpkgs, rust-overlay, mvm-src, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
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

      # mvm guest agent — auto-included in all mvm microVM images.
      # Provides health checks, sleep/wake lifecycle, and vsock communication.
      mvm-guest-agent = import "${mvm-src}/nix/modules/guest-agent-pkg.nix" {
        inherit pkgs rustPlatform;
        mvmSrc = mvm-src;
      };

      # Build a NixOS guest for Firecracker.
      # Output: $out/vmlinux, $out/initrd, $out/rootfs.ext4
      mkGuest = name: modules:
        let
          eval = nixpkgs.lib.nixosSystem {
            inherit system;
            specialArgs = { inherit mvm-guest-agent; };
            modules = [
              # mvm core modules (always included)
              "${mvm-src}/nix/modules/guest-agent.nix"
              ./baseline.nix
            ] ++ modules;
          };
          cfg = eval.config;
          kernel = cfg.boot.kernelPackages.kernel;

          rootfs = pkgs.callPackage (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
            storePaths = [ cfg.system.build.toplevel ];
            volumeLabel = "nixos";
            populateImageCommands = ''
              mkdir -p ./files/etc
              ln -s ${cfg.system.build.toplevel} ./files/etc/system-toplevel
              mkdir -p ./files/sbin
              ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init
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
          cp "${cfg.system.build.initialRamdisk}/initrd" "$out/initrd"
          cp "${rootfs}" "$out/rootfs.ext4"
          echo "${cfg.system.build.toplevel}" > "$out/toplevel-path"
        '';
    in
    {
      packages.${system} = {
        # Default build target -- a minimal NixOS microVM.
        default = mkGuest "default" [];

        # Add more variants here, e.g.:
        # tenant-worker  = mkGuest "worker" [ ./roles/worker.nix ];
        # tenant-gateway = mkGuest "gateway" [ ./roles/gateway.nix ];
      };
    };
}
