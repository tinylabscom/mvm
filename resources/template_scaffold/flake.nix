{
  description = "openclaw template: minimal gateway/worker mvm flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, microvm, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
    in
    flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs { inherit system; };

        mkGuest = modules:
          let
            guestConfig = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [ microvm.nixosModules.microvm ./guests/baseline.nix ] ++ modules;
            };
            cfg = guestConfig.config;
          in {
            config = cfg;
            kernel = cfg.microvm.kernel;
            rootfs = cfg.microvm.volumes.root or cfg.system.build.squashfs;
            toplevel = cfg.system.build.toplevel;
          };

        gateway = mkGuest [ ./roles/gateway.nix ./guests/profiles/gateway.nix ];
        worker = mkGuest [ ./roles/worker.nix ./guests/profiles/worker.nix ];
      in
      {
        packages = {
          tenant-gateway = gateway.toplevel;
          tenant-worker = worker.toplevel;
          default = worker.toplevel;
        };

        checks = {
          tenant-gateway = gateway.toplevel;
          tenant-worker = worker.toplevel;
          gateway-smoke = pkgs.runCommand "gateway-smoke" { } ''
            test "${if gateway.config.systemd.services ? openclaw-gateway then "yes" else "no"}" = "yes"
            test "${if builtins.elem 18789 gateway.config.networking.firewall.allowedTCPPorts then "yes" else "no"}" = "yes"
            echo "gateway smoke passed" > "$out"
          '';
          worker-smoke = pkgs.runCommand "worker-smoke" { } ''
            test "${if worker.config.systemd.services ? openclaw-worker then "yes" else "no"}" = "yes"
            test "${if builtins.elem 18790 worker.config.networking.firewall.allowedTCPPorts then "yes" else "no"}" = "yes"
            echo "worker smoke passed" > "$out"
          '';
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            git
            nixfmt-rfc-style
            nil
          ];
        };
      }
    );
}
