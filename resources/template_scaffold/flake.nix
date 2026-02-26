{
  description = "mvm microVM template";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, microvm, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };

      mkGuest = extra:
        (nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            microvm.nixosModules.microvm
            {
              system.stateVersion = "24.11";
              services.getty.autologinUser = "root";
              networking.firewall.enable = false;
              environment.systemPackages = with pkgs; [ curl ];
            }
          ] ++ extra;
        }).config.system.build.toplevel;
    in
    {
      packages.${system} = {
        # Default build target -- a minimal NixOS microVM.
        default = mkGuest [];

        # Add more variants here, e.g.:
        # tenant-worker  = mkGuest [ ./worker.nix ];
        # tenant-gateway = mkGuest [ ./gateway.nix ];
      };
    };
}
