{
  description = "mvm dev environment — Linux VM image with Nix + build tools";

  inputs = {
    mvm.url = "path:../guest-lib";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];

      mkDevImage = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in mvm.lib.${system}.mkGuest {
          name = "mvm-dev";
          hostname = "mvm-dev";

          packages = [
            # Core tools
            pkgs.bashInteractive
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.gnused
            pkgs.gawk
            pkgs.findutils
            pkgs.which

            # Build tools
            pkgs.gnumake

            # Nix package manager
            pkgs.nix

            # Version control
            pkgs.git

            # Networking
            pkgs.curl
            pkgs.iproute2
            # iptables + jq are required by the bridge_ensure script in
            # mvm-runtime/src/vm/network.rs when this dev VM hosts
            # transient microVMs (e.g., `mvmctl exec`).
            pkgs.iptables
            pkgs.jq

            # Editors
            pkgs.less

            # Filesystem
            pkgs.e2fsprogs
            pkgs.util-linux

            # Debugging
            pkgs.procps
          ];
        };
    in {
      packages = builtins.listToAttrs (map (system: {
        name = system;
        value = { default = mkDevImage system; };
      }) systems);
    };
}
