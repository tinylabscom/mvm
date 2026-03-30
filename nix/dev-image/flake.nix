{
  description = "mvm dev environment — Linux VM image with Nix + build tools";

  inputs = {
    mvm.url = "path:../guest-lib";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      # Build a dev image for a given Linux system.
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
            pkgs.gcc
            pkgs.binutils

            # Nix package manager
            pkgs.nix

            # Version control
            pkgs.git

            # Networking
            pkgs.curl
            pkgs.wget
            pkgs.iproute2
            pkgs.openssh

            # Editors
            pkgs.nano
            pkgs.less

            # Filesystem
            pkgs.e2fsprogs
            pkgs.squashfsTools
            pkgs.util-linux

            # Debugging
            pkgs.strace
            pkgs.procps
            pkgs.htop
          ];
        };

      # Native Linux builds
      linuxSystems = [ "aarch64-linux" "x86_64-linux" ];

      # Darwin systems get the matching-arch Linux image
      # (aarch64-darwin -> aarch64-linux, x86_64-darwin -> x86_64-linux)
      darwinMappings = {
        "aarch64-darwin" = "aarch64-linux";
        "x86_64-darwin" = "x86_64-linux";
      };

      linuxPackages = builtins.listToAttrs (map (system: {
        name = system;
        value = { default = mkDevImage system; };
      }) linuxSystems);

      darwinPackages = builtins.mapAttrs (_darwin: linux: {
        default = mkDevImage linux;
      }) darwinMappings;
    in {
      packages = linuxPackages // darwinPackages;
    };
}
