{
  description = "mvm dev environment — Linux VM image with Nix + build tools for Apple Container";

  inputs = {
    mvm.url = "path:../guest-lib";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);
    in {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          # Full dev environment image with Nix, git, build tools.
          #
          # Boot via Apple Container -> get a shell with everything needed
          # to build microVM images via `nix build`.
          #
          # Produces:
          #   $out/vmlinux      - kernel for Virtualization.framework
          #   $out/rootfs.ext4  - ext4 rootfs with Nix + tools
          #   $out/image.tar.gz - OCI image (optional, for container runtimes)
          default = mvm.lib.${system}.mkGuest {
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

            # No services — dev image is for interactive use.
            # The guest agent handles PTY console access.
          };
        });
    };
}
