{
  description = "mvm dev environment — Linux VM image with Nix + build tools for Apple Container";

  inputs = {
    mvm.url = "path:../guest-lib";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      # The dev image is always a Linux aarch64 rootfs (it runs inside a VM).
      # We expose it under both Linux and Darwin systems so `nix build` works
      # on macOS (cross-builds the Linux image via Nix's Linux builder).
      linuxSystem = "aarch64-linux";
      linuxPkgs = import nixpkgs { system = linuxSystem; };

      devImage = mvm.lib.${linuxSystem}.mkGuest {
        name = "mvm-dev";
        hostname = "mvm-dev";

        packages = [
          # Core tools
          linuxPkgs.bashInteractive
          linuxPkgs.coreutils
          linuxPkgs.gnugrep
          linuxPkgs.gnused
          linuxPkgs.gawk
          linuxPkgs.findutils
          linuxPkgs.which

          # Build tools
          linuxPkgs.gnumake
          linuxPkgs.gcc
          linuxPkgs.binutils

          # Nix package manager
          linuxPkgs.nix

          # Version control
          linuxPkgs.git

          # Networking
          linuxPkgs.curl
          linuxPkgs.wget
          linuxPkgs.iproute2
          linuxPkgs.openssh

          # Editors
          linuxPkgs.nano
          linuxPkgs.less

          # Filesystem
          linuxPkgs.e2fsprogs
          linuxPkgs.squashfsTools
          linuxPkgs.util-linux

          # Debugging
          linuxPkgs.strace
          linuxPkgs.procps
          linuxPkgs.htop
        ];

        # No services — dev image is for interactive use.
        # The guest agent handles PTY console access.
      };
    in {
      # Expose the Linux dev image under all common systems so
      # `nix build` works from macOS, Linux x86_64, and Linux aarch64.
      packages = builtins.listToAttrs (map (system: {
        name = system;
        value = { default = devImage; };
      }) [
        "aarch64-linux"
        "x86_64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ]);
    };
}
