{
  description = "mvm dev environment — Linux VM image with Nix + build tools";

  # The dev VM is mvmctl's own build sandbox: shell::run_in_vm dispatches
  # `nix build` calls into it via the guest agent's vsock Exec handler.
  # That handler is only compiled in when the agent is built with the
  # `dev-shell` Cargo feature, which is what the dev sibling flake at
  # `nix/dev` re-exports `mkGuest` with. The nested input override pins
  # the dev sibling's own `mvm` input to the local checkout, so the prod
  # library and dev agent both build from the same source tree.
  inputs = {
    mvm.url = "path:../../dev";
    mvm.inputs.mvm.url = "path:../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];

      mkDevImage = system:
        let
          pkgs = import nixpkgs { inherit system; config = {}; overlays = []; };
        in mvm.lib.${system}.mkGuest {
          name = "mvm-dev";
          hostname = "mvm-dev";

          # W7.3 — tag this rootfs as the *builder* VM image, not a
          # tenant rootfs. Visible on the derivation as
          # `passthru.role = "builder"` for downstream tooling.
          role = "builder";

          # ADR-002 §W3.4 names the dev VM as the explicit exemption
          # from verified boot: the overlayfs upper layer mutates /nix
          # at runtime, which can't compose with dm-verity (the lower
          # layer's root hash would have to change on every write). The
          # flag is plumbed all the way through mkGuest → start_vm so
          # that the kernel cmdline doesn't carry `dm-mod.create=` and
          # the rootfs.verity sidecar isn't even built.
          verifiedBoot = false;

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
