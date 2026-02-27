{
  description = "mvm microVM template";

  inputs = {
    # mvm provides lib.mkGuest, NixOS modules, and the guest agent.
    # For local development, override with: mvm.url = "path:/path/to/mvm";
    mvm.url = "github:auser/mvm";
  };

  outputs = { mvm, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
    in {
      packages.${system} = {
        # Default build target — a minimal NixOS microVM.
        default = mvm.lib.${system}.mkGuest {
          name = "my-vm";
          modules = [ ./config.nix ];
          # hypervisor = "qemu";  # optional: default is firecracker
        };

        # Add more variants here, e.g.:
        # tenant-worker  = mvm.lib.${system}.mkGuest {
        #   name = "worker";
        #   modules = [ ./roles/worker.nix ];
        # };
      };
    };
}
