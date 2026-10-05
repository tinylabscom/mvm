{
  description = "Pinned Python runtime microVM image";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs-initramfs.url = "github:NixOS/nixpkgs/nixos-25.11";
    mvm = {
      url = "github:tinylabscom/mvm/4e65b221744885e536ec91a3f2948cdc508dcb49";
      flake = false;
    };
  };

  outputs = { nixpkgs, microvm, mvm, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system: {
        name = system;
        value = f system;
      }) systems);
      workspaceRoot = mvm.outPath;
      workspace =
        (import (workspaceRoot + "/nix/lib/workspace-filter.nix") {
          inherit (nixpkgs) lib;
        })
        { inherit workspaceRoot; };
      mvmLib = (import (workspaceRoot + "/nix/flake.nix")).outputs {
        self = { };
        inherit nixpkgs microvm;
        mvm-workspace = workspace;
      };
    in
    {
      packages = eachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = mvmLib.lib.${system}.mkGuest {
            name = "python-runtime";
            packages = [ pkgs.python3 ];
            entrypoint.command = [
              "/bin/busybox" "sh" "-c"
              "while :; do /bin/busybox sleep 2147483647; done"
            ];
            vcpus = 2;
            memory_mib = 512;
          };
        });
    };
}
