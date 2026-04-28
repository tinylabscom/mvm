{
  description = "Default minimal microVM image (busybox + guest agent) used by mvmctl when no --flake or --template is given.";

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
          # mvmctl uses this image whenever a command would otherwise need a
          # --flake or --template and none was provided (currently `mvmctl exec`
          # and `mvmctl up`/`run`/`start`).
          #
          # Intentionally minimal: busybox (sh, mount, coreutils, …) and the
          # guest agent are already baked in by mkGuest, so no extra packages
          # are needed. Users who want richer tooling should build their own
          # template via `mvmctl template create`.
          default = mvm.lib.${system}.mkGuest {
            name = "default-microvm";
            packages = [ ];
          };
        });
    };
}
