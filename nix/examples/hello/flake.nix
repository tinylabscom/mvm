{
  description = "Minimal hello-world microVM for boot time testing";

  inputs = {
    mvm.url = "path:../../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);
    in {
      packages = eachSystem (system: {
        default = mvm.lib.${system}.mkGuest {
          name = "hello";
          modules = [ ./hello.nix ];
        };
      });
    };
}
