{
  description = "OpenClaw microVM template for mvm";

  inputs = {
    mvm.url = "path:../../";
    # Unstable required — the nix-openclaw overlay uses fetchPnpmDeps.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix-openclaw.url = "github:openclaw/nix-openclaw";
  };

  outputs = { mvm, nixpkgs, nix-openclaw, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);

      openclawFor = system: (import nixpkgs {
        inherit system;
        overlays = [ nix-openclaw.overlays.default ];
      }).openclaw;
    in {
      packages = eachSystem (system: {
        default = mvm.lib.${system}.mkGuest {
          name = "openclaw";
          modules = [
            ({ ... }: { _module.args.openclaw = openclawFor system; })
            ./role.nix
          ];
        };
      });
    };
}
