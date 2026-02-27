{
  description = "OpenClaw microVM template for mvm";

  inputs = {
    mvm.url = "path:../../";
    # Unstable required — pnpm_10.fetchDeps is only in nixpkgs-unstable.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system:
        { name = system; value = f system; }
      ) systems);

      # Build the gateway locally instead of using the nix-openclaw overlay,
      # which bundles ML tools (whisper/torch/triton) that fail on aarch64.
      openclawFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.callPackage ./pkgs/openclaw.nix {};

      # Helper: build a guest image for a given role module.
      mkRole = system: roleModule: mvm.lib.${system}.mkGuest {
        name = "openclaw";
        modules = [
          ({ ... }: { _module.args.openclaw = openclawFor system; })
          roleModule
        ];
      };
    in {
      packages = eachSystem (system: {
        # Gateway variant — lightweight MCP proxy, no persistent data disk.
        tenant-gateway = mkRole system ./roles/gateway.nix;

        # Worker variant — agent execution, uses persistent data disk.
        tenant-worker = mkRole system ./roles/worker.nix;

        # Default = gateway (backward compatible, lower resource requirement).
        default = mkRole system ./roles/gateway.nix;
      });
    };
}
