{
  description = "Agent workload with host-side credential substitution";

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem =
        f:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = f system;
          }) systems
        );
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          agentRecipe = import "${mvm}/examples/llm-agent" {
            inherit pkgs;
            tools = [ "WebFetch" ];
          };
          agent = agentRecipe.agent;
          entrypoint = pkgs.writeShellScript "agent-workload-entrypoint" ''
            export HOME=/tmp
            exec ${agent}/bin/mvm-agent --allowedTools WebFetch --max-turns 3 --max-budget-usd 0.50
          '';
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "agent-workload";
            packages = [ agent ];
            # Workload IR injects ANTHROPIC_API_KEY only into this per-call
            # entrypoint. PID 1 receives neither the placeholder nor the proxy.
            entrypoint.command = [ "/etc/mvm/entrypoint" ];
            extraFiles."/etc/mvm/entrypoint" = {
              source = entrypoint;
              mode = "0755";
            };
            vcpus = 2;
            memory_mib = 4096;
          };
        }
      );
    };
}
