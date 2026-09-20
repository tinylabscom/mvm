{
  description = "Agent workload with host-side credential substitution";

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs
        (map (system: { name = system; value = f system; }) systems);
    in
    {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          agentRecipe = import "${mvm}/images/examples/llm-agent" { inherit pkgs; };
          agent = agentRecipe.agent;
          idle = [ "/bin/sh" "-c" "while :; do /bin/busybox sleep 2147483647; done" ];
          entrypoint = pkgs.writeShellScript "agent-workload-entrypoint" ''
            export HOME=/tmp
            exec ${agent}/bin/mvm-agent
          '';
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "agent-workload";
            packages = [ agent ];
            # Workload IR injects ANTHROPIC_API_KEY only into this per-call
            # entrypoint. PID 1 receives neither the placeholder nor the proxy.
            entrypoint.command = idle;
            bootCommand = idle;
            extraFiles."/etc/mvm/entrypoint" = {
              source = entrypoint;
              mode = "0755";
            };
            vcpus = 2;
            memory_mib = 2048;
          };
        });
    };
}
