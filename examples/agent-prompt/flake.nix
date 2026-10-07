{
  description = "A resident agent that answers prompts and remembers how many it has seen";

  # The smallest agent `mvmctl machine prompt` can talk to. Each prompt is the
  # complete stdin of the program baked at /etc/mvm/entrypoint; the program
  # answers with the turn number and the prompt it was given, and keeps the
  # turn count in the guest's /tmp. That count is guest state a prompt
  # changes, which is what lets a replay be checked: a fork replayed from the
  # session's base checkpoint answers its next prompt with the turn after the
  # replayed ones, not with turn 1.

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs (map (system: { name = system; value = f system; }) systems);
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          idle = [ "/bin/busybox" "sh" "-c" "while :; do /bin/busybox sleep 2147483647; done" ];
          agent = pkgs.writeShellScript "agent-prompt-turns" ''
            state=/tmp/agent-prompt-turns
            prompt=$(${pkgs.coreutils}/bin/cat)
            turns=0
            if [ -f "$state" ]; then
              turns=$(<"$state")
            fi
            turns=$((turns + 1))
            printf '%s\n' "$turns" > "$state"
            printf 'turn %s: %s\n' "$turns" "$prompt"
          '';
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "agent-prompt";
            entrypoint.command = idle;
            bootCommand = idle;
            extraFiles."/etc/mvm/entrypoint" = {
              source = agent;
              mode = "0755";
            };
            vcpus = 1;
            memory_mib = 256;
          };
        }
      );
    };
}
