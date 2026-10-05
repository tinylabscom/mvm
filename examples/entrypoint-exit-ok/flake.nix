{
  description = "Baked entrypoint that succeeds, for the sealed-session lifecycle witness";

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
          succeed = pkgs.writeShellScript "entrypoint-exit-ok" ''
            echo mvm-bdd-entrypoint-ok
          '';
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "entrypoint-exit-ok";
            entrypoint.command = idle;
            bootCommand = idle;
            extraFiles."/etc/mvm/entrypoint" = {
              source = succeed;
              mode = "0755";
            };
            vcpus = 1;
            memory_mib = 256;
          };
        }
      );
    };
}
