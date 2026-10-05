{
  description = "Baked entrypoint that attempts a destination outside its egress grant";

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
          deniedCall = pkgs.writeShellScript "entrypoint-denied-host" ''
            exec ${pkgs.curl}/bin/curl -fsSL --max-time 10 https://blocked.example/
          '';
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "entrypoint-denial";
            packages = [ pkgs.curl ];
            entrypoint.command = idle;
            bootCommand = idle;
            extraFiles."/etc/mvm/entrypoint" = {
              source = deniedCall;
              mode = "0755";
            };
            vcpus = 1;
            memory_mib = 256;
          };
        }
      );
    };
}
