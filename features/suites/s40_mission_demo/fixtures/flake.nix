{
  description = "Baked local-durable mailbox guest entrypoint";

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
          witness = pkgs.writeTextFile {
            name = "mailbox-local-live-witness";
            destination = "/bin/mailbox-local-live-witness";
            executable = true;
            text = "#!${pkgs.python3}/bin/python3\n" + builtins.readFile ./mailbox_witness.py;
          };
        in
        {
          default = mvm.lib.${system}.mkGuest {
            name = "mailbox-local-live-witness";
            packages = [ pkgs.python3 ];
            entrypoint.command = [ "${witness}/bin/mailbox-local-live-witness" ];
            extraFiles."/etc/mvm/mailbox-local-live-witness" = {
              source = "${witness}/bin/mailbox-local-live-witness";
              mode = "0755";
            };
            vcpus = 1;
            memory_mib = 256;
          };
        }
      );
    };
