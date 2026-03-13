{
  description = "hello-node microVM — minimal Node.js/TypeScript example using mkNodeService";

  inputs = {
    mvm.url = "path:../../guest-lib";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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

          # mkNodeService builds the app and returns { package, service, healthCheck }.
          #
          # npmHash: set to "" to get the correct hash from the build error, then
          # paste the "got: sha256-..." value here.
          app = mvm.lib.${system}.mkNodeService {
            name = "hello-node";
            src = ./app;
            npmHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            buildPhase = "node \"$TSC\"";
            entrypoint = "dist/index.js";
            port = 3000;
            env = {
              PORT = "3000";
            };
          };

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "hello-node";
            hostname = "hello-node";

            packages = [ pkgs.nodejs_22 app.package ];

            users.hello-node = {
              home = "/var/lib/hello-node";
            };

            services.hello-node = app.service // {
              preStart = pkgs.writeShellScript "hello-node-setup" ''
                mount -t tmpfs -o mode=0755,size=64m tmpfs /var/lib/hello-node
                chown hello-node:hello-node /var/lib/hello-node
              '';
            };

            healthChecks.hello-node = app.healthCheck;
          };
        });
    };
}
