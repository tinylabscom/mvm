{
  description = "hello-python microVM — minimal Python example using mkPythonService";

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
          # mkPythonService builds a Python app and returns
          # { package, service, healthCheck }.
          #
          # pythonPackages uses nixpkgs Python packages (not pip).
          # For pip-based deps, use mkGuest directly with a custom derivation.
          app = mvm.lib.${system}.mkPythonService {
            name = "hello-python";
            src = ./app;
            pythonPackages = ps: [
              # Add nixpkgs Python packages here, e.g.:
              # ps.flask
              # ps.requests
            ];
            entrypoint = "main.py";
            port = 8080;
            env = {
              PORT = "8080";
            };
          };

        in {
          default = mvm.lib.${system}.mkGuest {
            name = "hello-python";
            hostname = "hello-python";

            packages = [ app.package ];

            users.hello-python = {
              home = "/var/lib/hello-python";
            };

            services.hello-python = app.service;
            healthChecks.hello-python = app.healthCheck;
          };
        });
    };
}
