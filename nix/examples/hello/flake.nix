{
  description = "Minimal hello-world microVM for boot time testing";

  inputs = {
    mvm.url = "path:../../";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
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
          startScript = pkgs.writeShellScript "hello-http-start" ''
            mkdir -p /tmp/www
            echo '<h1>Hello from mvm!</h1>' > /tmp/www/index.html
            exec ${pkgs.python3}/bin/python3 -m http.server 8080 --directory /tmp/www
          '';
        in {
          default = mvm.lib.${system}.mkGuest {
            name = "hello";
            packages = [ pkgs.python3 pkgs.curl ];

            services.hello-http = {
              command = "${startScript}";
            };

            healthChecks.hello-http = {
              healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
              healthIntervalSecs = 5;
              healthTimeoutSecs = 3;
            };
          };
        });
    };
}
