{
  description = "mvm microVM — HTTP server preset";

  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-http-vm";

        packages = [ pkgs.python3 pkgs.curl ];

        # Python's built-in HTTP server on port 8080.
        # Replace with your own binary (e.g. pkgs.nginx, a compiled Go server, etc.)
        services.web = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        # Health check: poll the server until it responds.
        healthChecks.web = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
