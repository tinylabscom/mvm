{
  description = "mvm microVM — Python service preset";

  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };

      # Python with dependencies from nixpkgs.
      # Add packages to the list: ps.flask, ps.requests, ps.gunicorn, etc.
      python = pkgs.python3.withPackages (ps: [
        # ps.flask
        # ps.gunicorn
      ]);

      # Your application source directory (relative to this flake).
      appSrc = pkgs.stdenv.mkDerivation {
        pname = "my-python-app";
        version = "0";
        src = ./app;
        installPhase = "cp -r . $out";
      };

    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-python-vm";

        packages = [ python appSrc pkgs.curl ];

        services.app = {
          command = "${python}/bin/python3 ${appSrc}/main.py";
          env = {
            PORT = "8080";
            PYTHONUNBUFFERED = "1";
          };
        };

        healthChecks.app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
