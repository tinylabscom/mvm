{
  description = "mvm microVM — Python data-science preset";

  inputs = {
    mvm.url = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };

      # Python with pandas, numpy, and requests baked into the image.
      python = pkgs.python3.withPackages (ps: [
        ps.pandas
        ps.numpy
        ps.requests
      ]);

      # Your application source directory (relative to this flake).
      appSrc = pkgs.stdenv.mkDerivation {
        pname = "my-python-pandas-app";
        version = "0";
        src = ./app;
        installPhase = "cp -r . $out";
      };

    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-python-pandas-vm";

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
