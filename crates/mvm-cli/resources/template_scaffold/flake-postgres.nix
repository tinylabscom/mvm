{
  description = "mvm microVM — Postgres-backed app preset";

  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };
      pgData = "/var/lib/postgresql/data";
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-postgres-vm";

        packages = [ pkgs.postgresql pkgs.curl ];

        # PostgreSQL service — initialises the data directory on first boot.
        services.postgres = {
          preStart = ''
            if [ ! -f ${pgData}/PG_VERSION ]; then
              mkdir -p ${pgData}
              chown postgres:postgres ${pgData}
              su -s /bin/sh postgres -c "${pkgs.postgresql}/bin/initdb -D ${pgData}"
            fi
          '';
          command = "${pkgs.postgresql}/bin/postgres -D ${pgData} -k /run/postgresql";
        };

        # Replace this with your application service.
        # services.app = {
        #   command = "${pkgs.myApp}/bin/my-app --db-host localhost";
        # };

        # Health check: wait until Postgres is accepting connections.
        healthChecks.postgres = {
          healthCmd = "${pkgs.postgresql}/bin/pg_isready -h localhost";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 5;
        };
      };
    };
}
