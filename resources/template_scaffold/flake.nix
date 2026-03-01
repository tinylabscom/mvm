{
  description = "mvm microVM template";

  inputs = {
    # mvm provides lib.mkGuest — the microVM image builder.
    # For local development, override with: mvm.url = "path:/path/to/mvm/nix";
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux"; # change to x86_64-linux if needed
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-vm";
        packages = [ pkgs.curl ];

        # Services are supervised with automatic restart on failure.
        services.my-app = {
          # preStart runs once as root before the service starts.
          # preStart = "mkdir -p /tmp/data";

          # The long-running service command.
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        # Health checks are reported to the host via the guest agent.
        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
