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

        # Add packages available inside the microVM.
        packages = [ pkgs.curl pkgs.bash ];

        # Add supervised services:
        # services.my-service = {
        #   command = "${pkgs.somePackage}/bin/my-binary --flag";
        #   preStart = "echo starting";
        # };

        # Add health checks reported back to the host:
        # healthChecks.my-service = {
        #   healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
        #   healthIntervalSecs = 5;
        #   healthTimeoutSecs = 3;
        # };
      };
    };
}
