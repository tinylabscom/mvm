# Minimal hello-world service for boot time testing.
#
# Serves "Hello from mvm!" on port 8080 using python3's http.server.
# No extra deps, no persistent storage, no secrets.

{ pkgs, ... }:
{
  imports = [ ../../../nix/modules/guest-integrations.nix ];

  networking.hostName = "hello";
  networking.firewall.enable = false;

  services.mvm-integrations = {
    enable = true;
    integrations.hello-http = {
      healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
      healthIntervalSecs = 5;
      healthTimeoutSecs = 3;
    };
  };

  systemd.services.hello-http = {
    description = "Hello World HTTP Server";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      Restart = "on-failure";
      ExecStart = pkgs.writeShellScript "hello-http-start" ''
        mkdir -p /tmp/www
        echo '<h1>Hello from mvm!</h1>' > /tmp/www/index.html
        exec ${pkgs.python3}/bin/python3 -m http.server 8080 --directory /tmp/www
      '';
    };
  };
}
