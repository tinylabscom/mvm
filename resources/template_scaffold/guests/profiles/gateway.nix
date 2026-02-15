{ ... }:
{
  networking.hostName = "openclaw-gateway";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 443 8080 18789 ];

  # Gateway role config placeholders.
  environment.etc."openclaw/gateway.toml".text = ''
    [gateway]
    listen = "0.0.0.0:18789"
  '';
  environment.etc."openclaw/gateway.env".text = ''
    OPENCLAW_ROLE=gateway
    OPENCLAW_LISTEN_ADDR=0.0.0.0:18789
  '';

  # Role-specific persistent workspace.
  fileSystems."/var/lib/openclaw" = {
    fsType = "tmpfs";
    device = "tmpfs";
    options = [ "mode=0755" "size=512m" ];
  };
}
