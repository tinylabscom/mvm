{ ... }:
{
  networking.hostName = "openclaw-worker";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 18790 ];

  # Worker role config placeholders.
  environment.etc."openclaw/worker.toml".text = ''
    [worker]
    listen = "0.0.0.0:18790"
  '';
  environment.etc."openclaw/worker.env".text = ''
    OPENCLAW_ROLE=worker
    OPENCLAW_LISTEN_ADDR=0.0.0.0:18790
  '';

  # Role-specific persistent workspace.
  fileSystems."/var/lib/openclaw" = {
    fsType = "tmpfs";
    device = "tmpfs";
    options = [ "mode=0755" "size=1024m" ];
  };
}
