{ pkgs, ... }:
{
  system.stateVersion = "24.11";
  services.getty.autologinUser = "root";
  environment.systemPackages = with pkgs; [ curl git ];
}
