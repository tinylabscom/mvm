# Minimal Firecracker kernel for mvm guest VMs (NixOS module wrapper).
#
# Imports the standalone kernel package from nix/lib/firecracker-kernel-pkg.nix
# and wires it into the NixOS boot configuration.  The standalone package can
# also be used directly by mkMinimalGuest (no NixOS evaluation).
#
# Usage (in a guest module or mkGuest call):
#   imports = [ ./firecracker-kernel.nix ];

{ pkgs, lib, ... }:

let
  minimalKernel = import ../lib/firecracker-kernel-pkg.nix { inherit pkgs; };
in
{
  boot.kernelPackages = pkgs.linuxPackagesFor minimalKernel;

  # Monolithic kernel — no modules to load, no initrd module list needed.
  # Override the base mvm-guest.nix module settings since there are no
  # loadable modules in this kernel.
  boot.initrd.includeDefaultModules = lib.mkForce false;
  boot.initrd.availableKernelModules = lib.mkForce [];
  boot.initrd.kernelModules = lib.mkForce [];
}
