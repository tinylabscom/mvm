# Internal test fixture — NOT a user-facing template.
#
# This profile exists so mvm's own tests have a NixOS configuration to
# evaluate and a `microvm.declaredRunner` to build
# (`tests/nix_flake_structure.rs` pins its required settings).
# It is **not** a starter for user projects. User flakes use
# `mvm.lib.<system>.mkGuest { … }` to declare a microVM image —
# see `public/src/content/docs/guides/building-microvm-images.md`
# for the user-facing surface.
#
# The flake exposes this configuration under
# `nixosConfigurations.internal-minimal-<system>` so the namespace
# encodes the boundary: anything prefixed `internal-` is mvm-private
# tooling, not part of the public API.
#
# The fixture runs no services and is never sealed, so it carries no
# per-service uid, setpriv launch line, seccomp tier, read-only /etc, or
# dm-verity rootfs; the guest hardening mvm ships belongs to images built
# with `mkGuest`.
# Its only guest invariants are the two stated below: no network
# interface and no SSH.
#
# The profile is deliberately scheme-agnostic about the hypervisor:
# microvm.nix selects the right runner from `microvm.hypervisor` and
# builds artifacts the Firecracker backend can consume.

{ config, lib, pkgs, ... }:

{
  microvm = {
    # Default hypervisor for `microvm.declaredRunner`. Production
    # Linux paths point at Firecracker via the mvm runtime backend —
    # this default is for `nix build .#internal-minimal-runner` convenience and
    # gets overridden when consumers want a different runner.
    hypervisor = "firecracker";

    # Resource defaults — sized so the image boots cleanly on a
    # constrained CI runner.
    vcpu = 1;
    mem = 256;

    # No network interface, no extra disks, no host shares.
    interfaces = [ ];
    volumes = [ ];
    shares = [ ];
  };

  # Hostname is informational; the per-instance name comes from the
  # caller (mvmctl writes it on boot).
  networking.hostName = lib.mkDefault "mvm-minimal";

  # Locale + timezone defaults — chosen for size (no extra locale
  # data) rather than user-friendliness. Profiles that surface to
  # end users override these.
  time.timeZone = "UTC";
  i18n.defaultLocale = "C.UTF-8";

  # Bare-bones package set: a shell + coreutils. No guest agent and no
  # services.
  environment.systemPackages = with pkgs; [
    coreutils
    bashInteractive
  ];

  # SSH explicitly disabled. mvm reaches guests over vsock only. Setting `services.openssh.enable = false` is redundant with
  # NixOS's default but stated here as a load-bearing invariant.
  services.openssh.enable = false;

  # Stable system version pinned. Bumps land alongside nixpkgs flake
  # input bumps in CI.
  system.stateVersion = "25.11";
}
