# Builder-VM-side shell. Lives at `devShells.${system}.builder` on
# Linux only. Inside the Lima VM (or any Linux + KVM box) this is the
# shell with everything needed to build microVM rootfs / kernel /
# guest agent locally.
#
# Per W7 plan: the package set here is what `nix/images/builder/`
# already passes into `mkGuest` — formalized via shared
# `nix/lib/builder-tools.nix` so the builder image and this shell
# stay in sync.

{ pkgs, rustToolchain }:

pkgs.mkShell {
  name = "mvm-builder";

  packages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.pkg-config
    pkgs.openssl
    pkgs.nix
    pkgs.git
    pkgs.jq
    pkgs.just
    pkgs.cacert
    pkgs.qemu
    # iproute2 + iptables let contributors inspect the TAP/bridge
    # wiring mvmctl creates — read-only diagnostics, not mutation.
    pkgs.iproute2
    pkgs.iptables
    pkgs.bridge-utils
    pkgs.e2fsprogs
    pkgs.util-linux
  ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
    # Firecracker is Linux-only; the package gate keeps darwin
    # contributors from accidentally entering this shell with a
    # broken closure. (`devShells.<sys>.builder` is exposed only
    # under `*-linux` in flake.nix; the optionalAttrs pkgs.stdenv.isLinux
    # is belt-and-braces.)
    pkgs.firecracker-bin or pkgs.firecracker
  ];

  shellHook = ''
    echo "── mvm builder shell ────────────────────────────────────────"
    echo "  rust:        $(${rustToolchain}/bin/cargo --version 2>/dev/null || echo '?')"
    echo "  nix:         $(${pkgs.nix}/bin/nix --version 2>/dev/null || echo '?')"
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
      echo "  /dev/kvm:    accessible (Firecracker can boot here)"
    else
      echo "  /dev/kvm:    NOT accessible. Firecracker boot will fail."
      echo "               See ops/permissions/ for the manual fix."
    fi
    echo "─────────────────────────────────────────────────────────────"
  '';
}
