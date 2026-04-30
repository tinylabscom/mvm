# Host (dev-machine) shell. Lives at `devShells.${system}.default` on
# darwin and as `devShells.${system}.host` everywhere.
#
# Per the W7 plan:
#   - This shell is for hacking on the `mvmctl` Rust crate.
#   - It does NOT include firecracker / kernel build tooling — those
#     belong in the builder VM image (`nix/images/builder/flake.nix`).
#   - The hook is diagnostic-only. It must NOT mutate host state
#     (no chmod, no usermod, no mkdir, no daemon starts) per the
#     mvm-nix-best-practices guide's hard rules.

{ pkgs, rustToolchain }:

pkgs.mkShell {
  name = "mvm-host";

  packages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.pkg-config
    pkgs.openssl
    pkgs.jq
    pkgs.just
    pkgs.git
    pkgs.cacert
  ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
    # macOS dev path uses Lima (or Apple Container on macOS 26+ Apple
    # Silicon) to host the builder VM. Including the inspection tools
    # is fine; they don't touch host networking until the user runs
    # them explicitly.
    pkgs.lima
    pkgs.qemu
  ];

  shellHook = ''
    echo "── mvm host dev shell ──────────────────────────────────────"
    echo "  rust:    $(${rustToolchain}/bin/cargo --version 2>/dev/null || echo '?')"
    echo "  just:    $(${pkgs.just}/bin/just --version 2>/dev/null || echo '?')"
  '' + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
    echo "  lima:    $(${pkgs.lima}/bin/limactl --version 2>/dev/null | head -1 || echo '?')"
    echo
    echo "You are on the development machine."
    echo "Real microVM builds run inside the builder VM."
    echo "Use 'mvmctl dev up' to start it."
  '' + pkgs.lib.optionalString pkgs.stdenv.isLinux ''
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
      echo "  /dev/kvm: accessible (native Linux + KVM)"
    elif [ -e /dev/kvm ]; then
      echo "  /dev/kvm: present but not accessible by this user."
      echo "           See ops/permissions/ — do NOT auto-fix from this shell."
    else
      echo "  /dev/kvm: not present. mvmctl will fall back to Lima."
    fi
  '' + ''
    echo "─────────────────────────────────────────────────────────────"
  '';
}
