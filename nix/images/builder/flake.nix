{
  description = "mvm dev environment — Linux VM image with Nix + build tools";

  # The dev VM is mvmctl's own build sandbox: shell::run_in_vm dispatches
  # `nix build` calls into it via the guest agent's vsock Exec handler.
  # That handler is only compiled in when the agent is built with the
  # `dev-shell` Cargo feature, which is what the dev sibling flake at
  # `nix/dev` re-exports `mkGuest` with. The nested input override pins
  # the dev sibling's own `mvm` input to the local checkout, so the prod
  # library and dev agent both build from the same source tree.
  #
  # Plan 36: the new `builder` output (sealed, prod-agent, dm-verity
  # protected, consumed by mvmd) needs the *parent* flake — not the dev
  # sibling — as its mkGuest source. We expose a second input
  # `mvm-prod` pointing at the parent so the builder output is
  # unaffected by mvmctl's `--override-input mvm <abs>/nix/dev` swap.
  inputs = {
    mvm.url = "path:../../dev";
    mvm.inputs.mvm.url = "path:../..";
    mvm-prod.url = "path:../..";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, mvm-prod, nixpkgs, ... }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];

      # The build sandbox's package set. Identical between the dev and
      # builder variants — only the guest agent and verity posture
      # differ. Plan 36 §Layer 1: keeping one source of truth here is
      # what prevents "works in dev, breaks in production builder"
      # drift between the two outputs.
      builderPackages = pkgs: [
        # Core tools
        pkgs.bashInteractive
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.gawk
        pkgs.findutils
        pkgs.which

        # Build tools
        pkgs.gnumake

        # Nix package manager
        pkgs.nix

        # Version control
        pkgs.git

        # Networking
        pkgs.curl
        pkgs.iproute2
        # iptables + jq are required by the bridge_ensure script in
        # mvm-runtime/src/vm/network.rs when this VM hosts transient
        # microVMs (e.g., `mvmctl exec` against the dev variant). The
        # builder variant inherits both for now; plan 36 PR-B.2's
        # package-closure regression test will revisit whether mvmd's
        # production builder genuinely needs them or moves the bridge
        # logic host-side.
        pkgs.iptables
        pkgs.jq

        # Editors
        pkgs.less

        # Filesystem
        pkgs.e2fsprogs
        pkgs.util-linux

        # Debugging
        pkgs.procps
      ];

      # The mvmctl-facing dev variant. Built by mvmctl with the dev
      # override (`--override-input mvm <abs>/nix/dev`), which forces
      # `variant = "dev"` and swaps in the dev guest agent (Exec
      # handler compiled in for `mvmctl exec`/`console`). Verity is
      # disabled because the dev VM mounts a writable overlay disk
      # over /nix at runtime — see ADR-002 §W3.4. No behaviour change
      # from the pre-plan-36 single-output flake.
      mkDevImage = system:
        let pkgs = import nixpkgs { inherit system; config = {}; overlays = []; };
        in mvm.lib.${system}.mkGuest {
          name = "mvm-dev";
          hostname = "mvm-dev";
          role = "builder";
          verifiedBoot = false;
          packages = builderPackages pkgs;
        };

      # The sealed mvmd-facing builder variant. Plan 36 / ADR 005.
      # Sources `mkGuest` from the **parent** flake (`mvm-prod`), not
      # the dev sibling, so it gets the production library and the
      # default prod guest agent (no Exec handler) regardless of
      # whether mvmctl applies its `--override-input mvm <abs>/nix/dev`
      # swap. `verifiedBoot` defaults to true on the parent's
      # `mkGuestFn`, so this output ships the dm-verity sidecar that
      # mvmd-agent will verify on every boot. The mkGuest assertion
      # plan 36 added catches `variant=dev + verifiedBoot=true` at
      # evaluation time, so a mistakenly-applied dev override here
      # would fail loudly rather than silently shipping a dev-agent
      # binary inside an mvmd production builder.
      mkBuilderImage = system:
        let pkgs = import nixpkgs { inherit system; config = {}; overlays = []; };
        in mvm-prod.lib.${system}.mkGuest {
          name = "mvm-builder-prod";
          hostname = "mvm-builder";
          role = "builder";
          # `variant`, `verifiedBoot`, and `guestAgent` all stay at
          # the parent flake's defaults (prod / true / prod agent).
          packages = builderPackages pkgs;
        };
    in {
      packages = builtins.listToAttrs (map (system: {
        name = system;
        value = {
          default = mkDevImage system;
          builder = mkBuilderImage system;
        };
      }) systems);
    };
}
