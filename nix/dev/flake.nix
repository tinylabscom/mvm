{
  description = "mvm dev variant — re-exports mvm.lib with the dev guest agent injected.";

  # ── Purpose & threat model ─────────────────────────────────────────────
  #
  # This flake is the dev-side override target. It re-exports the parent
  # `mvm` flake's `lib.<system>` with `mkGuest` transparently rewired to
  # embed the dev guest agent (vsock Exec handler compiled in) instead of
  # the production agent.
  #
  # User flakes MUST NOT consume this flake directly. They reference the
  # parent (`?dir=nix` on the published mvm repo) and always get the
  # production agent. mvmctl, which is a dev tool, swaps this variant in
  # at build time via two chained overrides:
  #
  #   nix build \
  #     --override-input mvm <abs>/nix/dev \
  #     --override-input mvm/mvm <abs>/nix
  #
  # The first swaps the user flake's `mvm` input for this dev variant.
  # The second pins THIS flake's own `mvm` input to the local checkout,
  # so the production library + dev agent are both built from the same
  # source tree mvmctl is running against. Without the second override,
  # the placeholder URL below would be fetched, producing version skew.
  #
  # mvmd (production coordinator) does no overrides; production builds
  # remain prod-only.

  inputs = {
    # Placeholder. mvmctl ALWAYS overrides this via `--override-input
    # mvm/mvm` so the local checkout is used. The placeholder only has
    # to be a syntactically valid flake URL — its content is never read
    # by the dev-build path. Direct standalone `nix build path:nix/dev`
    # without the override fetches the published mvm repo, which would
    # produce a working but stale dev image; that's a documented
    # non-supported path.
    mvm.url = "github:auser/mvm?dir=nix";
  };

  outputs = { self, mvm, ... }: {
    # Re-export every system mvm exposes, but with `lib.<system>.mkGuest`
    # patched to inject the dev guest agent. The function NAME stays
    # `mkGuest` so user flakes call exactly the same symbol whether
    # they're built with or without the override.
    lib = builtins.mapAttrs (system: systemLib: systemLib // {
      mkGuest = args: systemLib.mkGuest (args // {
        guestAgent = mvm.packages.${system}.mvm-guest-agent-dev;
      });
    }) mvm.lib;

    # Pass underlying packages through unchanged so callers that reach for
    # `mvm.packages.<system>.mvm-guest-agent-dev` directly still resolve.
    packages = mvm.packages;
  };
}
