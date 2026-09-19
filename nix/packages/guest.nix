# The guest recipes: every derivation that compiles `mvm` source into a
# binary or shared object that runs inside a guest.
#
# `nix/flake.nix` exports this set as `packages.<linux-system>.*`, and the
# image flakes consume it from there rather than importing the recipe files.
# The recipes live here, beside `Cargo.lock`, because they compile this
# workspace; an image repository pins `mvm` and builds through these outputs.
#
# Each entry is called exactly as the image flakes called it before the
# export existed, so moving a consumer onto this set changes no derivation.

{ pkgs
, mvmSrc
, workspaceVersion
}:

let
  inherit (pkgs) lib;
  staticPkgs = pkgs.pkgsStatic;

  sdkCdylib = libc:
    import ./mvm-sdk-cdylib.nix {
      inherit pkgs lib mvmSrc libc workspaceVersion;
    };
in
{
  # agent + seccomp shim + netinit + OCI entrypoint, static-musl.
  mvm-guest-agent = import ./mvm-guest-agent.nix {
    pkgs = staticPkgs;
    inherit lib mvmSrc;
  };

  # The agent alone, LTO + stripped, for the universal initramfs `/init`.
  mvm-guest-agent-static = import ./mvm-guest-agent-static.nix {
    inherit pkgs lib mvmSrc;
  };

  mvm-setpriv = import ./mvm-setpriv.nix {
    inherit pkgs lib mvmSrc;
    rustPlatform = staticPkgs.rustPlatform;
  };

  mvm-runner = import ./mvm-runner.nix {
    inherit pkgs lib mvmSrc;
    version = workspaceVersion;
  };

  mvm-egress-client = import ./mvm-egress-client.nix {
    pkgs = staticPkgs;
    inherit lib mvmSrc;
  };

  mvm-addon-dns = import ./mvm-addon-dns.nix {
    pkgs = staticPkgs;
    inherit lib mvmSrc;
  };

  mvm-exit-report = import ./mvm-exit-report.nix {
    pkgs = staticPkgs;
    inherit lib mvmSrc;
  };

  # A guest can only dlopen the variant matching its own libc.
  mvm-sdk-cdylib-glibc = sdkCdylib "glibc";
  mvm-sdk-cdylib-musl = sdkCdylib "musl";
}
