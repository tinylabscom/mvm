# Library entry point — exposed as `mvm.lib.<system>` from the root
# flake. Functions here are user-facing and stable; their shapes are
# part of mvm's public API. New helpers go in their own files under
# `nix/lib/` and get re-exported here.

{ nixpkgs, microvm, mvmSrc }:
let
  mkGuestImpl = import ./mk-guest.nix { inherit nixpkgs microvm mvmSrc; };

  # plan 60 Phase 5 Slice E1 — generic function-service factory.
  # Single entry; the caller passes `language = "python"` / `"node"`
  # and the factory looks up the language in the registry under
  # `nix/lib/factories/languages/`. Adding a language is one data row
  # in `registry.nix` (no new .nix file, no caller-side switch, no
  # factory-dispatcher edit). Returns `{ extraFiles, servicePackages, service }` —
  # the contract `mkGuest`'s composition layer consumes (see
  # `tests/factory_shape.nix`).
  mkFunctionServiceImpl = import ./factories/mkFunctionService.nix;

  # plan 71 — one-line IR-to-image helper. Reads a workload IR JSON,
  # composes `mkFunctionService` with `mkGuest`, returns the rootfs
  # derivation directly. Documented at `nix/lib/factories/README.md`.
  mkFunctionWorkloadImpl = import ./mkFunctionWorkload.nix { inherit nixpkgs microvm mvmSrc; };
in
{ system }:
{
  # Full mkGuest implementation. Documented at
  # `public/src/content/docs/guides/building-microvm-images.md`.
  mkGuest = args: (mkGuestImpl { inherit system; }) args;

  # Bake a function-call workload (ADR-0009 / plan 0003 phase 4).
  # See `nix/lib/factories/mkFunctionService.nix` for the input
  # schema and `nix/lib/factories/languages/` for the language
  # registry.
  mkFunctionService = mkFunctionServiceImpl;

  # Turn a workload IR JSON into a microVM rootfs in one call.
  # See `nix/lib/mkFunctionWorkload.nix` for the supported IR shape.
  mkFunctionWorkload = args: (mkFunctionWorkloadImpl { inherit system; }) args;
}
