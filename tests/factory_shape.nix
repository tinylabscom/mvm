# Offline smoke tests for the function-service factory + workload
# helper. Returns an attrset of named test targets so a caller can
# evaluate each independently.
#
# Targets:
#   factory_shape    Asserts `mvm.lib.<system>.mkFunctionService` returns
#                    the `{ extraFiles, servicePackages, service }` triple
#                    `mkGuest`'s composition layer consumes (plan 48 + 60
#                    Slice E1; one row per language in the registry).
#   workload_shape   Asserts `mvm.lib.<system>.mkFunctionWorkload` reads a
#                    synthetic IR JSON, composes the factory with `mkGuest`,
#                    and returns a derivation whose `passthru.mvm` records
#                    the workload id + a sealed/command entrypoint shape
#                    (plan 71).
#
# Run via:
#
#   nix eval --no-warn-dirty --impure --raw --expr '
#     let flake = builtins.getFlake "path:/Users/auser/work/tinylabs/mvmco/mvm/nix";
#     in (import /Users/auser/work/tinylabs/mvmco/mvm/tests/factory_shape.nix { flake = flake; }).factory_shape'
#
#   nix eval --no-warn-dirty --impure --raw --expr '
#     let flake = builtins.getFlake "path:/Users/auser/work/tinylabs/mvmco/mvm/nix";
#     in (import /Users/auser/work/tinylabs/mvmco/mvm/tests/factory_shape.nix { flake = flake; }).workload_shape'

{ flake }:

let
  system = "aarch64-linux";
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  appPkg = pkgs.writeText "stub-app" "stub";
  mkFunctionService = flake.lib.${system}.mkFunctionService;
  mkFunctionWorkload = flake.lib.${system}.mkFunctionWorkload;

  # ── factory_shape (plan 48 / 60 Slice E1) ─────────────────────────
  testLanguage =
    language:
    let
      out = mkFunctionService {
        inherit pkgs appPkg language;
        workloadId = "test-${language}";
        module = "main";
        function = "handler";
        format = "json";
      };
      ok =
        out ? extraFiles
        && lib.isAttrs out.extraFiles
        && (out.extraFiles ? "/etc/mvm/runner")
        && (out.extraFiles ? "/usr/lib/mvm/wrappers/runner")
        && out ? servicePackages
        && lib.isList out.servicePackages
        && out ? service
        && lib.isAttrs out.service
        && out.service ? command
        && out.service ? env;
    in
    if ok then "${language}: ok" else "${language}: FAIL ${builtins.toJSON (builtins.attrNames out)}";

  # Each language entry in the registry should evaluate via the
  # unified factory. Adding a language is appending its name here.
  languageResults = map testLanguage [ "python" "node" ];
  languageAllOk = builtins.all (r: lib.hasInfix ": ok" r) languageResults;

  factory_shape =
    if languageAllOk then
      "factory_shape: ${toString (builtins.length languageResults)}/${toString (builtins.length languageResults)} passed (${lib.concatStringsSep ", " languageResults})"
    else
      "factory_shape: FAIL — ${lib.concatStringsSep "; " languageResults}";

  # ── workload_shape (plan 71) ──────────────────────────────────────
  #
  # Build a synthetic IR JSON that matches what the Python SDK's
  # `mvm.emit_json()` would write for a single-function workload.
  # `mkFunctionWorkload` should accept this and return a rootfs
  # derivation with the right passthru metadata.
  syntheticIrText = builtins.toJSON {
    schema_version = "0.1";
    id = "shape-test";
    extensions = { };
    volumes = [ ];
    apps = [
      {
        name = "shape-test";
        image = {
          kind = "nix_packages";
          packages = [ "python3" ];
        };
        entrypoints = [
          {
            kind = "function";
            language = "python";
            module = "main";
            function = "handler";
            format = "json";
            primary = true;
            working_dir = "/app";
            args_schema = null;
            return_schema = null;
            concurrency = null;
            env = { };
            extra_imports = [ ];
          }
        ];
        dependencies = {
          kind = "none";
        };
        env = { };
        mounts = [ ];
        network = null;
        resources = {
          cpu_cores = 1;
          memory_mb = 256;
          rootfs_size_mb = 512;
        };
        source = {
          kind = "local_path";
          path = ".";
          include = [ "**" ];
          exclude = [ ];
        };
      }
    ];
  };

  # `builtins.toFile` writes the IR JSON to the store at eval time
  # without invoking a builder — so this test runs offline even on
  # hosts whose remote linux-builder is unavailable. `pkgs.writeText`
  # would create a derivation that requires realization.
  syntheticIrFile = builtins.toFile "shape-test-ir.json" syntheticIrText;

  workloadOut = mkFunctionWorkload {
    irFile = syntheticIrFile;
    inherit appPkg;
  };

  meta = workloadOut.passthru.mvm or { };
  workloadOk =
    workloadOut ? passthru
    && workloadOut.passthru ? mvm
    && (meta.name or "") == "shape-test"
    # mkFunctionWorkload uses entrypoint.command (boot script + sleep
    # idle) — the function dispatcher runs per-call via the agent
    # over vsock, not as PID 1.
    && (meta.entrypointKind or "") == "command"
    && (meta.sealed or false) == true;

  workload_shape =
    if workloadOk then
      "workload_shape: ok (name=${meta.name or "<missing>"}, entrypointKind=${meta.entrypointKind or "<missing>"}, sealed=${if (meta.sealed or false) then "true" else "false"})"
    else
      "workload_shape: FAIL — ${builtins.toJSON meta}";
in
{
  inherit factory_shape workload_shape;
}
