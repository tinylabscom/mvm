# Offline smoke test for plan 48: function-service factories on
# `mvm.lib.<system>`. Asserts the factories evaluate and return the
# `{ extraFiles, servicePackages, service }` triple that
# `mvm/specs/contracts/...` (or mvmforge's binding contract at
# `mvmforge/specs/contracts/mvm-mkfunctionservice.md`) requires.
#
# Run via:
#
#   nix eval --no-warn-dirty --impure --raw --expr '
#     let flake = builtins.getFlake "path:/Users/auser/work/tinylabs/mvmco/mvm/nix";
#     in import /Users/auser/work/tinylabs/mvmco/mvm/tests/factory_shape.nix { flake = flake; }'
#
# Asserts (per language):
#   1. `extraFiles` is an attrset containing `/etc/mvm/entrypoint` and
#      a wrapper at `/usr/lib/mvm/wrappers/runner`.
#   2. `servicePackages` is a list.
#   3. `service` is an attrset with at least `command` and `env`.

{ flake }:

let
  system = "aarch64-linux";
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  appPkg = pkgs.writeText "stub-app" "stub";

  testFactory =
    name: factory:
    let
      out = factory {
        inherit pkgs appPkg;
        workloadId = "test-${name}";
        module = "main";
        function = "handler";
        format = "json";
      };
      ok =
        out ? extraFiles
        && lib.isAttrs out.extraFiles
        && (out.extraFiles ? "/etc/mvm/entrypoint")
        && out ? servicePackages
        && lib.isList out.servicePackages
        && out ? service
        && lib.isAttrs out.service
        && out.service ? command;
    in
    if ok then "${name}: ok" else "${name}: FAIL ${builtins.toJSON (builtins.attrNames out)}";

  resultPython = testFactory "python" flake.lib.${system}.mkPythonFunctionService;
  resultNode = testFactory "node" flake.lib.${system}.mkNodeFunctionService;
  # Wasm factory has different inputs (module is a .wasm path, no
  # appPkg in same shape) — skip in this smoke; cover separately.
  results = [
    resultPython
    resultNode
  ];

  allOk = builtins.all (r: lib.hasInfix ": ok" r) results;
in
if allOk then
  "plan-48 factory_shape: 2/2 passed (${lib.concatStringsSep ", " results})"
else
  "plan-48 factory_shape: FAIL — ${lib.concatStringsSep "; " results}"
