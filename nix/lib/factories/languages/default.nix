# Function-service language registry → built entries.
#
# `mkFunctionService` imports this directory and looks up `languages.<name>`
# to learn:
# - which interpreter / runtime package to bake into the rootfs
#   (`servicePackages`)
# - which wrapper-script source to inline at
#   `/usr/lib/mvm/wrappers/runner` (`runnerScript`)
# - the canonical language string emitted into `/etc/mvm/runtime.json`
#   (`language`) — must match the value `mvm-ir`'s validator allowlists in
#   `crates/mvm-ir/data/supported_languages.txt`
#
# The per-language DATA lives in ./registry.nix. THIS file is the single
# generic builder that turns each data row into the triple above — so adding
# a language is a data-row change in registry.nix, never new logic here.
#
# Wasm intentionally lives outside the registry today because its inputs
# differ (the user's `.wasm` module IS the wrapper; no interpreter package is
# baked). When it lands it becomes a row with `interpreter = null` + a
# wrapper-kind discriminator the builder branches on.

{ pkgs, concurrency }:

let
  specs = import ./registry.nix { inherit pkgs; };

  mkLanguage = name: spec:
    let
      # Cold tier (concurrency == null): single-call `oneshot`. Warm-process
      # tier: long-running wrapper speaking the framed multi-call protocol
      # (`mvm_guest::worker_protocol`). Same install path either way — the
      # wrapper itself decides whether to loop. ADR-0011 W-WRAPPER.
      variant = if concurrency == null then "oneshot" else "longrunning";
      runnerSource = ../../../wrappers + "/${spec.wrapperDir}/${variant}.${spec.ext}";
      raw = builtins.readFile runnerSource;
      runnerScript =
        if spec.shebang == null
        then raw
        else builtins.replaceStrings [ spec.shebang.from ] [ "#!${spec.shebang.to}" ] raw;
    in
    {
      language = name;
      inherit runnerScript;
      servicePackages = [ spec.interpreter ];
    };
in
builtins.mapAttrs mkLanguage specs
