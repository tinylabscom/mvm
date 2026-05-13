# mkFunctionService — bake a function-call workload (ADR-0009 / plan
# 0003 phase 4). Generic across languages: the `language` input drives
# a registry lookup (`languages/<lang>.nix`) that contributes the
# interpreter package + wrapper-script source. The factory body itself
# is identical for every language — it composes the `extraFiles` /
# `servicePackages` / `service` triple that mvm's `mkGuest` consumes.
#
# Plan 60 Phase 5 Slice E1. Replaces mvmforge's per-language factories
# (`mkPythonFunctionService.nix`, `mkNodeFunctionService.nix`) with a
# single dispatcher + a language registry. Adding a new language is
# now one file under `languages/`, not a new factory + caller switch.
#
# v1 wrapper hardening lives inside the per-language wrapper sources
# (`nix/wrappers/python/{oneshot,longrunning}.py`, same for `node/*.mjs`),
# which mirror the audited Rust `mvm-runner` crate's semantics. A
# follow-up PR replaces the inlined script with the compiled
# `mvm-runner` binary at `/usr/lib/mvm/wrappers/runner`; until then,
# **changes to mvm-runner's hardening must be mirrored into the
# wrappers.**
#
# Inputs:
#   pkgs        — nixpkgs.legacyPackages.<system>
#   language    — "python" | "node" (look up in `languages/`)
#   workloadId  — workload id from the IR
#   module      — IR entrypoint.module
#   function    — IR entrypoint.function
#   format      — IR entrypoint.format ("json" | "msgpack")
#   appPkg      — derivation built from the bundled user source
#                 (per ADR-0008)
#   sourcePath  — absolute path inside the rootfs where the user
#                 source tree lives (e.g. "/app")
#   concurrency — optional ADR-0011 concurrency block. When non-null,
#                 the registry picks the language's `longrunning`
#                 wrapper instead of `oneshot`, and the agent picks
#                 the value out of `/etc/mvm/runtime.json` to start
#                 the warm-process pool. Null = cold tier (today's
#                 default).
#
# Outputs (record):
#   extraFiles      — passed straight to mvm's `mkGuest extraFiles`
#   servicePackages — extra packages required in the rootfs
#   service         — `services.<workloadId>` entry for mkGuest

{ pkgs
, language
, workloadId
, module
, function
, format
, appPkg
, sourcePath ? "/app"
, concurrency ? null
, # Pre-merged per-phase hook command lists (SDK port Phase 10a). The
  # caller passes the launch.hooks JSON object verbatim; each phase
  # is `{ kind = "shell"; line = …; }` or `{ kind = "argv"; argv = […]; }`
  # entries. Empty / absent phases are no-ops. Defaults to all-empty
  # so workloads without `@mvm.app(before_start=…)` need no change.
  hooks ? { before_build = [ ]; before_start = [ ]; after_start = [ ]; before_stop = [ ]; }
,
}:

let
  languages = import ./languages { inherit pkgs concurrency; };
  lang =
    languages.${language} or (throw ''
      mkFunctionService: language "${language}" has no entry in the
      language registry. Available: ${builtins.concatStringsSep ", " (builtins.attrNames languages)}.
      Hint: add `nix/lib/factories/languages/${language}.nix` + append
      to `nix/lib/factories/languages/default.nix`, then add the bare
      name to `crates/mvm-ir/data/supported_languages.txt` so the IR
      validator accepts it.
    '');

  # Per-workload runtime config. Mirrors the IR field set on
  # `Entrypoint::Function` (see `crates/mvm-ir/src/workload.rs`) plus
  # the resolved source path. Baked into the rootfs at build time —
  # nothing here is decided at call time.
  #
  # The `concurrency` block (ADR-0011) opts the agent into the
  # warm-process worker pool. Schema mirrors `mvm_guest::
  # runtime_config::RuntimeConfig` exactly so mvm's
  # `serde(deny_unknown_fields)` parse succeeds.
  runtimeJson = builtins.toJSON (
    {
      language = lang.language;
      inherit module function format;
      source_path = sourcePath;
    }
    // (if concurrency == null then { } else { inherit concurrency; })
  );

  # `/etc/mvm/wrapper.json` — config the per-language wrapper reads
  # at startup (separate consumer from `runtime.json`, which is the
  # mvm agent's input). Schema in `nix/wrappers/README.md`.
  wrapperJson = builtins.toJSON {
    inherit module function format;
    working_dir = sourcePath;
    mode = "prod";
  };

  # Lifecycle hooks (SDK port Phase 10b). Each phase is rendered into
  # a shell script under `/etc/mvm/hooks/<phase>.sh`. The script
  # iterates the per-phase command list — `kind = "shell"` lines run
  # via `${pkgs.runtimeShell} -c <line>`; `kind = "argv"` lines run
  # the argv directly via `${pkgs.coreutils}/bin/env --` so paths
  # aren't word-split. The script exits non-zero on the first
  # failing command; consumers (init bootScript, readiness watchdog,
  # shutdown hook) decide how to react.
  #
  # We emit a script even for an empty phase (no commands) so
  # consumers can `test -x /etc/mvm/hooks/<phase>.sh && exec …` on
  # one stable path — no branch on existence. The empty-phase script
  # is a no-op (`exit 0`).
  renderHookCmd = cmd:
    if cmd.kind or "shell" == "argv" then
      "${pkgs.coreutils}/bin/env -- " + (builtins.concatStringsSep " "
        (map (a: pkgs.lib.escapeShellArg a) cmd.argv))
    else
      "${pkgs.runtimeShell} -c " + (pkgs.lib.escapeShellArg cmd.line);

  hookScriptFor = phase: cmds:
    let
      lines = map renderHookCmd cmds;
      body =
        if cmds == [ ]
        then ":"
        else builtins.concatStringsSep "\n" lines;
    in
    pkgs.writeShellScript "${workloadId}-hook-${phase}" ''
      set -eu
      ${body}
    '';

  hookScripts = {
    before_build = hookScriptFor "before-build" (hooks.before_build or [ ]);
    before_start = hookScriptFor "before-start" (hooks.before_start or [ ]);
    after_start = hookScriptFor "after-start" (hooks.after_start or [ ]);
    before_stop = hookScriptFor "before-stop" (hooks.before_stop or [ ]);
  };
in
{
  extraFiles = {
    "/etc/mvm/entrypoint" = {
      content = "/usr/lib/mvm/wrappers/runner";
      mode = "0644";
    };
    "/usr/lib/mvm/wrappers/runner" = {
      content = lang.runnerScript;
      mode = "0755";
    };
    "/etc/mvm/wrapper.json" = {
      content = wrapperJson;
      mode = "0644";
    };
    "/etc/mvm/runtime.json" = {
      content = runtimeJson;
      mode = "0644";
    };
    # Lifecycle hook scripts (SDK port Phase 10b). The bootScript
    # invokes `before_start.sh` before exec'ing PID 1's idle loop;
    # `after_start.sh` is the readiness probe a future watchdog will
    # poll; `before_stop.sh` runs at shutdown when wired by the agent;
    # `before_build.sh` is rendered for parity but runs in the builder
    # VM, which is mid-transition (Plan 72) — the builder consumer
    # lands in Phase 10c.
    "/etc/mvm/hooks/before_build.sh" = {
      content = hookScripts.before_build;
      mode = "0755";
    };
    "/etc/mvm/hooks/before_start.sh" = {
      content = hookScripts.before_start;
      mode = "0755";
    };
    "/etc/mvm/hooks/after_start.sh" = {
      content = hookScripts.after_start;
      mode = "0755";
    };
    "/etc/mvm/hooks/before_stop.sh" = {
      content = hookScripts.before_stop;
      mode = "0755";
    };
  };

  servicePackages = lang.servicePackages;

  # The agent (mvm `RunEntrypoint`) execs the wrapper directly per
  # call; no long-running service is needed. The `service` slot stays
  # populated for `mkGuest`'s shape — it requires every workload-id
  # key to declare a service block — but the command is a no-op idle
  # loop. preStart wires the appPkg symlink as today.
  service = {
    command = pkgs.writeShellScript "${workloadId}-noop" ''
      #!${pkgs.stdenv.shell}
      exec ${pkgs.coreutils}/bin/sleep infinity
    '';
    preStart = pkgs.writeShellScript "${workloadId}-prestart" ''
      set -eu
      mkdir -p "$(dirname ${sourcePath})"
      ln -sfn ${appPkg} ${sourcePath}
    '';
    env = { };
  };
}
