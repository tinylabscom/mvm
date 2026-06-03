# Python entry in the function-service language registry.
#
# Plan 60 Phase 5 Slice E1. `mkFunctionService` looks up
# `languages.python` to know which interpreter package to bake into
# the rootfs and which wrapper-script source to inline at
# `/usr/lib/mvm/wrappers/runner`.
#
# Wrapper variants:
# - cold tier (concurrency == null): single-call `oneshot.py`.
# - warm-process tier: long-running `longrunning.py` speaking the
#   framed multi-call protocol (`mvm_guest::worker_protocol`).
# Same install path either way; the agent dispatches the same way and
# the wrapper itself decides whether to loop. ADR-0011 W-WRAPPER.

{ pkgs, concurrency }:

let
  runnerSource =
    if concurrency == null
    then ../../../wrappers/python/oneshot.py
    else ../../../wrappers/python/longrunning.py;
in
{
  language = "python";
  # Stamp the nix interpreter into the shebang. The wrapper source carries
  # `#!/usr/bin/env python3`, but the busybox workload rootfs has no
  # /usr/bin/env, so the agent's per-call exec of the runner would fail
  # `not found`. `pkgs.python3` is in `servicePackages` below, so its
  # store path is in the rootfs closure. oneshot.py is stdlib-only on the
  # JSON path (msgpack/jsonschema are lazy best-effort imports), so a bare
  # python3 shebang suffices — no writePython3/library plumbing.
  runnerScript =
    let raw = builtins.readFile runnerSource; in
    builtins.replaceStrings
      [ "#!/usr/bin/env python3" ] [ "#!${pkgs.python3}/bin/python3" ] raw;
  servicePackages = [ pkgs.python3 ];
}
