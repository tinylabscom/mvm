# Function-service language registry — DATA ONLY.
#
# Each row states what is *genuinely* language-specific; the generic builder
# in ./default.nix turns a row into the `{ language; runnerScript;
# servicePackages; }` triple `mkFunctionService` bakes into the rootfs.
#
#   interpreter   nixpkgs package baked into the rootfs (→ servicePackages)
#   wrapperDir    subdir under nix/wrappers/ holding oneshot.* / longrunning.*
#   ext           wrapper file extension
#   shebang       optional { from; to } stamp — the busybox workload rootfs
#                 has no /usr/bin/env, so a `#!/usr/bin/env <x>` wrapper would
#                 fail the agent's per-call exec; stamp the nix store path
#                 instead. `null` when the runtime needs none.
#
# Adding a language is one ROW here + the bare name in
# `crates/mvm-ir/data/supported_languages.txt`. No new .nix file, no logic.
# The only other per-language artifact is the wrapper script under
# nix/wrappers/<wrapperDir>/ — unavoidable, since dispatch genuinely differs.

{ pkgs }:

{
  python = {
    interpreter = pkgs.python3;
    wrapperDir = "python";
    ext = "py";
    # oneshot.py is stdlib-only on the JSON path (msgpack/jsonschema are lazy
    # best-effort imports), so a bare python3 shebang suffices.
    shebang = {
      from = "#!/usr/bin/env python3";
      to = "${pkgs.python3}/bin/python3";
    };
  };

  node = {
    # Pin Node 22: the wrapper `import()`s the user's `.ts` directly and relies
    # on default-on type stripping (Node >=22.18). The floating `pkgs.nodejs`
    # alias could move to a build without it; nodejs_22 keeps it deterministic.
    interpreter = pkgs.nodejs_22;
    wrapperDir = "node";
    ext = "mjs";
    # Stamp the store path: the agent `fexecve`s the baked runner directly, so
    # its `#!/usr/bin/env node` shebang would ENOENT on the env-less busybox
    # rootfs. The runner is baked extensionless (`/usr/lib/mvm/wrappers/runner`);
    # Node >=22.7 auto-detects the ESM `import` syntax, so no `.mjs` is needed.
    shebang = {
      from = "#!/usr/bin/env node";
      to = "${pkgs.nodejs_22}/bin/node";
    };
  };
}
