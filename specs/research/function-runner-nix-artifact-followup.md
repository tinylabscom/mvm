# Follow-up: the function-service runner should be a nix-built artifact (per language)

**Status:** proposed (2026-06-02). Companion to the `mkFunctionService`
entrypoint-override fix (drop `/etc/mvm/entrypoint = runner` so PID 1 is
the idle bootScript) — that unblocks Plan 120 Task 4 (boot→ping). This
note covers the *remaining* layer needed for actual function **invocation**
(`mvmctl invoke`), which the boot fix alone does not address.

## The remaining problem

`/usr/lib/mvm/wrappers/runner` is the wrapper the **agent** execs per
`RunEntrypoint` call. It is currently baked by inlining a raw script:

```nix
# nix/lib/factories/languages/python.nix
runnerSource  = if concurrency == null then ../../../wrappers/python/oneshot.py
                else ../../../wrappers/python/longrunning.py;
runnerScript  = builtins.readFile runnerSource;   # ← verbatim string
# nix/lib/factories/mkFunctionService.nix
"/usr/lib/mvm/wrappers/runner" = { content = lang.runnerScript; mode = "0755"; };
```

`readFile` ships the script's bytes **unmodified**, so its shebang ships
unmodified too. `nix/wrappers/python/oneshot.py` starts with
`#!/usr/bin/env python3`; the busybox workload rootfs has **no
`/usr/bin/env`**, so any direct exec of the runner fails `not found`.
(`nix/wrappers/node/*.mjs` has the same shape; node infers ESM and the
README expects `node /usr/lib/mvm/wrappers/runner`.) Two further breaks:

1. **Mode.** Declared `0755`, but a later read-only pass in the rootfs
   build strips owner-write → the baked file is `555`, while the agent's
   entrypoint policy requires `0o755` (`crates/mvm-guest/src/entrypoint.rs:48`)
   → `RunEntrypoint` returns `EntrypointInvalid`.
2. **PATH/deps.** Even with a working interpreter, the wrapper relies on
   the guest's ambient `PATH` and on `python3`/libs being resolvable.

All three are exactly what nix builds solve by construction. The codebase
already says so: `mkFunctionService.nix:15-18` documents the inlined
wrappers as a **stopgap** "until [a] follow-up PR replaces the inlined
script with the compiled `mvm-runner` binary."

## Proposal: nix owns the runner, dispatched by the language registry

The language registry (`nix/lib/factories/languages/<lang>.nix`) already
returns `{ language, runnerScript, servicePackages }`. Change `runnerScript`
from a **raw string** to a **nix-built artifact** (a store path), and have
`mkFunctionService` install it via `source = <store path>` (which preserves
nix's shebang + the store's `555` mode) instead of `content = <string>`.

Per language, in `nix/lib/factories/languages/`:

- **python.nix** — build the wrapper with `pkgs.writers.writePython3`
  (or `makeWrapper`) so nix stamps `#!${pkgs.python3}/bin/python3` and puts
  the runtime libs on `PYTHONPATH`:
  ```nix
  runner = pkgs.writers.writePython3 "mvm-runner"
             { libraries = [ ]; flakeIgnore = [ ... ]; }
             (builtins.readFile ../../../wrappers/python/${variant}.py);
  ```
- **node.nix** — `pkgs.writeShellApplication`/`makeWrapper` that execs
  `${pkgs.nodejs}/bin/node <wrapper.mjs>` (the registry already pins
  `servicePackages = [ pkgs.nodejs ]`).
- Future languages add their own registry entry the same way — the
  interpreter + builder live with the language, not in `mkFunctionService`.

Then `mkFunctionService.nix`:
```nix
"/usr/lib/mvm/wrappers/runner" = { source = lang.runner; };   # was: content = lang.runnerScript;
```
(`source` defaults to mode `0755` in mkGuest's extraFiles; nix's store
file is `555`, which is the correct hardened mode for a read-only wrapper.)

## Also: relax the agent's mode requirement to 0o555

`crates/mvm-guest/src/entrypoint.rs:48` requires `required_mode: 0o755`.
A nix-built wrapper (like the agent binary itself, mk-guest.nix:676
"mode 0555 so the agent can't rewrite itself") is `0o555` — read-only is
the *more* hardened mode. Change the policy to accept/require `0o555`
(no owner-write) and update the `entrypoint.rs` unit tests
(`test_policy(..., 0o755)` → `0o555`). This removes the 555-vs-755
conflict at its source instead of forcing the wrapper writable.

## End state (the documented direction)

The cleanest finish is the compiled, language-agnostic **`mvm-runner`**
Rust binary baked at `/usr/lib/mvm/wrappers/runner` like the agent — no
shebang, no interpreter, mode handled by nix, the per-language dispatch
done in Rust. The `writePython3`/`makeWrapper` step above is the interim
that makes `invoke` work today; the binary is the eventual replacement.

## Acceptance

- `mvmctl invoke hello-app --input name='ari'` returns `hello ari` against
  a running function workload (the agent execs the runner, the runner
  dispatches `greet`, returns the encoded string) — the part Plan 120
  Task 4's boot→ping acceptance does **not** cover.
- The runner's baked shebang resolves inside the rootfs (no `/usr/bin/env`
  dependency); `RunEntrypoint` no longer returns `EntrypointInvalid`.
