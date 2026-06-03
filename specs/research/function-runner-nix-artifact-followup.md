# Follow-up: make `mvmctl invoke` work on a function workload

**Status:** spec (2026-06-02). Companion to the boot→ping fixes in this
PR (#537). Those got the function workload to **boot and answer `Ping`**
(Plan 120 Task 4). This note covers the *remaining* layer — actual
function **invocation** (`mvmctl invoke` → vsock `RunEntrypoint`), which
boot→ping does not exercise. Grounded in the live trace + the agent code
(`crates/mvm-guest/src/entrypoint.rs`, `bin/mvm-guest-agent.rs`).

## What the boot→ping trace revealed

With the workload finally staying up, the agent logs at boot:

```
mvm-guest-agent: entrypoint validation failed at boot:
  entrypoint marker contents not absolute: #!/bin/sh
  /nix/store/…-greet-boot; RunEntrypoint requests will return EntrypointInvalid
```

So there are **two** independent invoke blockers, in priority order:

### 1. (primary) `/etc/mvm/entrypoint` is overloaded — marker vs boot command

`/etc/mvm/entrypoint` has two *incompatible* consumers:

- **`/init`** (`nix/lib/mk-guest.nix`) **sources** it as PID 1's boot
  command. For a function workload that's the idle `funcBootScript`
  (`exec sleep infinity`) — a `#!/bin/sh` script.
- **The agent** (`EntrypointPolicy::production()`,
  `entrypoint.rs:43`) reads it as a **marker whose contents must be a
  bare absolute path** to the per-call runner under
  `/usr/lib/mvm/wrappers/`, then `RunEntrypoint` execs *that* per call.

One file cannot be both a shell script and a bare path. The history
proves the conflict is fundamental, not a bug:

- **Before #537:** `mkFunctionService` wrote `/etc/mvm/entrypoint =
  /usr/lib/mvm/wrappers/runner` (a bare path). The agent marker was
  *valid* — but PID 1 became the one-shot runner → reboot.
- **After #537:** `/etc/mvm/entrypoint` is the idle bootScript. PID 1 is
  correct — but the agent marker is now a script → `NotAbsolute` →
  `EntrypointInvalid`.

The two requirements move in opposite directions on the same file. **They
must be different files.**

Note the agent's boot validation is **non-fatal** (`init_entrypoint_validation`,
`mvm-guest-agent.rs:1440` — logs one line, agent stays up, only
`RunEntrypoint` fails). Command (non-function) workloads never call
`RunEntrypoint`, so they tolerate a missing/failed marker. The marker is
therefore a *function-workload* concept.

### 2. (secondary) the runner isn't executable in the rootfs

`/usr/lib/mvm/wrappers/runner` is what the agent execs per call. It's
baked by inlining the raw wrapper bytes:

```nix
# nix/lib/factories/languages/python.nix
runnerScript = builtins.readFile ../../../wrappers/python/oneshot.py;
# nix/lib/factories/mkFunctionService.nix
"/usr/lib/mvm/wrappers/runner" = { content = lang.runnerScript; mode = "0755"; };
```

`readFile` ships the bytes verbatim, so `oneshot.py`'s
`#!/usr/bin/env python3` ships verbatim — and the busybox workload rootfs
has **no `/usr/bin/env`**, so a direct exec fails `not found`. (Even once
the marker points here, this is the next failure.)

## Design

### Decouple the marker from the boot command (fixes blocker 1)

Keep `/etc/mvm/entrypoint` as PID 1's boot command (unchanged — `/init`
keeps sourcing it). Give the agent its **own** marker file:

- New file `/etc/mvm/runner`, contents = `/usr/lib/mvm/wrappers/runner\n`
  (a bare absolute path). Written only by `mkFunctionService` (only
  function workloads have a runner).
- `EntrypointPolicy::production().marker_path` → `/etc/mvm/runner`.

Command workloads have no `/etc/mvm/runner`; the agent's marker read
fails benignly (`ReadMarker`, already non-fatal) instead of the current
misleading `NotAbsolute` on the boot script — strictly clearer.

### Fix the runner shebang (fixes blocker 2) — shebang rewrite, not a full artifact

`oneshot.py` is **stdlib-only on the JSON path** (`msgpack`/`jsonschema`
are lazy, best-effort imports — see `_decode_msgpack`, `_validate_against_schema`).
`pkgs.python3` is already baked via the registry's `servicePackages`, so
its store path is in the rootfs closure. The minimal correct fix is to
stamp the nix interpreter into the shebang — no `writePython3`, no
library plumbing:

```nix
# nix/lib/factories/languages/python.nix
runnerScript =
  let raw = builtins.readFile runnerSource; in
  builtins.replaceStrings
    [ "#!/usr/bin/env python3" ] [ "#!${pkgs.python3}/bin/python3" ] raw;
```

`mkFunctionService` keeps `content = lang.runnerScript; mode = "0755"`.
`mkGuest`'s `install -m 0755` lands it at exactly 0755 in the rootfs
(`mk-guest.nix:558`), owned root by the rootfs build.

**Mode: the agent must require 0555.** The live trace showed the baked
runner is `555`, not `755` (`runner has mode 555 (must be 755)`):
mkGuest's rootfs hardening pass strips owner-write from baked files —
`install -m 0755` does not survive it — and the agent binary itself is
`555`. So set `EntrypointPolicy.required_mode = 0o555` (read-only is the
*more* hardened mode) and declare the runner at `mode = "0555"` so the
baked mode is honest rather than relying on the strip pass. (The original
draft's `0o555` instinct was right; an intermediate "install -m forces
0755, no relaxation needed" reasoning was wrong — it missed the strip
pass, and the live trace caught it.)

#### Node

`oneshot.mjs` is ESM and needs the `node` runtime — a shebang rewrite
alone won't do (a shebang'd file with no `.mjs` extension loads as
CommonJS and the ESM syntax fails). Install two files via the registry
instead, keeping `mkFunctionService` language-generic by having the
registry return a set of runner files rather than one string:

```nix
# node.nix contributes:
#   /usr/lib/mvm/wrappers/runner.mjs  (content = the wrapper, mode 0644)
#   /usr/lib/mvm/wrappers/runner      (content = "#!${runtimeShell}\n
#                                       exec ${nodejs}/bin/node \
#                                       /usr/lib/mvm/wrappers/runner.mjs \"$@\"",
#                                       mode 0755)
```

The marker still points at `/usr/lib/mvm/wrappers/runner`; the shell shim
is the executable the agent validates and execs. `${pkgs.nodejs}` is
already in `servicePackages`, so its closure is in the rootfs.

To support both shapes cleanly, change the registry contract from
`runnerScript` (one string) to `runnerFiles` (a `{ "<rel-path>" = {
content/source; mode }; }` attrset that `mkFunctionService` merges into
`extraFiles` under `/usr/lib/mvm/wrappers/`). Python contributes one
entry, node two.

## Files to change

- `crates/mvm-guest/src/entrypoint.rs` — `marker_path` →
  `/etc/mvm/runner`; `required_mode` → `0o555`; update the mode-sensitive
  unit tests and the module doc-comment.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs`,
  `crates/mvm-guest/src/vsock.rs` — comments naming `/etc/mvm/entrypoint`
  as the marker → `/etc/mvm/runner`.
- `nix/lib/factories/languages/{python,node}.nix` — fix the python
  shebang; node contributes the shim + `.mjs`; switch the registry
  contract to `runnerFiles`.
- `nix/lib/factories/mkFunctionService.nix` — install `lang.runnerFiles`
  under `/usr/lib/mvm/wrappers/`; add the `/etc/mvm/runner` marker
  (`content = "/usr/lib/mvm/wrappers/runner\n"`).

## Acceptance

- `mvmctl invoke hello-app --input name='ari'` returns `hello ari`
  against a running function workload: agent boot logs `entrypoint
  validated at /usr/lib/mvm/wrappers/runner`, `RunEntrypoint` execs the
  runner, the runner dispatches `greet` and returns the encoded string.
- The runner's baked shebang resolves inside the rootfs (no
  `/usr/bin/env` dependency); `RunEntrypoint` no longer returns
  `EntrypointInvalid`.
- Boot→ping (Task 4) still green — `/etc/mvm/entrypoint` is untouched,
  so PID 1 still idles.

## Why not the compiled `mvm-runner` binary now

`mkFunctionService.nix:15-18` documents the eventual end state: a
compiled, language-agnostic `mvm-runner` Rust binary at
`/usr/lib/mvm/wrappers/runner` (no shebang, no interpreter, dispatch in
Rust). That's the clean finish, but it's a larger build-system change.
The shebang rewrite + marker decouple above makes `invoke` work today
against the existing audited wrappers; the binary is the later
replacement, and the marker decoupling it needs is identical.
