# The TypeScript machine wrapper bounds its subprocess

Delivered 2026-08-16. Closes #2558.

## What was wrong

`_machine.ts` called `child.spawnSync(bin, ["machine", ...argv], { encoding:
"utf-8" })` with no `timeout` and no `maxBuffer`. Two consequences, one of them
worse than it looks:

- **Unbounded wait.** Node applies no default timeout. A `mvmctl machine` call
  that hangs hangs the caller, with no recovery.
- **A wrong diagnosis, not just a missing feature.** `spawnSync` defaults to a
  1 MiB `maxBuffer` and reports the overflow through `result.error` with code
  `ENOBUFS`. The wrapper turned *any* `result.error` into
  ``failed to spawn `${bin}` ``, so a machine that ran perfectly and simply
  talked a lot was reported as one that could not be started. That sends the
  reader to check `MVM_CLI_BIN` and `PATH` for a problem that is neither.

The Python SDK bounded both, through `run_capped`, with typed
`TransportTimeout` / `TransportOutputOverflow`.

## Why this was known and still open

It was not undetected drift. The env-name registry work deliberately did *not*
emit `MVM_MACHINE_TIMEOUT_ENV` / `MVM_MACHINE_MAX_OUTPUT_ENV` into TypeScript,
because nothing there read them: emitting the constants would have cleared the
last two entries from `surface_divergence.json` while changing no behaviour, and
the gate would then have certified a parity that did not exist. Each registry
row names the surfaces that actually *read* it, an s27 step checks that claim in
both directions, and a unit test pinned this pair as not-TypeScript.

So the mechanism worked. What was missing was the behaviour.

## What changed

**`src/_env/read.ts`** — `envFloat` / `envInt`, mirroring `_subprocess.py`'s
readers including the part worth stating out loud: absent, empty and
unparseable all fall back to the default, silently. Matching Python rather than
improving on it is the point; two SDKs that disagree about what a malformed
value means is the divergence class this whole registry exists to close.

**`src/_machine.ts`** — passes `timeout` and `maxBuffer` to `spawnSync`, and
classifies `result.error` instead of flattening it:

- `ETIMEDOUT` → ``did not exit within ${n}s``
- `ENOBUFS` → ``exceeded ${n} bytes on stdout or stderr``
- anything else → the existing spawn-failure message, which is now true when it
  is used

A signalled child (`status === null`, `signal` set) is also named now rather
than reported as "exit code null".

Two honest differences from Python, both commented at the seam:

- A zero timeout means "no timeout" to `spawnSync` and "give up at once" to
  Python. Left unhandled, a `MVM_MACHINE_TIMEOUT_SEC=0` would silently restore
  the unbounded wait this change removes, so the millisecond value is floored
  at 1.
- Node does not say which stream overflowed. Python caps each independently and
  names it; this names the cap, not the side.
- `spawnSync` signals only the child, not its process group. A grandchild that
  outlives the kill can still hold the pipes. The wait is bounded either way;
  the reap is best-effort.

**`crates/mvm-sdk/src/env.rs`** — both rows now list `TypeScript`, and
`machine_vars_are_not_claimed_for_typescript` is inverted into
`machine_vars_are_claimed_for_typescript`, so the honesty property still holds
and now fails if the behaviour is ever removed and the claim left behind.
`cargo xtask gen-stubs` regenerated `_env/vars.ts` and `schema/sdk-env-v0.json`;
`surface_divergence.json` drops the two names, and its comment records why they
were there and how they left.

## The gap this uncovered

Neither SDK's unit suite ran anywhere in CI. `crates/mvm-sdk/sdks/python/tests`
(212 tests) and `sdks/typescript/tests` (138) are not cargo targets, so
`cargo nextest run --workspace` never saw them, and no workflow invoked `pytest`
or `vitest`. A vitest regression for this bug would have been a decoration.

Added `just sdk-test` and a step on the BDD lane, which is already scoped to
`crates/mvm-sdk/` and already installs uv, Node and the TypeScript dependencies.
`--extra schema` is passed to pytest so the eight `derive_schema` tests install
pydantic and run, rather than failing on an ImportError.

## Not done here

The TypeScript wrapper still has no typed error hierarchy — timeout and overflow
are `MachineError` with distinct messages, which is exactly what Python's
`_machine.py` surfaces to its own callers after catching the typed transport
exceptions. A shared taxonomy is Tier D of the generated-surface plan.
