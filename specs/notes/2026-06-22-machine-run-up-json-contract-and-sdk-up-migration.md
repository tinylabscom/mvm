# `machine run --up-json` contract + SDK `up`→`machine run` migration

**Date:** 2026-06-22
**Relates to:** [Plan 208](../plans/208-machine-sole-cli-surface-consolidation.md)
(machine CLI consolidation), PR #1266 (SDK ops verbs already migrated).

## Why this note

PR #1266 migrated the live-mode SDKs' operation verbs to `machine`
(`proc`/`fs`/`cp`/`forward`/`wait`/`down` → `machine …`/`machine stop`), but
**deliberately left the `up` boot call on the legacy `up` verb**, because the
SDKs parse `up`'s `--up-json` envelope and `machine run` does not emit a
compatible one yet.

This note pins the **exact contract** `machine run` must satisfy so the boot
call can migrate, and stages the **ready-to-apply SDK diff**. The contract is
not aspirational — it is *defined by what the SDKs already require* (their
`up`-envelope parsers), so the `machine run` side has a fixed target.

## The contract (for the Plan 208 `machine run` work to deliver)

Both SDKs invoke, verbatim:

```
<mvmctl> up --up-json --name <vm_id> --manifest <template> --ttl <N>s
```

and parse stdout as a JSON envelope. So `machine run` must accept the same
surface and emit the same envelope:

### Flags `machine run` must accept
- `--up-json` — **new.** Emit the boot envelope (below) as the *only* thing on
  stdout, then return. Must reserve stdout (route all chrome to stderr — the
  `emits_machine_readable_stdout` guard already added for `machine run --json`
  is the right hook; extend it to `--up-json`).
- `--ttl <duration>` — **new on `machine run`.** Duration string with unit
  (the SDK sends e.g. `1800s`). Sets the same `expires_at` registry field that
  `machine set-ttl` writes; parse via `mvm_core::crypto::policy::parse_ttl`.
- `--name <id>` — exists (Plan 207). The SDK supplies a validated id.
- `--manifest <template>` — exists (Plan 208 sub-step 1).
- Boot must be **persistent + non-blocking** (boot, print envelope, return; the
  VM stays up for the SDK's follow-on `machine proc/fs/…` calls). This is what
  `up --up-json --name` did; the SDK will pair `--up-json` with `-d`/`--detach`
  to get that boot-and-return behavior.

### The stdout envelope `machine run --up-json` must emit
Exactly one JSON object (schema pinned by both SDK parsers):

```json
{"schema_version": 1, "vm_id": "<the --name value>", "build_mode": "dev"}
```

- `schema_version` — integer `1` (Python `_LiveTransport.SCHEMA_VERSION` / TS
  `LiveTransport.SCHEMA_VERSION`). A mismatch makes the SDK reject the boot.
- `vm_id` — non-empty string; the booted VM's id (the `--name` value).
- `build_mode` — `"dev"` or `"prod"`. The SDK enforces claim-4/W4.3 with it
  (only `"dev"` permits `commands.start`/exec). It is the resolved image's
  `passthru.mvm.accessible` / dev-vs-prod build mode.

Non-zero exit ⇒ the SDK raises `SandboxLiveError`; today the `up` path already
fails closed the same way.

## The SDK migration (apply once `machine run --up-json` lands)

A one-line argv change in each SDK — swap `up` for `machine run` and add `-d`
for boot-and-return. **Do not apply until the contract above ships**, or the
SDK live-mode boot breaks (the flags won't parse).

### `sdks/python/mvm/_sandbox.py`
```python
# before
argv = [
    mvm_cli_bin,
    "up",
    "--up-json",
    "--name", vm_id,
    "--manifest", template,
    "--ttl", f"{ttl_seconds}s",
]
# after
argv = [
    mvm_cli_bin,
    "machine", "run", "-d",
    "--up-json",
    "--name", vm_id,
    "--manifest", template,
    "--ttl", f"{ttl_seconds}s",
]
```
Update the method docstring (`Run \`\`mvmctl up --up-json …\`\``) to
`machine run`.

### `sdks/typescript/src/_sandbox.ts`
```ts
// before
const argv = [mvmCliBin, "up", "--up-json", "--name", vmId,
              "--manifest", opts.template, "--ttl", `${opts.ttlSeconds}s`];
// after
const argv = [mvmCliBin, "machine", "run", "-d", "--up-json", "--name", vmId,
              "--manifest", opts.template, "--ttl", `${opts.ttlSeconds}s`];
```

### Test fixtures (both SDKs + the Rust `tests/run_live_mode.rs` fixture)
The fake-`mvmctl` fixtures key the boot on the `up)` case. After the swap the
boot arrives as `machine run …`, which the `machine`-unwrap (added in #1266)
turns into verb `run`. Add a `run)` arm to each fixture that emits the same
envelope the `up)` arm did, and update the `calls[0]` assertions from
`up --up-json …` to `machine run -d --up-json …`.

## Sequencing
1. `machine run` gains `--up-json` + `--ttl` and emits the envelope (Plan 208
   `machine run` work / its B4 slice).
2. Apply the SDK diff above + fixture updates; `up` is then unused by the SDKs.
3. Remove `up` from the CLI (already the Plan 208 plan) — now unblocked on the
   SDK side, since nothing shells to it.

This closes the one carve-out PR #1266 left.
