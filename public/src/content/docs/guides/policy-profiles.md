---
title: Policy profiles
description: Choose the right run profile, host-share mode, and environment policy for a sandboxed workload.
---

Policy profiles are the first security decision for a sandbox run. Pick the
least permissive profile that lets the workload do its job, then add filesystem,
environment, and network permissions deliberately.

For generated code, third-party code, model tool calls, and CI jobs, start with
`restrictive` and relax only the specific boundary that blocks the workload.

## One-shot run profiles

`mvmctl run` supports four profile intents:

| Profile | Default use | Host shares | Environment injection |
| --- | --- | --- | --- |
| `restrictive` | Generated or untrusted code. | Not allowed. | Not allowed. |
| `standard` | Normal local one-shot runs. | Read-only. | Explicit `--env KEY=VAL` allowed. |
| `dev` | Local iteration against a project tree. | Read-only here; writable only on a *persistent* machine. | Explicit `--env KEY=VAL` allowed. |
| `permissive` | Last-resort local debugging. | Same as `dev`, plus `MVM_ACK_PERMISSIVE_RUN=1`. | Explicit `--env KEY=VAL` allowed. |

A one-shot run's host shares are **read-only under every profile** — the
writable grant applies only when the machine is persistent. Guest mount paths
must be under `/data` or `/work`.

The default is `standard`. Use `restrictive` when the workload does not need
host files or host-provided environment values:

```sh
mvmctl run --profile restrictive -- python task.py
```

Use `standard` when the workload needs explicit environment values or
read-only input files:

```sh
mvmctl run --profile standard --mount ./fixtures:/data/fixtures:ro -- python task.py
```

Use `dev` for local development commands that need the broader development
profile. Transient host-directory shares remain read-only:

```sh
mvmctl run --profile dev --mount .:/work:ro -- cargo test
```

Use `permissive` only when a local experiment needs the escape hatch. It
requires an explicit acknowledgement so broad execution is visible:

```sh
MVM_ACK_PERMISSIVE_RUN=1 mvmctl run --profile permissive -- ./debug-script.sh
```

## Filesystem policy

Transient host directory mounts are declared with:

```sh
mvmctl run --mount HOST:GUEST:ro -- command
```

Rules:

- the mode must be `ro` — a transient run refuses `:rw` under every profile;
- `GUEST` must be under `/data` or `/work`; every other root is refused, and
  `/mnt/*` is refused specifically so a share cannot shadow the runtime's own
  config and secrets drives;
- `restrictive` rejects host directory shares;
- `standard` accepts read-only host shares.

Prefer read-only shares for test inputs, source snapshots, fixtures, and model
context. Use `mvmctl machine cp` or a managed volume when changes must persist.

:::note[Hidden verbs]
`machine cp`, `machine fs`, `machine volume`, `machine wait`, `machine
boot-report`, `machine checkpoint`, `machine pause` and `machine resume` all
work but are marked hidden, so they do not appear in `--help` output.
:::

## Environment policy

Use explicit environment injection:

```sh
mvmctl run --env TASK_MODE=check -- python task.py
```

Rules:

- `restrictive` rejects `--env`.
- `standard`, `dev`, and `permissive` allow explicit `--env KEY=VAL`.
- Do not pass secrets through argv or `--env`; use managed secret references
  where a secret is required.

Environment values are easy to leak through process listings, shell history,
debug output, and crash reports. Treat them as configuration, not as a secret
delivery path.

## Dry-run before relaxing policy

Use dry-run mode to check a run plan without resolving an image, booting a VM,
executing the command, or writing a receipt:

```sh
mvmctl run --dry-run --json --profile restrictive -- python task.py
```

Dry-run output is redacted. It is useful in CI because policy failures can be
caught before a workload starts.

## Seccomp tier

There is **no per-launch seccomp selector**. Every plan `mvmctl` synthesises
hardcodes the `standard` tier, and `--profile` carries no seccomp field — a
profile governs `--env`, host shares, writable-share eligibility, the dev
guest profile, and whether an acknowledgement is required, and nothing else.

The tier is still recorded in the signed admission profile, so an audit can
show which tier was admitted; it just cannot vary per run today. The
`PlanSeccompTier` type has five values (`essential`, `minimal`, `standard`,
`network`, `unrestricted`) and the plumbing to carry them, but no CLI flag
and no manifest key feeds it.

The one place you can name a tier is the hidden developer command
`mvmctl seccomp-audit --tier <tier>`, which is Linux-only, boots no microVM,
and installs no filter — it only reports on a syscall set.

## Recommended defaults

| Workload | Start with | Add only if needed |
| --- | --- | --- |
| Model-generated code | `mvmctl run --profile restrictive` | Read-only fixtures after review. |
| Code interpreter | `mvmctl run --profile restrictive` | A bounded work directory or receipt output. |
| CI validation | `mvmctl run --profile standard` | Read-only source share and explicit non-secret env. |
| Local development | `mvmctl run --profile dev` | Writable project share. |
| Long-running local service | `mvmctl machine run --profile standard` | Explicit ports, volumes, and readiness checks. |

Security-first defaults should feel slightly strict. A denied `--env` or
writable share is a useful signal that the run is crossing a boundary.

## Audit and receipts

Profiles affect the run's policy surface, so include evidence with automated
runs:

```sh
mvmctl run --profile restrictive --receipt /tmp/run-receipt.json -- python task.py
mvmctl trust receipt verify /tmp/run-receipt.json
```

Use [audit and receipts](/guides/audit-and-receipts/) for portable proof and
host-local investigation. Keep policy identifiers, run IDs, and audit IDs in
higher-level logs instead of copying raw command payloads there.

## Related pages

- [Run commands and processes](/working/commands/)
- [Config and secrets](/guides/config-secrets/)
- [Secrets and credentials](/guides/secrets-and-credentials/)
- [Networking](/guides/networking/)
- [Network egress policy](/guides/network-egress-policy/)
- [Security and isolation](/architecture/security-isolation/)
