---
title: Policy profiles
description: Choose the right run profile, host-share mode, environment policy, and seccomp tier for a sandboxed workload.
---

Policy profiles are the first security decision for a sandbox run. Pick the
least permissive profile that lets the workload do its job, then add filesystem,
environment, network, and seccomp permissions deliberately.

For generated code, third-party code, model tool calls, and CI jobs, start with
`restrictive` and relax only the specific boundary that blocks the workload.

## One-shot run profiles

`mvmctl run` supports four profile intents:

| Profile | Default use | Host shares | Environment injection |
| --- | --- | --- | --- |
| `restrictive` | Generated or untrusted code. | Not allowed. | Not allowed. |
| `standard` | Normal local one-shot runs. | Read-only only. | Explicit `--env KEY=VAL` allowed. |
| `dev` | Local iteration against a project tree. | Read-only or writable. | Explicit `--env KEY=VAL` allowed. |
| `permissive` | Last-resort local debugging. | Broadest local mode. | Explicit `--env KEY=VAL` allowed. |

The default is `standard`. Use `restrictive` when the workload does not need
host files or host-provided environment values:

```sh
mvmctl run --profile restrictive -- python task.py
```

Use `standard` when the workload needs explicit environment values or
read-only input files:

```sh
mvmctl run --profile standard --mount ./fixtures:/fixtures:ro -- python task.py
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

- the mode must be `ro`;
- `restrictive` rejects host directory shares;
- `standard` accepts read-only host shares.

Prefer read-only shares for test inputs, source snapshots, fixtures, and model
context. Use `mvmctl machine cp` or a managed volume when changes must persist.

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

## Seccomp tiers for named VMs

Named VM launches expose a separate seccomp tier:

```sh
mvmctl machine run --flake ./my-app --name agent-sandbox -d --profile standard
```

Supported tiers are:

| Tier | Use it when |
| --- | --- |
| `essential` | The workload needs the smallest syscall surface the current guest can boot with. |
| `minimal` | The workload is simple and should run with a reduced syscall set. |
| `standard` | Default named-VM posture. |
| `network` | The workload needs network-oriented syscalls beyond the standard profile. |
| `unrestricted` | Local debugging only; avoid for untrusted code. |

The selected tier is recorded in the signed admission profile for audit.

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
