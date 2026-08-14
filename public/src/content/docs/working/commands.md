---
title: Run commands & processes
description: Run commands in a microVM and choose the right command surface.
---

`mvm` has two command styles:

- one-shot sandboxes that boot, run a command, and exit;
- commands inside an already-running named microVM.

Use one-shot mode for isolated code execution. Use named-VM commands when you are working with persistent state, services, logs, or cold-mode recovery.

## One-shot run

```sh
mvmctl run -- uname -a
mvmctl run python3 script.py
mvmctl run --template python script.py
mvmctl run --profile restrictive -- python -c 'print("hello")'
mvmctl run --timeout 30 --receipt /tmp/run-receipt.json -- python task.py
```

When no image, manifest, or launch plan is supplied, `mvmctl run` auto-detects
a runtime from the trailing command (`python3`, `npm`, `cargo`, `go`, ...) and,
as a fallback, from project files in the working directory (`requirements.txt`,
`package.json`, `Cargo.toml`, ...). The detected image is a conservative,
pinned OCI reference such as `python:3.12-alpine`. Use `--no-detect` to force
the bundled default microVM, or `--image <ref>` to override.

`mvmctl run` produces a transient sandbox. It can write a signed receipt with invocation hashes, output hashes, and exit status. Raw argv, env values, stdout, stderr, and host paths are not stored in the receipt.

Use dry-run mode to inspect policy effects without booting:

```sh
mvmctl run --dry-run --json -- python task.py
```

## Named VM commands

```sh
mvmctl machine run --flake ./my-app --name agent-sandbox -d
mvmctl machine exec agent-sandbox -- python /work/task.py
mvmctl machine logs agent-sandbox -f
```

Use this path when the VM has state, files, services, or snapshots that should survive across commands.

## Profiles

| Profile | Use it when | Notes |
| --- | --- | --- |
| `restrictive` | Running generated or untrusted code. | No `--env`, `--mount`, `--net`, or `--allow-host`. Seccomp tier: `essential`. |
| `standard` | Normal local runs. | Explicit `--env` allowed; host shares are read-only. Network is default-deny unless you opt in with `--net`/`--allow-host`. Seccomp tier: `standard`. |
| `dev` | Iterating on a local project. | Explicit `--env` allowed; writable host shares allowed. Seccomp tier: `network`. |
| `permissive` | Last-resort debugging. | Same capabilities as `dev`, plus `seccomp=unrestricted`. Requires `MVM_ACK_PERMISSIVE_RUN=1`. |

Network egress remains default-deny for every profile except where you pass `--net` or `--allow-host`; `restrictive` refuses those flags outright.

## Security notes

- Prefer argv arrays and explicit command arguments.
- Avoid passing secrets through command-line args.
- Use receipts for automation and audit correlation.
- Keep writable host shares out of untrusted runs.
- Treat stdout and stderr as sensitive because guest code controls them.

## Related pages

- [Sandbox management](/working/sandbox-management/)
- [Filesystem operations](/working/filesystem/)
- [Policy profiles](/guides/policy-profiles/)
- [Audit and receipts](/guides/audit-and-receipts/)
- [Error handling](/tutorials/error-handling/)
