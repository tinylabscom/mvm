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
mvmctl run --profile restrictive -- python -c 'print("hello")'
mvmctl run --timeout 30 --receipt /tmp/run-receipt.json -- python task.py
```

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
| `restrictive` | Running generated or untrusted code. | No env injection and no host directory shares. |
| `standard` | Normal local runs. | Explicit env is allowed; host shares must be read-only. |
| `dev` | Iterating on a local project. | Host shares may be writable on a persistent machine; a transient run's share stays read-only. Also selects the dev guest profile. |
| `permissive` | Last-resort debugging. | Same grants as `dev`, and refuses unless `MVM_ACK_PERMISSIVE_RUN=1` is set. |

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
