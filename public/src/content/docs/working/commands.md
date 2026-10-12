---
title: Run commands & processes
description: Run commands in a microVM and choose the right command surface.
---

`mvm` has two command styles:

- one-shot sandboxes that boot, run a command, and exit;
- commands inside an already-running named microVM.

Use one-shot mode for isolated code execution. Use named-VM commands when you are working with persistent state, services, logs, or cold-mode recovery.

## One-shot run

An unnamed one-shot run claims a prepared warm standby booted from the same
image and sizing, and refuses rather than cold-booting when none is ready, so
prepare one per image first. A `python` command infers `python:3.12-alpine`
(see [runtime detection](/reference/cli-commands/#runtime-detection)), so it
needs a standby of that image:

```sh
export MVM_RESIDENCY=warm                     # Linux defaults to parked: no claims
mvmctl pool warm                              # the bundled default image
mvmctl pool warm --image python:3.12-alpine   # the image python commands infer
mvmctl run -- uname -a
mvmctl run --profile restrictive -- python -c 'print("hello")'
mvmctl run --timeout 30 --receipt /tmp/run-receipt.json -- python task.py
```

Add `--name` to boot a run cold instead; a named run never claims a standby.

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
| `restrictive` | Running generated or untrusted code. | No env injection, no host directory shares, and no disk images. |
| `standard` | Normal local runs. | Explicit env is allowed; host directory shares must be read-only, on transient runs only; a sized disk image (`HOST.img:/GUEST:SIZE:rw`) may be writable. |
| `dev` | Iterating on a local project. | Same grants as `standard`, plus the dev guest profile. No profile makes a host directory writable, and a persistent machine takes none. |
| `permissive` | Last-resort debugging. | Same grants as `dev`, and refuses unless `MVM_ACK_PERMISSIVE_RUN=1` is set. |

## Security notes

- Prefer argv arrays and explicit command arguments.
- Avoid passing secrets through command-line args.
- Use receipts for automation and audit correlation.
- Keep host shares narrow in untrusted runs.
- Treat stdout and stderr as sensitive because guest code controls them.

## Related pages

- [Sandbox management](/working/sandbox-management/)
- [Filesystem operations](/working/filesystem/)
- [Policy profiles](/guides/policy-profiles/)
- [Audit and receipts](/guides/audit-and-receipts/)
- [Error handling](/tutorials/error-handling/)
