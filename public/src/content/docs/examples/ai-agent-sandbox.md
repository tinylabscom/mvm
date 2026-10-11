---
title: AI agent sandbox
description: Run agent tool code in an mvm microVM with explicit policy.
---

Use this pattern when an agent needs Linux tools but generated code should not
run directly on the host.

For a stricter model-facing tool API, see [Agent tool contract](/guides/agent-tool-contract/).

## Scaffold

```sh
mvmctl init ./agent-tool --preset python
cd agent-tool
$EDITOR flake.nix
mvmctl machine build
```

Keep the flake pinned. Add only the packages the tool needs.

## Run a tool call

```sh
mvmctl machine run --flake . --name agent-tool -d
mvmctl machine exec agent-tool -- python /work/tool.py
```

For one-off calls. An unnamed run claims a prepared warm standby of the image it boots — here the
`python:3.12-alpine` image a `python` command infers — and refuses rather than
cold-booting without one, so the standby is warmed first; `--name` boots cold.

```sh
export MVM_RESIDENCY=warm                     # Linux defaults to parked: no claims
mvmctl pool warm --image python:3.12-alpine   # the image a `python` command infers
mvmctl run --timeout 20 -- python -c 'print("bounded tool call")'
```

## Security checklist

- Validate model tool inputs before invoking `mvmctl`.
- Start without network access unless the tool needs a named endpoint.
- Keep host mounts narrow and read-only where possible.
- Use secret references rather than plaintext command args.
- Redact stdout/stderr before adding it to model context.
- Stop, destroy, or cold-pause intentionally after the task.
