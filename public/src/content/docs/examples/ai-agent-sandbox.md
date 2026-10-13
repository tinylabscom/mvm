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

For one-off calls:

```sh
mvmctl run --timeout 20 -- python -c 'print("bounded tool call")'
```

## Security checklist

- Validate model tool inputs before invoking `mvmctl`.
- Start without network access unless the tool needs a named endpoint.
- Keep host mounts narrow and read-only where possible.
- Use secret references rather than plaintext command args.
- Redact stdout/stderr before adding it to model context.
- Stop, destroy, or cold-pause intentionally after the task.
