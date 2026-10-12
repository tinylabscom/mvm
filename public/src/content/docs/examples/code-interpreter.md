---
title: Code interpreter pattern
description: Run user-provided code in a bounded mvm sandbox.
---

A code interpreter accepts source text, runs it, and returns output. The
important rule is that user code runs in the guest, not in the host process.

## One-shot interpreter

```sh
export MVM_RESIDENCY=warm                     # Linux defaults to parked: no claims
mvmctl pool warm --image python:3.12-alpine   # the image `--runtime python` boots
mvmctl machine run --runtime python --timeout 10 -- python - <<'PY'
print("hello from inside the sandbox")
PY
```

Use this shape for stateless calls where every invocation should start clean.
An unnamed run claims a prepared warm standby of the image it boots and refuses
rather than cold-booting without one, which is why the standby is warmed first.
Piped stdin reaches the guest only on a transient `mvmctl machine run`; the
top-level `mvmctl run` does not forward it, so the guest would read EOF.

## Persistent interpreter

```sh
mvmctl init ./interpreter --preset python
mvmctl machine build --flake ./interpreter
mvmctl machine run --flake ./interpreter --name interpreter -d
mvmctl machine exec interpreter -- python /work/run_cell.py
```

Use a named VM when you intentionally want cached packages, files, or session
state across cells.

## Security checklist

- Enforce input size limits before invoking the sandbox.
- Set a timeout.
- Bound stdout/stderr returned to the caller.
- Disable network unless the interpreter needs named endpoints.
- Never pass host credentials through argv.
- Delete or snapshot state intentionally.
