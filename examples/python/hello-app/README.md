# hello-app (Python)

Minimum-viable `@mvm.app(...)` example. The decorator parser auto-fills
the source path (`.`), entrypoint shape (`Function { module: "app",
function: "greet", primary: true }`), and language (`"python"`) — you
only need to declare what the IR can't infer.

Demonstrates:

- `mvm.python_image(python="3.12")` — image helper.
- `mvm.resources(cpu=1, memory_mb=256)` — per-VM resource budget.
- `env={"KEY": mvm.literal("value")}` — env var.
- `before_start="..."` — lifecycle hook (string ⇒ Shell command).

## Build and run

```sh
# Compile the decorated function into build artifacts (static parse; no execution).
mvmctl build compile examples/python/hello-app/app.py --out /tmp/hello-app

# Build the image and call its function entrypoint (RunEntrypoint over vsock).
mvmctl machine run --flake /tmp/hello-app --entrypoint
```

`--entrypoint` is the production-safe call surface — no shell, no argv override.


## What gets emitted

`launch.json` carries the merged hooks per phase. With this file:

```json
"hooks": {
  "before_start": [
    { "kind": "shell", "line": "export FOO=1" }
  ]
}
```

The Nix factory bakes `/etc/mvm/hooks/before_start.sh` into the rootfs;
the workload's bootScript runs it before the entrypoint dispatch.
