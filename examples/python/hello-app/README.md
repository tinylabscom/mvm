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

## Build, run, invoke

```sh
mvmctl compile examples/python/hello-app/app.py --out /tmp/hello-app
mvmctl build /tmp/hello-app
mvmctl up hello-app
mvmctl invoke hello-app --input name='ari'
# expect: "hello ari"
```

## Deploy

```sh
mvmctl deploy examples/python/hello-app/app.py --out /tmp/hello-app.tar.gz
# v1 stub: "would ship: /tmp/hello-app.tar.gz → https://mvmd.local/v1"
tar -tzf /tmp/hello-app.tar.gz
# flake.nix  launch.json  mvmd-spec.json  src/app.py
```

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
