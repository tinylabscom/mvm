# hello-env (Python)

The landing-page quickstart example: a zero-argument `main()` entrypoint
that reads a baked env var and prints it. Bare strings in `env={...}` are
literals; `examples/python/hello-app/` shows the same thing with the
explicit `mvm.literal(...)` wrapper.

## Build, run, invoke

```sh
mvmctl build compile examples/python/hello-env/app.py --out /tmp/hello-env
mvmctl machine run --flake /tmp/hello-env --entrypoint
# expect: "hello danny"
```
