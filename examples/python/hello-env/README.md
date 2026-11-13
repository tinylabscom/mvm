# hello-env (Python)

The landing-page quickstart example: a zero-argument `main()` entrypoint
that reads a baked env var and prints it. Env values are explicit:
`mvm.literal(...)` for a literal (a bare string is refused with an error
naming `mvm.literal` and `mvm.secret`), `mvm.secret(...)` for a secret.

## Build, run, invoke

```sh
mvmctl dev compile examples/python/hello-env/app.py --out /tmp/hello-env
mvmctl machine run --flake /tmp/hello-env --entrypoint
# expect: "hello danny"
```
