# hello-app (TypeScript)

Minimum-viable `mvm.app({...})(fn)` example. Mirrors
`examples/python/hello-app/` — the parser produces the same IR from
either source language.

## Build

```sh
mvmctl build compile examples/typescript/hello-app/app.ts --out /tmp/hello-app
mvmctl machine run --flake /tmp/hello-app --entrypoint
```

The decorator + bootscript hook behavior is identical to the Python
example — see that README for what `launch.json` ends up containing.
