# hello-app (TypeScript)

Minimum-viable `mvm.app({...})(fn)` example. Mirrors
`examples/python/hello-app/` — the parser produces the same IR from
either source language.

## Build

```sh
mvmctl compile examples/typescript/hello-app/app.ts --out /tmp/hello-app
mvmctl build /tmp/hello-app
mvmctl up hello-app
mvmctl invoke hello-app --input name='ari'
```

## Deploy

```sh
mvmctl deploy examples/typescript/hello-app/app.ts --out /tmp/hello-app.tar.gz
```

The decorator + bootscript hook behavior is identical to the Python
example — see that README for what `launch.json` ends up containing.
