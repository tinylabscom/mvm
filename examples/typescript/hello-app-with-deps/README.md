# hello-app-with-deps (TypeScript)

`examples/typescript/hello-app/` plus an npm dependency (`is-number`).

The decorator parser auto-fills source path, entrypoint shape, and language
(`node`) exactly as the no-deps example. The difference is the bundled
`package-lock.json`: `mvmctl build compile` copies it into the artifact, and the
generated `flake.nix` then builds `node_modules` **reproducibly at build time**
inside the builder VM via nixpkgs' `importNpmLock` (hash-free — it reads the
lockfile's integrity hashes directly). `node_modules` is baked into the
read-only app image, so the runtime resolves `/app/node_modules` natively: no
boot-time `npm install`, no runtime network, no separate volume mount.

A lockfile is required — nix fetching is fixed-output, so the deps must be
pinned. Regenerate after editing `package.json`:

```sh
npm install            # writes package-lock.json; node_modules is rebuilt by nix
rm -rf node_modules    # never committed — the build produces it
```

## Build, run, invoke

```sh
mvmctl build compile examples/typescript/hello-app-with-deps/app.ts --out /tmp/hello-ts-deps
mvmctl machine run --flake /tmp/hello-ts-deps
# invoke greet → uses is-number from the baked node_modules
```
