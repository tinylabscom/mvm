# hello-app-with-deps (Python)

`@mvm.app(...)` example with a `dependencies=mvm.python_deps(...)` clause
backed by a pinned `uv.lock`. The compile step is the same shape as
`examples/python/hello-app/` — the new bit is that the install pipeline
(Plan 73 Followup B.2) materializes a sealed deps volume at
`~/.mvm/volumes/deps/<volume_hash>/` carrying:

- `content/` — the installed `site-packages` tree.
- `sbom.cdx.json` — CycloneDX 1.5 SBOM produced by `cyclonedx-py`.
- `fetch.log` — every URL the installer dialed.
- `cve.json` — pip-audit scan output.
- `meta.json` — schema version + per-artifact sha256s + the canonical
  manifest the supervisor admission gate (Followup A) pins.

This example is the positive-path fixture for the Followup D CI gate
(`.github/workflows/security.yml::app-deps-audit`): the lockfile is
hash-pinned, the resolved deps scan clean under pip-audit at the time
this example was added, and the `mvmctl compile` step emits a launch.json
with a `dependencies` field the supervisor wires into the workload's
mount layout.

## Compile (no VM needed)

```sh
mvmctl build compile examples/python/hello-app-with-deps/app.py --out /tmp/hello-with-deps
ls /tmp/hello-with-deps
# flake.nix  launch.json  src/
jq '.dependencies' /tmp/hello-with-deps/launch.json
# {
#   "kind": "python",
#   "lockfile": "uv.lock",
#   "tool": "uv"
# }
```

## Build + run (needs a working builder VM)

```sh
# Build + boot + call the entrypoint. The install pipeline seals the deps
# volume inside the builder VM; --prod enforces the strict CVE/attestation gate.
mvmctl machine run --flake examples/python/hello-app-with-deps/ --profile prod --entrypoint
# claim 11 gate: the supervisor verifies the sealed volume before launching
```

The prod profile exercises the strict app-deps gate: missing attestations or
any high/critical CVE finding fails admission closed. The dev profile
warn-and-continues for fast iteration.

## Inspect a sealed volume

After a successful build:

```sh
# volume_hash is printed at the end of `mvmctl build`
mvmctl deps inspect <volume_hash>
mvmctl deps inspect <volume_hash> --json | jq '.cve'
```

## Re-audit (for long-lived deployments)

```sh
mvmctl deps audit --all
# Re-runs pip-audit against the current CVE feed, reseals the volume,
# and emits a `LocalAuditKind::DepsAudit` chain entry.
```

## Why the lockfile is the cache key

ADR-047 pins the *volume* hash at admission time, but the volume hash
bakes in `cve.json` + `meta.json` — values only the builder VM knows
after the install runs. The orchestrator keys its cache on
`sha256(lockfile_bytes)` mixed with `(language, gate_level)` so the
"have I already installed this?" check works without a VM spawn. Same
bytes ⇒ same key ⇒ same cached volume.

Bump the lockfile → cache miss → install pipeline runs → new sealed
volume.
