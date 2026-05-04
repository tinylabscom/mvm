---
title: Manifests
description: How mvmctl turns a flake + an mvm.toml into a running microVM.
---

> **Status:** this guide describes the **plan-38 manifest model**, shipped on `feat/manifest-driven-template-dx-claude`. The user-facing primitive is `mvm.toml`; the old `mvmctl template *` namespace has been removed. `mvmctl manifest push` and `pull` are tracked in [plan 39](https://github.com/tinylabscom/mvm/blob/main/specs/plans/39-manifest-push-pull.md) and not yet implemented; everything else listed here works.

A manifest (`mvm.toml` or `Mvmfile.toml`) is the user-facing primitive for "what to build and how to size it". One manifest sits next to a `flake.nix` in your project; together they describe one microVM.

```
my-service/
├── mvm.toml       # build inputs + dev sizing (this file)
├── flake.nix      # rootfs + kernel content (Nix's job)
└── …              # your app source
```

The flake is the source of truth for *what's inside* the microVM. The manifest is the source of truth for *how mvm builds and runs that flake* — sizing, profile selector, optional display name. That's the entire surface.

## The 5-field schema

```toml
flake = "."                   # default ".", any flake ref accepted
profile = "default"           # selects packages.<system>.<profile>
vcpus = 2
mem = "1024M"
data_disk = "0"

name = "openclaw"             # optional; display + S3 channel hint
```

That's it. Build inputs (`flake`, `profile`) and dev sizing (`vcpus`, `mem`, `data_disk`). No `role`, no `[network]`, no `[[variants]]`, no dependencies — those are flake territory or [`mvmd`](https://github.com/auser/mvmd) territory, not the dev tool's.

Each field's owner:

| Field | Owner | In manifest? |
|---|---|---|
| `flake` | mvmctl (input pointer) | **Yes** |
| `profile` | flake defines, mvmctl selects | **Yes**, as selector |
| `vcpus` | mvmctl — Firecracker host-side sizing | **Yes** |
| `mem` | mvmctl — host-side sizing | **Yes** |
| `data_disk` | mvmctl — host-side block device sizing | **Yes** |
| `name` | mvmctl — display in `ls`, optional S3 channel key | Optional |

Anything not in this list belongs in the flake (kernel/rootfs content, NixOS modules, services) or in `mvmd` (multi-VM topology, network policy, secrets, runtime deps).

## The everyday flow

Three commands. That's the user model.

```bash
mvmctl init                # scaffold mvm.toml + flake.nix in cwd
$EDITOR mvm.toml           # tweak sizing / profile to taste
mvmctl build               # discover manifest, run nix build, persist artifacts
mvmctl up                  # boot the built microVM
```

Repeated edits are just edits. The next `mvmctl build` re-reads `mvm.toml` and re-runs the build. Resource changes (`vcpus`, `mem`, `data_disk`) update silently; identity changes (`flake`, `profile`) trip a drift refusal that asks you to `--force` or rename — see [Drift detection](#drift-detection) below.

### Manifest discovery

`mvmctl build`, `mvmctl up`, `mvmctl run`, `mvmctl exec`, `mvmctl info`, `mvmctl rm` all accept an optional `[PATH]` argument:

```bash
mvmctl build                              # walks up from cwd looking for mvm.toml
mvmctl build /abs/path/to/mvm.toml        # explicit file path
mvmctl build /abs/path/to/project-dir     # explicit directory (resolves to mvm.toml inside)
```

Walk-up rules (Cargo-style): start at cwd, look for `mvm.toml` then `Mvmfile.toml` in each ancestor, stop at the first match, at a `.git` boundary, or at the filesystem root.

### `mvm.toml` vs `Mvmfile.toml`

Both filenames are accepted with the same parser and schema. Use whichever fits your repo's convention. Two files in the same directory is an error (`"found both mvm.toml and Mvmfile.toml in <dir>; pick one"`).

## Scaffolding new projects

`mvmctl init` creates a minimal `mvm.toml` + `flake.nix` in the target directory:

```bash
mvmctl init my-service              # scaffold into ./my-service
mvmctl init                         # scaffold into cwd
```

### Presets

```bash
mvmctl init my-api --preset python      # Python HTTP service
mvmctl init my-web --preset http        # generic HTTP server
mvmctl init my-db  --preset postgres    # PostgreSQL
mvmctl init my-job --preset worker      # background worker / cron-like
mvmctl init my-vm  --preset minimal     # bare minimum (default)
```

Each preset emits a different `flake.nix` plus a `mvm.toml` with sensible resource defaults (`vcpus = 2, mem = "1024M"` for HTTP/Python, `vcpus = 1, mem = "512M"` for workers, etc.).

### Prompt-driven scaffolding (LLM-assisted)

```bash
mvmctl init my-api --prompt "FastAPI app with Postgres backend"
```

A heuristic planner picks a preset from the prompt. With `OPENAI_API_KEY` set, an LLM refines the plan via structured output (JSON Schema, deterministic). With Ollama or another OpenAI-compatible local endpoint at `127.0.0.1:11434` or `127.0.0.1:8080`, mvmctl auto-detects and uses it instead. Override via `MVM_TEMPLATE_PROVIDER=auto|openai|local|heuristic`.

The planner outputs a structured plan (preset, features, http port, entrypoint, resources) — no free-form Nix or shell. Generated `flake.nix` comes from a fixed preset corpus, not from the LLM.

## Building

```bash
mvmctl build                                 # discover manifest, build
mvmctl build --snapshot                       # also create a Firecracker snapshot for instant warm-start
mvmctl build --force                          # rebuild even if the cache hits
mvmctl build --update-hash                    # recompute Nix FOD hash (after package version bump)
mvmctl build --vcpus 4 --mem 2G               # CLI overrides; persisted to the slot record
```

Build artifacts are stored in a content-addressed registry under `~/.mvm/templates/<sha256(canonical_manifest_path)>/artifacts/revisions/<revision_hash>/`. The manifest's *path* identifies the project; `revision_hash = sha256(flake.lock + profile)` content-addresses the actual build outputs.

Snapshots (`--snapshot`) are Firecracker-only. On Apple Virtualization or Docker the flag downgrades gracefully to image-only.

## Listing / inspecting / removing

Manifest registry operations live under `mvmctl manifest`. (The unprefixed `mvmctl ls` / `mvmctl info` / `mvmctl down` continue to operate on **running VMs** — those are unchanged.)

```bash
mvmctl manifest ls                            # list built slots (manifest path, name, last built)
mvmctl manifest ls --json                     # machine-readable
mvmctl manifest ls --orphans                  # slots whose manifest file is gone
mvmctl manifest ls --legacy                   # pre-refactor name-keyed slots (migration aid)

mvmctl manifest info                          # details for the manifest at cwd / walked-up
mvmctl manifest info /path/to/project         # explicit
mvmctl manifest info --json                   # full manifest + revision + provenance JSON

mvmctl manifest rm                            # remove the slot keyed by current manifest
mvmctl manifest rm /path/to/project --force   # idempotent
mvmctl manifest rm --manifest-file            # also delete mvm.toml on disk (off by default)
```

For running VMs (separate concern), continue to use `mvmctl ls` / `mvmctl down <vm>` / `mvmctl logs <vm>` etc.

## Booting

```bash
mvmctl up                            # boot from slot keyed by manifest at cwd
mvmctl up /path/to/project           # explicit
mvmctl run /path/to/project          # similar to up; boots transient VM
mvmctl exec /path/to/project -- uname -a   # ephemeral one-shot
```

If no current revision exists, you get an error with a hint to run `mvmctl build`. If the manifest's `vcpus`/`mem` differ from what the slot's snapshot was taken at, the snapshot is ignored and a cold-boot from the rootfs proceeds (with a warning).

### Backend mismatch

If the slot was built on Firecracker but you boot on Apple Virtualization (or vice versa), `mvmctl up` warns and proceeds when artifacts are compatible (cold-boot from rootfs); hard-errors only when the artifact shape can't be loaded.

## Local registry inspection / cleanup

The `mvmctl manifest *` namespace is where slot-registry operations live:

```bash
mvmctl manifest verify                          # checksum integrity check (local)
mvmctl manifest verify --revision <hash>        # specific revision
mvmctl manifest prune --orphans                 # cleanup builds whose source mvm.toml is gone
mvmctl manifest prune --orphans --dry-run       # preview what would be removed
```

`mvmctl cache prune --orphan-builds` is a convenience that bundles `manifest prune --orphans` into the broader cache-cleanup pass.

## Sharing via a registry (planned)

Pushing a built slot to an S3-compatible registry and pulling it on another machine is **planned but not yet implemented** — the design is captured in [plan 39](https://github.com/tinylabscom/mvm/blob/main/specs/plans/39-manifest-push-pull.md). The dominant question (where pull installs the slot when the source's `manifest_path` doesn't exist on the target) is resolved there. The shape will be:

```bash
# producer
mvmctl manifest push [PATH] [--revision <hash>]

# consumer
mvmctl manifest pull <CHANNEL-OR-HASH> [DIR]
mvmctl manifest pull openclaw ./openclaw   # writes mvm.toml in DIR, installs artifacts
mvmctl manifest verify --check-signature    # cosign verify (gated on plan 36)
```

Until plan 39 lands, transfer is via flake-level artifacts (Nix's own caching + `flake.lock`). Most of the time that's enough.

## Drift detection

The slot's `manifest.json` records the manifest's identity-shaping fields (`flake`, `profile`) at last build. If you edit `mvm.toml` to change either of those without `--force`, the next `mvmctl build` aborts with:

> Manifest at `<path>` declares `flake=X, profile=Y`. The slot at `<sha256>` was last built with `flake=X', profile=Y'`. Pass `--force` to overwrite, or pick a different manifest directory.

This catches typos, "I'm in the wrong cwd" mistakes, and accidental flake-ref churn. Resource changes (`vcpus`, `mem`, `data_disk`) update silently; only the build-identity fields trip the gate.

## Schema versioning

`mvm.toml` carries an implicit `schema_version = 1`. Future fields are additive (default-valued), so older manifests keep parsing. Bumping the major schema version requires explicit opt-in:

```toml
schema_version = 2   # bumped manifest
```

A manifest declaring `schema_version` higher than the running mvmctl supports errors with `"this manifest declares schema_version=N; this mvmctl supports M; upgrade mvmctl"`.

## What's NOT in the manifest

To keep the schema small and the boundaries crisp, the following are explicitly out:

- **What's installed in the rootfs** → flake (via `mkGuest`).
- **NixOS configuration / systemd services / users** → flake.
- **Kernel cmdline tweaks** → flake (kernel package).
- **Build-time deps on other flakes** → flake `inputs` + `flake.lock`.
- **Runtime deps on other VMs (lifecycle ordering, health gates)** → `mvmd` (separate repo).
- **Per-tenant network bridges, tap names, IP allocation** → `mvmd`.
- **Network egress policy** → `mvmctl up` flags or `~/.mvm/config.toml` defaults; eventually `mvmd` tenant config.
- **Secrets / env vars at boot** → `mvmctl up`-time injection or `mvmd` instance config.

## See also

- [Nix flakes guide](./nix-flakes.md) — writing the `flake.nix` half of the equation
- [CLI reference](../reference/cli-commands.md) — full flag/option list
- [Plan 38](https://github.com/tinylabscom/mvm/blob/main/specs/plans/38-manifest-driven-template-dx.md) — the design doc this guide tracks
