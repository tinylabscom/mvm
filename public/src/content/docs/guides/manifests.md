---
title: Manifests
description: How mvmctl turns an mvm.toml into a built image or a named machine.
---

> **Status:** `mvm.toml` / `Mvmfile.toml` is schema v1. A manifest selects
> exactly one source: `flake = ...` for the build/slot flow, or `image = ...`
> for `mvmctl machine create`. `mvmctl manifest push` and `pull` are tracked in
> [plan 39](https://github.com/tinylabscom/mvm/blob/main/specs/plans/39-manifest-push-pull.md)
> and not yet implemented.

A manifest is the user-facing primitive for "what source should back this VM
and how should it be sized." It can sit next to a `flake.nix` for source-built
microVM images, or it can name an OCI image for a durable `mvmctl machine`
spec.

```
my-service/
├── mvm.toml       # source selector + sizing (this file)
├── flake.nix      # present for flake-backed builds
└── …              # your app source
```

For a flake-backed manifest, the flake is the source of truth for what's inside
the microVM, and the manifest selects the flake/profile plus sizing. For an
image-backed manifest, `machine create` persists the manifest's runtime shape as
a named machine spec without requiring host Nix.

## Schema v1

```toml
# Source selector: choose exactly one. Omitting both defaults to flake = "."
flake = "."                   # any flake ref accepted
# image = "alpine:3.20"       # OCI image for mvmctl machine create

profile = "default"           # flake package selector; machine profile is CLI-selected
cpus = 2                      # vcpus remains accepted as a legacy alias
mem = "1024M"                 # memory cap
mem_initial = "512M"          # optional initial host commitment
data_disk = "0"               # flake/build flow only today
net = false                   # default-deny unless true or allow_hosts narrows it

[network]
allow_hosts = ["api.example.com:443"]

[auth]
ssh_agent = false             # parsed and persisted; machine start fails closed today

[dev]
init = []                     # dev-only; machine start fails closed today
volumes = ["./src:/work/src:ro"]

name = "openclaw"             # optional; display + S3 channel hint
```

Unknown keys are rejected. `image` and `flake` are mutually exclusive; setting
both is an error. Volumes default read-only; use `:rw` explicitly for a writable
mount. Relative volume host paths in an image-backed manifest are resolved
relative to the manifest file when persisted by `machine create`.

Each field's owner:

| Field | Owner | In manifest? |
|---|---|---|
| `flake` / `image` | mvmctl source selector | **Yes**, exactly one effective source |
| `profile` | flake defines, mvmctl selects | **Yes**, as selector |
| `cpus` / `vcpus` | mvmctl — host-side sizing | **Yes** |
| `mem` | mvmctl — host-side sizing | **Yes** |
| `mem_initial` | mvmctl — optional balloon initial commitment | Optional |
| `data_disk` | mvmctl — host-side block device sizing | **Yes** |
| `net`, `[network].allow_hosts` | mvmctl — effective egress policy | Optional |
| `[auth].ssh_agent` | mvmctl — future agent socket forwarding | Parsed, start fails closed today |
| `[dev].init` | mvmctl — future dev-only init hook | Parsed, start fails closed today |
| `[dev].volumes` | mvmctl — host shares / persistent disks | Optional |
| `name` | mvmctl — display in `ls`, optional S3 channel key | Optional |

Anything not in this list belongs in the flake (kernel/rootfs content, NixOS
modules, services) or in `mvmd` (multi-VM topology, tenant policy, runtime deps).

## The everyday flow

Three commands. That's the user model.

```bash
mvmctl init                # scaffold mvm.toml + flake.nix in cwd
$EDITOR mvm.toml           # tweak sizing / profile to taste
mvmctl build               # discover manifest, run nix build, persist artifacts
mvmctl up                  # boot the built microVM
```

Repeated edits are just edits. The next `mvmctl build` re-reads `mvm.toml` and re-runs the build. Resource changes (`vcpus`, `mem`, `data_disk`) update silently; identity changes (`flake`, `profile`) trip a drift refusal that asks you to `--force` or rename — see [Drift detection](#drift-detection) below.

For an image-backed durable machine:

```toml
image = "alpine:3.20"
cpus = 2
mem = "512M"
net = false

[dev]
volumes = ["./workspace:/work:ro"]
```

```bash
mvmctl machine create --name alpine-dev --manifest ./mvm.toml
mvmctl machine start --name alpine-dev
```

`machine create` stores a strict JSON spec under `MVM_DATA_DIR`, and
`machine start` boots it through the admitted OCI-backed launch path.
`[auth].ssh_agent` and `[dev].init` are intentionally fail-closed at start
until their runtime transports are implemented.

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
mvmctl build --snapshot                       # also create a Firecracker snapshot where supported
mvmctl build --force                          # rebuild even if the cache hits
mvmctl build --update-hash                    # recompute Nix FOD hash (after package version bump)
mvmctl build --vcpus 4 --mem 2G               # CLI overrides; persisted to the slot record
```

Build artifacts are stored in a content-addressed registry under `~/.mvm/templates/<sha256(canonical_manifest_path)>/artifacts/revisions/<revision_hash>/`. The manifest's *path* identifies the project; `revision_hash = sha256(flake.lock + profile)` content-addresses the actual build outputs.

Snapshots (`--snapshot`) are Firecracker-only. On Apple Virtualization or Docker the flag downgrades gracefully to image-only.

## Listing / inspecting / removing

Manifest registry operations live under `mvmctl manifest`. (The unprefixed `mvmctl ls` / `mvmctl info` / `mvmctl machine stop` continue to operate on **running VMs** — those are unchanged.)

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

For running VMs (separate concern), continue to use `mvmctl ls` / `mvmctl machine stop <vm>` / `mvmctl machine logs <vm>` etc.

## Booting

```bash
mvmctl up                            # boot from slot keyed by manifest at cwd
mvmctl up /path/to/project           # explicit
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
- **Per-tenant network policy bundles** → `mvmctl up` flags or `~/.mvm/config.toml` defaults; eventually `mvmd` tenant config. The manifest only carries simple machine defaults (`net`, `allow_hosts`).
- **Secrets / env vars at boot** → `mvmctl up`-time injection or `mvmd` instance config.

## See also

- [Nix flakes guide](./nix-flakes.md) — writing the `flake.nix` half of the equation
- [CLI reference](../reference/cli-commands.md) — full flag/option list
- [Plan 38](https://github.com/tinylabscom/mvm/blob/main/specs/plans/38-manifest-driven-template-dx.md) — the design doc this guide tracks
