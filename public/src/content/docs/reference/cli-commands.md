---
title: CLI Commands
description: Complete command reference for mvmctl.
---

## VM Lifecycle

`mvmctl` is the local microVM substrate CLI: it builds images, boots local
microVMs, talks to guest agents over vsock, manages local artifacts, and exposes
developer/SDK workflows. Fleet and tenant control-plane verbs live in `mvmd`.
In particular, `mvmctl` does not expose `tenant`, `policy`, or `deploy`
subcommands; tenant lifecycle, tenant policy authoring/review, and deployment to
the hosted control plane are `mvmd` responsibilities.

**Command grouping (Plan 178).** The surface is organized into a small set
of top-level daily-driver verbs plus noun groups; operations on a single
running VM live under `vm`, build-time verbs under `build`, observability
under `ops`, install/environment lifecycle under `env`, and provenance &
verification under `trust`. Domains that already own their own subcommands
(`image`, `catalog`, `manifest`, `storage`, `network`, `cache`, `pool`,
`secret`, `bundle`, `deps`, `artifact`, `capture`) stay top-level.

| Group / top-level | Commands |
|--------|----------|
| Daily drivers (top-level) | `machine` (`run`/`fork`/`restore`/`exec`/`console`/`logs`/`stop`/`forward`/…), `ls`, `build`, `doctor`, `init`, `bootstrap` |
| `vm <sub>` | `pause`, `resume`, `snapshot`, `save`, `restore`, `checkpoint`, `cp`, `fs`, `proc`, `diff`, `wait`, `boot-report`, `set-ttl`, `forward`, `sandbox`, `session`, `volume` |
| `build <sub>` | `image` (the former `build`), `compile`, `validate`, `kernel`, `runtime-overlay` |
| `ops <sub>` | `metrics`, `config`, `mcp` |
| `env <sub>` | `bootstrap`, `cleanup`, `uninstall`, `update`, `sign` |
| `trust <sub>` | `add`/`list`/`remove` (publishers), `attest`, `receipt`, `audit` |
| Already-grouped top-level | `image`, `catalog`, `manifest`, `storage`, `network`, `cache`, `pool`, `secret`, `bundle`, `deps`, `artifact`, `capture` |

**Beginner vs. advanced surfaces.** [`mvmctl machine`](#machine-beginner-ux)
(further down) is the beginner-facing front door — one small command group for
the common "run something in a microVM" cases, and the path the
[getting-started docs](/getting-started/machine-scenarios/) lead with. Every
verb in the grouping above is an **advanced / underlying surface**: `machine`
is a thin UX layer over the *same* signed, audited, OCI-provenance execution
path. The former top-level `up`/`invoke`/`console`/`down` verbs have folded into
`machine` (`machine run`, `machine run --entrypoint`, `machine console`,
`machine stop`); the `vm *` and `build *` noun-groups and the internal `run`
SDK transport remain for power users and scripts — reach for them when you need
finer control than `machine` exposes (custom flakes, snapshots, templates, the
guest-RPC surface, fleet-shaped workflows).

| Command | Description |
|---------|-------------|
| `mvmctl capture` | Inspect a Linux project and selected commands, resolve the evidence into canonical MVM IR, and render or verify the resulting environment (`project`, `resolve`, and `verify` subcommands) |
| `mvmctl machine run --flake <ref>` | Build a Nix flake and boot a transient VM |
| `mvmctl machine run --manifest <path>` | Boot a pre-built manifest (`mvm.toml`, its directory, or a slot name; short form `-m`). Mutually exclusive with `--flake`/`--image` |
| `mvmctl machine run --image <ref>` | Boot an OCI image (pulled/cached). Mutually exclusive with `--flake`/`--manifest` |
| `mvmctl machine run --name <name>` | Run under a machine identity (auto-generated if omitted) |
| `mvmctl machine run --entrypoint --stdin <PATH>` | Feed the baked entrypoint's stdin from a file, sent as one complete payload with the call |
| `mvmctl machine run --entrypoint --stdin -` | **Stream** this process's own stdin into the running workload: bytes arrive as they are written and your EOF closes the workload's stdin. Puts the `host.stream.v1` input grant on the signed plan, so a sealed production image whose entrypoint is shell-shaped — or whose entrypoint the host cannot resolve — is refused at admission. Not available with `--attach`, which dispatches into a machine this process did not admit. See [Workload input](/guides/workload-input/) |
| `mvmctl machine run -d` | Boot a **persistent** machine detached and return immediately |
| `mvmctl machine run --port HOST:GUEST` | Boot a persistent machine and forward the host loopback port to the guest while the command remains attached (repeatable; conflicts with `--detach`; Ctrl-C closes the forwards) |
| `mvmctl machine run --healthcheck '<cmd>'` | Declare the workload a long-running service: presence alone promotes the run to the **persistent** lifecycle (registered, shows in `machine ls`, torn down via `machine stop <name>`). Runs in the foreground unless combined with `-d`. `<cmd>` is exec'd in the guest by the resident host-agent daemon as its liveness check (exit 0 = healthy), actively probed on `--health-interval`; an unhealthy or crashed service is restarted with bounded exponential backoff. A run whose entrypoint exits still tears down on that exit code — a healthcheck on a run-to-completion task is a no-op |
| `mvmctl machine run --health-interval <secs> --health-timeout <secs> --health-retries <n> --health-start-period <secs>` | Tune the healthcheck cadence: seconds between checks (default `30`), per-check timeout (default `5`), consecutive failures before unhealthy (default `3`), and grace period after start before checks count (default `0`). Recorded on the machine spec and actively enforced by the host-agent daemon's probe loop |
| `mvmctl machine run --cpus N --memory SIZE` | vCPU count the guest sees, and memory (supports 512M, 4G, etc.) |
| `mvmctl machine run --cpu-limit MILLICORES` | Cap the workload's share of **host CPU time**, in thousandths of a core (`1500` = 1.5 cores). A different control from `--cpus`, which sets how many vCPUs the guest sees — a workload can hold four vCPUs and be bounded to half a core. Recorded on the signed execution plan and refused when it exceeds the host's `max_cpu_millicores` ceiling |
| `mvmctl machine run --grants-file PATH` | Read the workload's grants (CPU, wall clock, egress) from a JSON document. Unknown keys are refused, so a typo is an error rather than a silently dropped cap |
| `mvmctl machine run -e KEY=VALUE` | Inject an environment variable (repeatable; gated by `--profile`) |
| `mvmctl machine run --volume host:/guest[:mode]` | Share a host directory (mode defaults to `ro`; `rw` needs `--profile dev`/`permissive`) |
| `mvmctl machine run --profile <p>` | Security posture: `restrictive`, `standard` (default), `dev`, `permissive` |
| `mvmctl machine run --net` | Enable broad dev-tier outbound egress (default is deny-all) |
| `mvmctl machine run --allow-host HOST[:PORT]` | Allow egress only to these hosts (repeatable; PORT defaults to 443; wins over `--net`) |
| `mvmctl machine run --hypervisor <backend>` | Backend: `firecracker` (Linux/KVM), `hvf` (macOS 26+ default, vsock-only), `libkrun` (macOS 13–25 & Linux), `qemu` (dev/test) |
| `mvmctl machine run --flake <ref> --flake-profile <variant>` | Flake package variant (e.g. worker, gateway) |
| `mvmctl machine run --host-service <service>` | Bind a host service the workload may call over the broker channel (repeatable, e.g. `host.audit.v1`). Baked into the signed execution plan: the broker refuses any service absent from the set. Binding an SDK-served service (`host.audit.v1`, `host.cost.v1`, `host.secrets.v1`, `host.time.v1`) also attaches the optional SDK sidecar read-only at `/mvm/sdk`. On an installed `mvmctl` a cold cache downloads the published sidecar for the running version and arch, hash-verifies it, and boots; the launch is refused if the download fails or the artifact is version-mismatched, tampered, or incomplete. From a source checkout the refusal names `nix build ./nix/images/runtime-overlay#sdk-sidecar-image` instead of downloading, because building it needs the builder VM |
| `mvmctl machine session start <template> --agent-verb <verb>` | Boot a prod session with an explicit ProdSafe agent-verb allow-list instead of the computed baked-entrypoint/non-dev default. Repeatable; refused with `--dev` |
| `mvmctl machine build --flake <ref> --watch` | Watch the flake and rebuild on change |
| `mvmctl machine stop [name...]` | Stop one or more VMs by name, or `--all` |
| `mvmctl machine ls` | List every microVM: persistent machines and running transients (alias: `ps`) |
| `mvmctl machine ls -a` | Also show transient machines that are no longer running |
| `mvmctl machine ls --json` | Output as JSON |
| `mvmctl machine run ... --port HOST:GUEST` | Declare signed TCP ingress before boot (repeatable) |
| `mvmctl machine logs <name>` | View the workload's captured stdout/stderr — live while it runs, and still readable after it exits (`-f` to follow, `-n` for how many recorded records to replay first; a record is one captured write, not one line). Workload stdout is written to your stdout and stderr to your stderr, so an ordinary pipeline (`\| grep …`) filters the channel it asked for, and a closed pipe (`\| head -1`) ends the read cleanly rather than erroring. Falls back to the machine's console log when no output capture exists, saying so. Exits nonzero when there is no source at all, and warns on stderr when what it shows is a window rather than the whole run — a truncated capture, a pruned live window, or a hole between the recorded and live halves |
| `mvmctl machine logs <name> --stream <stdout\|stderr\|trace\|all>` | Show one channel only (default `all`). Refused on a machine whose only source is its console log: that log merges both channels with no labels, so narrowing it has no honest answer. A recorded capture holding nothing on the requested channel is reported as such, not as a missing capture |
| `mvmctl machine logs <name> --hypervisor` | View the VMM's own diagnostic log (`firecracker.log`) rather than workload output, `-f` to follow it. Firecracker writes one; the other backends do not |
| `mvmctl machine diff <name>` | Show filesystem changes in a running VM (created/modified/deleted since boot) |
| `mvmctl machine diff <name> --json` | Output filesystem diff as JSON |
| `mvmctl machine wait <name> --for <component>` | Block until a guest readiness component is `Ready`, `Disabled`, or `Failed`. Targets: `control-plane`, `entrypoint`, `warm-pool`, `integrations`, `probes`, `all` (default). Exit codes: `0` ready, `65` (`EX_DATAERR`) failed, `75` (`EX_TEMPFAIL`) timeout. Plan 76 Phase 2. |
| `mvmctl machine wait <name> --timeout <secs> --interval-ms <ms>` | Tune the deadline and poll cadence. Defaults: 60s / 250ms. |
| `mvmctl machine boot-report <name>` | Print a single readiness snapshot + per-phase boot timings. Plan 76 Phase 4. |
| `mvmctl machine boot-report <name> --json` | Same payload as JSON. |
| `mvmctl machine fork <parent> --as <child>` | Snapshot a running machine as a `vm_full` checkpoint and branch it into a fresh child VM with a new identity. The child is admitted through the same path as `machine warm-restore`. |
| `mvmctl machine fork <parent> --branch <slug>` | Auto-name the child `<parent>-<slug>-<timestamp>` instead of using `--as`. |
| `mvmctl machine restore <checkpoint> --as <child>` | Branch an existing `vm_full` checkpoint into a fresh child VM with a new identity. |
| `mvmctl machine restore <checkpoint> --branch <slug>` | Auto-name the child `<checkpoint>-<slug>-<timestamp>` instead of using `--as`. |
| `mvmctl machine warm-restore <checkpoint> [--name <name>]` | Low-level synonym for restoring a `vm_full` checkpoint into a fresh child VM. Prefer `machine restore` for new scripts. |

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Prepare the environment: host tooling **and pre-fetch the builder VM image** so the first build is fast (no first-run download/build on the hot path). `install.sh` runs this automatically unless `MVM_SKIP_BUILDER_PREFETCH=1`. Idempotent — safe to re-run |
| `mvmctl bootstrap --production` | Production mode (skip Homebrew, assume Linux with apt) |
| `mvmctl env bootstrap` | Same as `mvmctl bootstrap` (the `env`-grouped form) |
| `mvmctl doctor` | Run diagnostics + dependency checks + security posture, including per-tenant host-agent daemon state (folded in from the dropped `mvmctl security` verb) |
| `mvmctl doctor --json` | Output diagnostics as JSON |
| `mvmctl env update` | Check for and install mvmctl updates |
| `mvmctl env update --check` | Only check for updates, don't install |
| `mvmctl env update --force` | Force reinstall even if already up to date |
| `mvmctl env update --skip-verify` | Skip cosign signature verification |

## Building

| Command | Description |
|---------|-------------|
| `mvmctl machine build <path>` | Build the slot for a manifest directory. A `flake =` manifest builds through Nix in the builder VM; an `image =` manifest materializes the OCI reference through the same path `run --image` boots, then installs it as a slot revision |
| `mvmctl kernel build` | Build the custom microVM kernels (builder and workload) |
| `mvmctl build image <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build image --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build image --flake <ref> --profile <variant>` | Build a specific flake package variant |
| `mvmctl build image --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl build image --json` | Output structured JSON events instead of human-readable output |
| `mvmctl build image -o <path>` | Output path for the built .elf image |
| `mvmctl build runtime-overlay build` | Prebuild the version-matched read-only runtime overlay into `~/.mvm/cache/runtime-overlay/<version>/<arch>/` without booting a VM. This is the explicit “pay the guest-binary build debt once” command for required-overlay workflows |
| `mvmctl build runtime-overlay build --force` | Refresh the cached overlay even when the matching cache entry already exists |
| `mvmctl build runtime-overlay build --source build\|download\|auto` | Choose whether the overlay is assembled from the source checkout, downloaded from the published release, or resolved the same way ordinary required-overlay boots do |
| Runtime overlay update model | Stopped VMs pick up the newer version-matched overlay on the next boot. Running VMs keep the overlay they booted with; mvm does not hot-remount a different runtime overlay into a live guest |
| `just runtime-overlay [--force]` | Preferred worktree-local convenience wrapper around `mvmctl build runtime-overlay build`; sources `scripts/dev-env.sh` first so cache/target state stays isolated per worktree |
| `just runtime-overlay-build [--force]` | Compatibility alias for `just runtime-overlay` |
| `mvmctl env cleanup` | Remove old dev-build artifacts and run Nix garbage collection |
| `mvmctl env cleanup --all` | Remove all cached build revisions |
| `mvmctl env cleanup --keep <N>` | Keep the N newest build revisions |
| `mvmctl env cleanup --verbose` | Print each cached build path that gets removed |
| `mvmctl env cleanup --cache` | Remove the regenerable `~/.mvm/cache` |
| `mvmctl env cleanup --state` | `--cache` plus the regenerable subdirs `dev`, `vms`, `log`, `dev-cluster`, `mock-vms`, `tool-staging`. Preserves identity, templates, and everything not named here |
| `mvmctl env cleanup --nuclear` | Remove **every** entry under `~/.mvm`, leaving the (0700) root directory itself in place. Defined by subtraction, so a state directory added by a future subsystem is covered without editing a list. Always requires typing `DELETE-EVERYTHING` at an interactive prompt; `--yes` does not bypass it |
| `mvmctl env cleanup --nuclear --keep-identity` | As above, but spares the material a rebuild cannot regenerate: `keys`, `audit`, `attestation`, `secrets`, `secret-bindings`, `egress-ca`, `.secret-store.key`, `snapshot.key`, `config.toml`. Past audit logs stay verifiable. Templates, images, machines, checkpoints and snapshots still go |
| `mvmctl env cleanup --<tier> --dry-run` | Print the paths a tier sweep would remove, with sizes, and remove nothing |
| `mvmctl env cleanup --<tier> --force` | Let the sweep proceed even when a VM appears to be running. Wiping live VM state corrupts the running guest — use only when the PID file is known stale |

To reclaim disk without losing anything unrecoverable, `--nuclear --keep-identity`
is the command. `mvmctl env uninstall --all` also wipes `~/.mvm`, but it removes
`/var/lib/mvm` and the `mvmctl` binary too, and needs `sudo`.

## Manifests

> **Status:** the `mvmctl init/build/manifest *` surface below is the **plan-38 model**, shipped on `feat/manifest-driven-template-dx-claude`. The user-facing primitive is an `mvm.toml` file alongside your `flake.nix`. See the [Manifests guide](/guides/manifests/) for the conceptual model. The old `mvmctl template <verb>` namespace was removed; clap returns "unrecognized subcommand" for old invocations. `mvmctl manifest push` / `pull` are planned in [plan 39](https://github.com/tinylabscom/mvm/blob/main/specs/plans/39-manifest-push-pull.md) but not yet implemented.

### Scaffolding (top-level)

| Command | Description |
|---------|-------------|
| `mvmctl init <DIR>` | Scaffold `mvm.toml` + `flake.nix` (+ NixOS config) in `DIR` (required) |
| `mvmctl init <DIR> --preset <preset>` | Preset: `minimal`, `http`, `postgres`, `worker`, `python` (default: `minimal`) |
| `mvmctl init <DIR> --catalog <name>` | Scaffold from a bundled catalog entry (run `mvmctl catalog list` to browse). Mutually exclusive with `--preset`/`--prompt` |
| `mvmctl init <DIR> --prompt "<text>"` | Generate scaffold from a natural-language prompt. In `auto` mode (default) probes for a local OpenAI-compatible endpoint on loopback (Ollama @ `:11434`, LocalAI @ `:8080`) before falling through to OpenAI. Override with `MVM_TEMPLATE_PROVIDER=openai\|local\|heuristic`; skip probe with `MVM_TEMPLATE_NO_LOCAL_PROBE=1` |

### Building (top-level)

| Command | Description |
|---------|-------------|
| `mvmctl build image [PATH]` | Build the manifest at `PATH` (file or directory; default: cwd walk-up). Persists artifacts to a slot keyed by `sha256(canonical_manifest_path)`. Subsumes today's `mvmctl build image --flake .` and the legacy `Mvmfile.toml` flow into one verb |
| `mvmctl build image [PATH] --force` | Rebuild even if the cache hits |
| `mvmctl build image [PATH] --update-hash` | Recompute the Nix fixed-output derivation hash |
| `mvmctl build image [PATH] --vcpus N --mem SIZE --data-disk SIZE` | CLI overrides for resource sizing; persisted to the slot record |
| `mvmctl build image [PATH] --json` | Stream structured build events |

### Running (top-level — already manifest-aware)

`mvmctl machine run [PATH]` and `mvmctl run [PATH] -- <cmd>` accept a manifest path or its directory and look up the manifest-keyed slot. If no current revision exists, they error with a hint to run `mvmctl build image`. See the [VM Lifecycle](#vm-lifecycle) and [One-shot Exec](#one-shot-run-transient-runner) sections for full flag lists. (Plan 40 dropped the `start` and `run` aliases on `up`.)

### Inspection / registry (`mvmctl manifest *`)

| Command | Description |
|---------|-------------|
| `mvmctl manifest ls [--json]` | List built slots — manifest path, last-built timestamp, optional `name` |
| `mvmctl manifest ls --orphans` | Slots whose source manifest file is missing on disk |
| `mvmctl manifest info [PATH] [--json]` | Print manifest, slot path, current revision, snapshot info, provenance |
| `mvmctl manifest rm [PATH] [--force]` | Remove the slot from the registry |
| `mvmctl manifest rm [PATH] --manifest-file` | Also delete the source `mvm.toml` (off by default) |
| `mvmctl manifest verify [PATH] [--revision <hash>]` | Verify checksums for a built slot |
| `mvmctl manifest verify --check-signature` | Reserved for plan 36 (sealed-signed-builder-image); errors today with "not yet wired" |
| `mvmctl manifest prune --orphans` | Remove builds whose source manifest is gone |
| `mvmctl manifest prune --orphans --dry-run` | Preview what would be removed |
| `mvmctl manifest push` / `mvmctl manifest pull` | **Planned, not yet implemented.** Tracked in [plan 39](https://github.com/tinylabscom/mvm/blob/main/specs/plans/39-manifest-push-pull.md). |

## Configuration

| Command | Description |
|---------|-------------|
| `mvmctl ops config show` | Print current config as TOML |
| `mvmctl ops config edit` | Open the config file in $EDITOR (falls back to nano) |
| `mvmctl ops config set <key> <value>` | Set a single config key (e.g. `mvmctl ops config set dev_vm_cpus 4`) |

## Audit

| Command | Description |
|---------|-------------|
| `mvmctl trust audit tail` | Show the last 20 audit events from /var/log/mvm/audit.jsonl |
| `mvmctl trust audit tail -n <N>` | Show the last N audit events |
| `mvmctl trust audit tail -f` | Follow audit log output (poll until Ctrl-C) |
| `mvmctl trust audit publish-root [--tenant <t>]` | Build, sign, and publish a Merkle transparency-log root over the tenant's chain-signed audit log to `~/.mvm/audit/<tenant>.root.json`. Only builds over a chain that verifies clean |
| `mvmctl trust audit prove <selector> [--tenant <t>] [--json]` | Emit an inclusion proof that one audit line is in the log, paired with the current signed root. `<selector>` is a numeric line index, a `plan_id`, or `sha256:<hex>` of the exact line; an ambiguous selector is refused |
| `mvmctl trust audit verify-inclusion --proof <file\|-> [--root <file>] [--pubkey <file>] [--tenant <t>]` | Verify an inclusion proof against a host-signed root: verifies the signed root under the trusted host key, checks its tenant, verifies the proof, and binds root_hash + tree_size. Nonzero exit naming the failed check |
| `mvmctl trust audit provenance export [--tenant <t>] [--local] [-o <path>]` | Export the chain-signed audit log as W3C PROV-O/Turtle for compliance reporting |
| `mvmctl trust audit decisions export [--tenant <t>] [--format json\|tibet] [-o <path>]` | Export cached decision records for a tenant; default format is JSON |
| `mvmctl trust audit decisions list [--tenant <t>] [--json]` | List cached decision records for a tenant |
| `mvmctl trust audit decisions show <decision-id> [--tenant <t>] [--json]` | Show a single decision record by its content address |
| `mvmctl trust audit decisions trace <decision-id> [--tenant <t>] [--json]` | Trace the causal chain that led to a decision |
| `mvmctl trust audit decisions impact <decision-id> [--tenant <t>] [--json]` | Show decisions that depend on or were caused by a decision |
| `mvmctl trust audit decisions similar <decision-id> [--tenant <t>] [--json]` | Find cached decisions similar to the given decision |

## Local Secrets

| Command | Description |
|---------|-------------|
| `mvmctl secret put <name>` | Store or replace a local secret using hidden interactive input when stdin is a terminal, or piped stdin otherwise |
| `mvmctl secret put <name> --value -` | Store or replace a local secret from stdin |
| `mvmctl secret put <name> --value-file <path>` | Store or replace a local secret from a file |
| `mvmctl secret put <name> --value <value>` | Store or replace a local secret from an inline value. Avoid in interactive shells because the value may be saved in shell history |
| `mvmctl secret set <name> --provider <provider>` | Store a secret and bind it to a catalogued provider's destinations and auth type |
| `mvmctl secret set <name> --host <host> --type <auth>` | Store a secret and bind it to explicit destinations. Repeat `--host`; `*.` subdomain wildcards supported |
| `mvmctl secret providers` | List the built-in service providers `--provider` accepts |
| `mvmctl secret providers --search <query>` | Filter providers by name, description, or tag |
| `mvmctl secret get <name>` | Verify that a local secret exists without printing the value |
| `mvmctl secret ls` | List stored secret names, and for bound secrets their auth type, destinations, and authoring provider |
| `mvmctl secret rm <name>` | Remove a local secret |
| `mvmctl secret <put|get|set|ls|rm> --tenant <tenant>` | Use a non-default local tenant namespace. Default: `local` |

`secret set` is `put` plus an egress binding: it records where the substituted
credential may go and how it authenticates. `--provider` takes those from the
built-in catalog so the destination is not hand-typed, which matters because a
mistyped host does not fail loudly — it withholds the credential, surfacing as an
unrelated upstream auth error. `--provider` and `--host`/`--type` are mutually
exclusive, and an unrecognised provider name is refused rather than falling back
to a default.

The catalog is expanded once, when `secret set` runs, and the resulting literal
hosts are what get stored and enforced; it is never consulted again for that
binding. A later change to a catalog entry therefore cannot widen a binding that
already exists. For a SigV4 provider the credential-scope service comes from the
entry, while `--region` and `--aws-access-key-id` stay yours to supply — they
belong to your account, not to the provider.

Secret values are write-only through the CLI after storage: `get` is a presence
check and never emits the raw value. Replace a secret by running `secret put`
again with the same name. Local secret storage is encrypted at rest: the OS
keyring backend stores values in the platform keystore, and the file fallback
stores AES-256-GCM encrypted records with mode-0600 files and a mode-0600 local
store key. Auto backend mode keeps file-backed secrets visible when the OS
keyring is reachable, so a backend probe change cannot hide an existing secret.
Legacy plaintext file records are refused; replace them with `secret put`.
Secret audit entries in `~/.mvm/audit/secrets.jsonl` record the operation
metadata plus `secret_visibility: "write_only"` and
`storage_security: "encrypted_at_rest"`; secret values are never logged.

## Policy Contracts

`mvmctl machine run` still synthesizes and admits signed execution plans with policy
references. The default local ref is `local-default`; tenant-scoped policy
authoring, diffing, rollout, and review are exposed by `mvmd`, not by a public
`mvmctl policy` command.

When admission resolves a workload policy bundle, `[audit].chain_signing = true`
is required. The default local chain remains active, and `file://...` entries in
`[audit].stream_destinations` receive exact JSONL replica chains. Other
destination schemes validate at the policy-shape layer but fail closed during
admission until their transports are wired.

## Flake Validation

| Command | Description |
|---------|-------------|
| `mvmctl build validate` | Validate a Nix flake before building (current directory) |
| `mvmctl build validate --flake <ref>` | Validate a specific flake path or reference |
| `mvmctl build validate --json` | Output structured JSON instead of human-readable output |

> Plan 40 renamed this verb from `mvmctl flake check` to `mvmctl build validate`.

## Runtime Overlay

| Command | Description |
|---------|-------------|
| `mvmctl build runtime-overlay build` | Populate the local runtime-overlay cache at `~/.mvm/cache/runtime-overlay/<version>/<arch>/` for this `mvmctl` version and host architecture without booting a workload VM |
| `mvmctl build runtime-overlay build --source build` | Build the overlay from the source checkout. Requires `nix/images/runtime-overlay/flake.nix` in the current checkout |
| `mvmctl build runtime-overlay build --source download` | Download the published runtime-overlay artifact for this version into the cache |
| `mvmctl build runtime-overlay build --arch aarch64\|x86_64 --version <semver>` | Override the target architecture or the expected overlay version |
| Runtime overlay update model | Running VMs keep the overlay they booted with; a changed overlay takes effect on the next boot of a stopped VM |
| `just runtime-overlay` | Prebuild the overlay through the worktree-local dev environment so later required-overlay boots avoid rebuilding guest binaries on the hot path |
| `just runtime-overlay-build` | Compatibility alias for `just runtime-overlay` |

## Networks

| Command | Description |
|---------|-------------|
| `mvmctl network create <name>` | Create a named dev network with its own bridge and subnet |
| `mvmctl network list` | List all dev networks (alias: `ls`) |
| `mvmctl network inspect <name>` | Show details of a named network (JSON) |
| `mvmctl network remove <name>` | Remove a named network (alias: `rm`) |

## Image Catalog

`mvmctl catalog *` is the metadata-only browser for bundled application entries. `mvmctl image *` is reserved for the local OCI image cache under `~/.mvm/cache/oci/`.

| Command | Description |
|---------|-------------|
| `mvmctl catalog list` | List bundled catalog entries |
| `mvmctl catalog search <query>` | Search entries by name, description, or tag |
| `mvmctl catalog info <name>` | Show catalog entry details (JSON) |
| `mvmctl init <DIR> --catalog <name>` | Scaffold a project from a catalog entry |
| `mvmctl image pull <ref> [--prod]` | Pull an OCI image, unpack its layers, materialize a bootable `rootfs.ext4`, and record it plus a provenance sidecar in the local OCI cache. `--prod` requires a digest-pinned reference, an OCI policy file, and cosign verification |
| `mvmctl image ls [--registry <host>] [--json]` | List cached OCI images by reference, resolved digest, fetched timestamp, and size |
| `mvmctl image inspect <ref-or-digest> [--json]` | Print cached OCI manifest/config metadata, layer digests, and any claims/provenance sidecar |
| `mvmctl image rm <ref-or-digest>` | Remove a cached OCI image and garbage-collect unreferenced layer files |
| `mvmctl image boot status [--json]` | Report each cached default boot image variant (`dev`, `prod`): tag, source (`built-local` / `fetched`), acquisition time, protocol version, on-disk size, and whether the next run would use it. Cache only, no network |
| `mvmctl image boot check [--json]` | Compare the cached boot image tag against the latest published `boot-image/v*` release. Read-only; exits nonzero only when behind, so a script can gate on the exit code |
| `mvmctl image boot update [--tag <t>] [--force]` | Fetch and hash-verify a published boot image into a staging directory, then atomically swap it into the cache. `--tag` pins a release; `--force` is required in a source checkout, where the local build is authoritative |

Production OCI policy reads `MVM_OCI_POLICY` when set, otherwise
`$MVM_HOME/oci-policy.toml`. The policy allow-lists registries and trusted
keyless cosign identities. Production mode always requires signatures and
verifies the resolved digest form (`registry/repo@sha256:...`) before the image
is cached or booted:

```toml
allowed_registries = ["ghcr.io"]

[[cosign]]
certificate_identity = "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
```

Private registry pulls use explicit mvm bearer-token environment variables only.
For a single registry, set `MVM_OCI_BEARER_TOKEN_<HOST>` where `<HOST>` is the
registry host uppercased with `.`, `-`, and `:` replaced by `_`
(`ghcr.io` -> `MVM_OCI_BEARER_TOKEN_GHCR_IO`). `MVM_OCI_BEARER_TOKEN` is the
global fallback. mvm does not read `~/.docker/config.json` or invoke Docker
credential helpers, and audit entries record only the credential source name,
never the token value.

## Console

| Command | Description |
|---------|-------------|
| `mvmctl machine console <name>` | Dev-only interactive PTY shell into a running VM (vsock, no SSH; refused for sealed/production VMs) |
| `mvmctl machine console <name> --command <cmd>` | Dev-only one-shot command in the VM (refused for sealed/production VMs) |

## One-shot Run (transient runner)

`mvmctl run` is the one-shot sandbox UX: it boots a fresh transient microVM,
runs one command, and tears the VM down on exit — like `docker run --rm` but
with a Firecracker microVM as the sandbox. Plan 178 merged the former bare
`mvmctl exec` into `run` (it was already a strict superset); `run` adds a
security `--profile`, OCI `--image`, signed `--receipt`, `--json`/`--dry-run`,
and the SDK `--mode`/`--dev`/`--prod` transport. Arbitrary command dispatch
requires a dev-feature guest agent (the `do_exec` handler is `interactive`-gated,
claim 4). A baked-entrypoint run on a non-dev profile receives the restricted
ProdSafe grant; PTY and ad-hoc argv runs require DevOnly verbs. Production
guests run their baked entrypoint via `mvmctl machine run --entrypoint` (no
shell).

| Command | Description |
|---------|-------------|
| `mvmctl run -- <cmd>...` | Boot the bundled default microVM image, run `<cmd>`, exit |
| `mvmctl run --manifest <name-or-path> -- <cmd>...` | Boot a registered manifest/template instead of the default |
| `mvmctl run npm test` | Infer the runtime when no source flag is given (see **Runtime detection** below) |
| `mvmctl run --runtime <name> -- <cmd>...` | Boot a named runtime from the built-in catalog; an unknown name is refused, never defaulted |
| `mvmctl run --no-detect -- <cmd>...` | Skip inference and use the bundled default image |
| `mvmctl run --image <ref> -- <cmd>...` | Pull or reuse a cached OCI image, emit signed audit-chain provenance for the resolved image, boot its prepared OCI rootfs (read-only virtiofs-root on capable dev-tier backends, otherwise block `rootfs.ext4`), run `<cmd>`, exit |
| `mvmctl run --image <ref> --prod -- <cmd>...` | Production OCI-image policy: require `<ref>` to be digest-pinned and cosign-verified by the OCI policy before cache use or boot |
| `mvmctl run --profile standard -- <cmd>` | Default profile on both `run` and `machine run`: explicit env is allowed; host shares must be read-only |
| `mvmctl run --profile dev -- <cmd>` | Dev tier: as standard, plus a writable (`:rw`) host share on a persistent machine and the dev guest profile for a sealed-image entrypoint run |
| `mvmctl run --profile restrictive -- <cmd>` | No env injection and no host directory shares |
| `mvmctl run --mount .:/work:ro -- <cmd>` | Attach a live read-only host-directory share |
| `mvmctl run --profile permissive -- <cmd>` | Escape hatch; requires `MVM_ACK_PERMISSIVE_RUN=1` |
| `mvmctl run --mount HOST:GUEST:ro -- <cmd>` | Attach a live read-only host-directory share |
| `mvmctl run --env KEY=VAL -- <cmd>` | Inject an explicit environment variable. Repeatable; disabled by `--profile restrictive` |
| `mvmctl run --cpus <n> --memory <size> -- <cmd>` | Resize the transient VM |
| `mvmctl run --timeout <secs> -- <cmd>` | Per-command timeout |
| `mvmctl run --dry-run -- <cmd>` | Validate and explain the run plan without resolving an image, booting a VM, writing a receipt, or executing the command |
| `mvmctl run --dry-run --json -- <cmd>` | Print the dry-run preflight summary as redacted JSON |
| `mvmctl run --receipt <path> -- <cmd>` | Write a signed JSON receipt with invocation hashes, output hashes, and exit status. Raw argv, env values, stdout, and stderr are not stored. |
| `mvmctl run --json -- <cmd>` | Print a redacted JSON execution summary with invocation metadata and output hashes. Guest stdout/stderr are not streamed. |
| `mvmctl run --json --receipt <path> -- <cmd>` | Print the same JSON summary and also write a signed receipt artifact |
| `mvmctl trust receipt verify <path>` | Verify a signed run receipt against `~/.mvm/keys/host-signer.pub` |
| `mvmctl trust receipt verify <path> --pubkey <path>` | Verify a signed run receipt against an explicit raw Ed25519 public key |

`run --dry-run` is a preflight-only path. It validates profile, env-key,
resource, and host-share policy, then reports hashes and policy-relevant
metadata. Manifest arguments, argv, host paths, and receipt paths are hashed
rather than printed. It deliberately does not resolve manifests, build/download
the default image, start a VM, execute the command, or write a receipt.

`run --json` is intended for machine callers. It preserves the command's exit
code, but the JSON does not include raw argv, env values, stdout, stderr, or host
paths.

### Runtime detection

With no `--image` / `--manifest` / `--flake` / `--deployment` / `--runtime-pack`,
`mvmctl run` settles the boot source in this order. The order is the contract:

1. **An explicit source flag.** Nothing is inferred.
2. **`--runtime <name>`** against the built-in catalog. An unknown name is
   refused and lists the known ones — a typo never falls through to a default.
3. **`--no-detect`** stops here, leaving the bundled default image.
4. **An `mvm.toml` (or `Mvmfile.toml`)** in or above the working directory,
   found by the same walk-up `mvmctl build` uses, stopping at a `.git` boundary.
5. **The command, then a project file.** `npm` selects node; `Cargo.toml`
   selects rust. The command wins over the directory — argv is what you just
   typed, the directory is where you happened to be standing.
6. **The bundled default image.**

| Runtime | Image | Commands | Project files |
|---------|-------|----------|---------------|
| `python` | `python:3.12-alpine` | `python`, `python3`, `pip`, `pip3`, `pytest` | `pyproject.toml`, `requirements.txt`, `Pipfile`, `setup.py` |
| `node` | `node:22-alpine` | `node`, `npm`, `npx`, `yarn`, `pnpm` | `package.json` |
| `rust` | `rust:1-alpine` | `cargo`, `rustc` | `Cargo.toml` |
| `go` | `golang:1-alpine` | `go`, `gofmt` | `go.mod` |
| `ruby` | `ruby:3-alpine` | `ruby`, `bundle`, `rake`, `gem` | `Gemfile`, `Rakefile` |
| `shell` | `alpine:3` | `sh`, `bash`, `ash` | — |

An inferred source always announces itself on stderr before booting
(`[mvm] detected node from the command `npm` — booting node:22-alpine`), so a
run never boots an image you did not choose without saying so. `--json` stdout
is unaffected.

Detection picks a **source**, never a posture. An inferred run admits through
the same signed `ExecutionPlan`, with the same `--profile standard` default and
the same deny-all egress, as one that named its image.

**`machine run` does not infer.** Steps 4 and 5 are skipped there: it creates a
named, possibly persistent machine, and picking its base image from whatever
directory you were standing in is a footgun — `machine run` inside any Rust
checkout would quietly build a machine on `rust:1-alpine`. It keeps its error
naming every way to supply a source. `--runtime <name>` works on both verbs,
because that is you naming one.

The catalog is curated, in-tree, and versioned with the code; it is never
fetched at runtime. Its refs are **tags, not digests**, which is deliberate:
they are a dev-tier convenience. `--prod` refuses a mutable reference before any
network fetch, so a production run cannot inherit a detected tag — it has to
name a digest.

## Machine (beginner UX)

`mvmctl machine` is the beginner-facing command group. It is a thin UX layer
over the existing runtime verbs and state helpers, not a parallel runtime.
Booting machine commands use the same signed-`ExecutionPlan`, audited,
OCI-provenance execution path as the lower-level commands; non-booting state
commands persist declarative specs under `MVM_HOME`.

The flagship verb is `machine run`, which selects one of three lifecycles by
flag:

- **Transient** (default): boot a fresh microVM from an OCI image, run the
  command, tear the VM down. Routes into the same code path as
  `mvmctl run --image`, inheriting **deny-all networking by default**, opt-in
  egress via `--net` / `--allow-host`, and the same `--profile`, `--volume`,
  `--receipt`, `--json`, and `--dry-run` semantics.
- **Foreground interactive** (`-t`/`--tty`, with `-i` accepted so `-it`
  parses): boot a fresh transient VM, run the requested argv attached to a PTY,
  return that command's exit code, then tear the VM down. **Dev-only** —
  requires DevOnly verbs, is refused for a sealed image (claim 15), and is
  refused when stdin is not a terminal.
- **Persistent** (`machine create` + `machine start`, or `machine run -d`):
  boot a machine that survives after the command returns and is reconnectable by
  name through `machine shell`/`exec`/`stop`. Bare `-d` auto-generates a name and
  prints it; `-d --name <N>` uses your chosen name.

A fourth trigger promotes into the persistent lifecycle without `-d`:
`--healthcheck '<cmd>'` declares the workload a long-running service — its mere
presence registers the machine (shows in `machine ls`, torn down with `machine
stop <name>`) and it runs in the **foreground** unless you also pass `-d`. The
command is exec'd in the guest as a liveness check (exit 0 = healthy); the
`--health-interval`/`--health-timeout`/`--health-retries`/`--health-start-period`
tuning flags are recorded on the machine spec and actively enforced. The
entrypoint's own exit code still terminates the machine either way, so a
healthcheck on a run-to-completion task has no effect.

The resident host-agent daemon (default-on; opt out with
`MVM_HOST_AGENT_DAEMON=0`, in which case health always shows `unknown`) probes
every healthchecked persistent machine every `--health-interval` seconds, once
`--health-start-period` seconds have elapsed since start (failures during the
start period are grace-period noise and don't count). `machine ls` shows the
result in a `HEALTH` column and `machine inspect` shows a `health:` line, one
of:

- `starting` — still inside the start period, or no probe result yet.
- `healthy` — the most recent probe exited 0.
- `unhealthy` — `--health-retries` consecutive probes have failed.
- `-`/`unknown` — no readiness signal (including when the daemon is disabled).

When a service goes `unhealthy`, the daemon restarts it (the same stop→start
`mvmctl machine restart` does) under a bounded exponential backoff: 1s base,
doubling per attempt, capped at 5 minutes, up to 5 attempts. Once the cap is
hit the service is left `unhealthy` rather than crash-looping forever; a
sustained-healthy period afterward resets the restart budget back to zero. A
crashed service — the guest process gone, the agent unreachable — is caught by
the same probe path (an unreachable agent counts as a failed probe) and
restarted under the identical policy, so there's no separate crash-detection
mechanism to reason about.

This is a dev/accessible-tier feature: the check runs inside the guest via the
host agent, so it only applies to backends where that agent is reachable.

Identity and lifetime are separate: `--name <N>` names a foreground transient
run but does not make it persistent. `-d`/`--detach`, `--up-json`, or the
explicit `machine create`/`start` lifecycle make a long-lived machine.
`--volume` host shares work on every run mode. The syntax is
`HOST:/GUEST[:MODE]` (`MODE` defaults to `ro`; `rw` needs `--profile dev` or
`permissive`). Persistent machine specs canonicalize host paths to absolute
paths so later reconnects re-mount the same share regardless of your working
directory; the host directory must exist at boot.

SSH is banned in microVMs, with no dev-tier carve-out: `--allow-host <host:22>`
is refused, the runtime also denies TCP/22 even under broad egress, and there
is no ssh-agent forwarding of any kind — no private keys, `~/.ssh`,
known-hosts material, SSH config, or host agent socket ever crosses into a
guest, on any tier.

| Command | Description |
|---------|-------------|
| `mvmctl machine run --image <ref> -- <cmd>...` | Boot an OCI image, run `<cmd>` with no network, tear down |
| `mvmctl machine run --net --image <ref> -- <cmd>...` | Boot with dev-tier outbound networking enabled |
| `mvmctl machine run --image <ref> --allow-host <host[:port]> -- <cmd>...` | Boot with egress narrowed to the listed TCP host/port entries (`<host>` alone defaults to `:443`) |
| `mvmctl machine run --image <ref> --profile dev --volume .:/work:rw -- <cmd>` | Same, with a writable host share under the dev profile |
| `mvmctl machine run --image <ref> --cpus <n> --memory <size> -- <cmd>` | Resize the transient VM |
| `mvmctl machine run --image <ref> --dry-run -- <cmd>` | Validate and explain the run plan without booting a VM |
| `mvmctl machine run --image <ref> --json -- <cmd>` | Print a redacted JSON execution summary |
| `mvmctl machine run --image <ref> --receipt <path> -- <cmd>` | Write a signed execution receipt |
| `mvmctl machine run -d --image <ref>` | Boot a **persistent** machine, auto-name it (printed), return |
| `mvmctl machine run -d --name <name> --image <ref>` | Boot a **persistent** named machine, return; reconnect via `machine shell <name>` |
| `mvmctl machine run --healthcheck 'curl -fsS localhost/health' --image <ref>` | Boot a **persistent** machine in the foreground (registered, shows in `machine ls`); its presence alone promotes the lifecycle even without `-d` |
| `mvmctl machine run -d --healthcheck 'curl -fsS localhost/health' --name <name> --image <ref>` | Same, detached — the usual way to run a long-lived service |
| `mvmctl machine run --name <name> --image <ref> -- <cmd>` | Boot a named foreground transient machine, run `<cmd>`, tear down |
| `mvmctl machine run -it --image <ref> -- <cmd>` | Run `<cmd>` attached to a PTY, return its exit code, tear down |
| `mvmctl machine run -it --name <name> --image <ref> -- <cmd>` | Same, with a stable transient VM name while it runs |
| `mvmctl machine create <name> --image <ref>` | Persist a named OCI-backed machine spec without booting it |
| `mvmctl machine create <name> --manifest <path>` | Persist a named machine spec from an image-backed `mvm.toml` / `Mvmfile.toml` |
| `mvmctl machine create <name> --image <ref> --net --allow-host <host[:port]>` | Persist a named spec with opt-in egress settings for future lifecycle starts |
| `mvmctl machine create <name> --manifest <path>` | Persist an image-backed `mvm.toml` / `Mvmfile.toml` as a named machine spec |
| `mvmctl machine create <name> --image <ref> --force` | Overwrite an existing named machine spec |
| `mvmctl machine start <name>...` | Boot one or more persisted named machines through the admitted OCI-backed start path (`--receipt`/`--json`/`--dry-run` are single-machine) |
| `mvmctl machine start <name> --dry-run` | Validate and explain the effective machine-start policy without booting a VM |
| `mvmctl machine start <name> --dry-run --json` | Print the machine-start preflight summary as redacted JSON |
| `mvmctl machine start <name> --json` | Print a redacted JSON start summary instead of plain text |
| `mvmctl machine start <name> --receipt <path>` | Write a signed machine-start receipt with effective policy plus the resolved digest and start timestamp |
| `mvmctl machine start <name> --image <ref>` | Start a persisted machine, creating its spec on demand if it does not exist. Combines `machine create <name> --image <ref>` and `machine start <name>` into one command |
| `mvmctl machine start <name> --manifest <path>` | When auto-creating, source defaults (image, sizing, network, volumes, dev-init) from an image-backed `mvm.toml` / `Mvmfile.toml` |
| `mvmctl machine start <name> --image <ref> --cpus N --memory SIZE` | Size the machine when auto-creating it (same defaults as `machine create`) |
| `mvmctl machine start <name> --image <ref> --net --allow-host <host[:port]>` | Set egress policy when auto-creating the machine |
| `mvmctl machine start <name> --image <ref> --force` | If the machine exists with a different config, stop the old instance, overwrite the spec, and start. Without `--force` a config mismatch errors |
| `mvmctl machine restart <name>...` | Restart one or more named machines: stop if running, then start (same stop→start as a config-change recreate). This is also how a running machine picks up a newer version-matched runtime overlay. |
| `mvmctl machine ls` (alias `ps`) | List persisted named machine specs |
| `mvmctl machine ls --json` | Print persisted named machine specs as JSON |
| `mvmctl machine inspect <name>` | Show one persisted named machine spec, plus `enforced-cpu:` — the tier that actually bounded its last boot, read back off the live control. A `cpu-limit:` line shows what was *requested*; the two are separate on purpose, since a request and an enforcement are not the same statement. Absent when no boot has recorded a tier. |
| `mvmctl machine inspect <name> --json` | Print one persisted named machine spec as JSON, with an `enforced_grants` object carrying the achieved per-dimension tiers |
| `mvmctl machine rm <name>... --yes` | Remove one or more persisted named machine specs (refuses a running machine; pass `--force` to stop then remove) |
| `mvmctl machine rm --all --yes` | Remove every persisted named machine spec |
| `mvmctl machine rm <name>... --yes --json` | Print a JSON array deletion summary |
| `mvmctl machine exec <name> -- <cmd>...` | Run a command in an already-started named machine |
| `mvmctl machine exec <name> -it -- <cmd>...` | Run a command in an already-started named machine attached to a PTY |
| `mvmctl machine exec <name>` | Omit the command to drop into an interactive shell (same as `machine shell`) |
| `mvmctl machine shell <name>` | Attach an interactive shell/console to an already-started named machine — persistent or transient (a `machine run --name <name>` VM is reachable while it runs) |
| `mvmctl machine stop <name>...` | Stop one or more already-started named machines (prompts for confirmation; pass `--yes` to skip) |
| `mvmctl machine reconfigure <name> [flags]` | Patch a persistent machine's config and relaunch it. Only the flags you pass are changed; everything else (image, volumes, profile) is preserved. When the machine is running, it is stopped and restarted automatically; when stopped, the change is staged for the next `machine start`. |
| `mvmctl machine reconfigure <name> --net` / `--no-net` | Enable or disable the dev-tier outbound network preset |
| `mvmctl machine reconfigure <name> --allow-host <host[:port]>` | Replace the stored egress allowlist with these hosts (repeatable within one invocation); use `--clear-allow-host` to empty it |
| `mvmctl machine reconfigure <name> --clear-allow-host` | Remove all per-host egress entries and fall back to the default network posture |
| `mvmctl machine reconfigure <name> --cpus <n>` | Change the vCPU count |
| `mvmctl machine reconfigure <name> --memory <size>` | Change the memory limit (accepts `512m`, `1g`, etc.) |
| `mvmctl machine reconfigure <name> --mem-initial <size>` | Change the initial balloon memory target (CLI-only; not exposed on the remote facade) |
| `mvmctl machine check-artifact <artifact.mvm>` | Verify a portable artifact and preview its admission posture without extracting or booting |
| `mvmctl machine check-artifact <artifact.mvm> --key <pubkey>` | Verify with an explicit raw Ed25519 public key |
| `mvmctl machine check-artifact <artifact.mvm> --json` | Print the verified artifact/admission preview as JSON |

### Workload output capture

`machine run` attaches to the workload's output by default — `--detach`,
`--json`, and `--up-json` are the three ways to opt out. Interrupting an
attached run on a **persistent** machine detaches from the output and leaves
the machine running; the command says so before it blocks.

Every workload's stdout and stderr are captured whether or not anybody is
watching. Two sources feed one stream: the guest's entrypoint frames over
vsock, which keep their channel, and the hypervisor's console capture, which
covers boot and anything written after the guest agent is gone. Console-sourced
records are recorded as `stdout` whichever fd wrote them, because a console is
one merged byte stream; a narrowed `--stream` read prints a note saying so.

Records are hash-chained and the recorded transcript is sealed to a Merkle root
at exit, so `machine logs` verifies what it shows and **exits nonzero on a
verification failure**, mirroring `mvmctl trust audit verify`. A pruned window
is not a failure: retention is a ring, so a chatty workload loses its oldest
records rather than being throttled or killed, and the loss is announced as a
gap or truncation notice on stderr.

Recording is on by default. `ExecutionPlan.stream_retention` (`persist` /
`ephemeral`) is a signed plan field, not a CLI flag, recorded on
the `plan.admitted` audit entry so an absent transcript is attributable rather
than ambiguous. Nothing selects `ephemeral` today — every production caller
takes the default — so treat the field as the place a future opt-out will live
rather than one you can reach now.

Three limits are worth knowing before you rely on this:

- The recorded transcript is redacted; the **console fallback is not**, so a
  read that falls back to (or splices in) the console shows raw guest bytes.
- A machine started with `-d` is captured only for as long as the starting
  process lives, so a detached machine's later output reaches no recorder. You
  still see it, via the unchained console log.
- A spliced read **repeats** the part the recording already showed, because
  console byte offsets and transcript sequence numbers share no coordinate.
  Duplicated, never lost.

Full walkthrough: [Workload output
streaming](/guides/workload-output-streaming/).

### Runtime overlay updates

For overlay-backed guests, runtime updates happen on **start/restart**, not by
live remounting inside a running VM:

- `mvmctl machine start <name>` picks up the overlay version attached for that
  boot.
- `mvmctl machine restart <name>` is the normal way to move a running machine
  onto a newer version-matched runtime overlay.
- A running machine keeps the runtime overlay version it already booted with
  until restart.

### `machine run` lifecycles in practice

A transient run is the default and needs no flags — it boots, runs the command,
and tears the VM down:

```bash
mvmctl machine run --image alpine -- echo hi      # prints "hi", VM gone
```

A bare `machine run --image alpine -- /bin/sh` is **non-interactive**: it streams
the command's output but forwards no terminal. For a live shell or any command
that needs a TTY, add `-it` and pass the foreground argv explicitly:

```bash
mvmctl machine run -it --image <dev-image> -- /bin/sh   # exits with /bin/sh, VM gone
mvmctl machine run -it --image <dev-image> -- htop      # exits with htop, VM gone
```

For OCI `--image` runs that request outbound egress (`--net` or `--allow-host`),
`mvmctl` selects only backends that can keep the guest NIC-less and route
traffic through the host-side vsock mediation endpoint. On that path the
injected guest `/init` starts `mvm-egress-client` and the runtime injects proxy
env vars pointing at its loopback SOCKS listener automatically. Today that
means `hvf`; incapable backends are refused rather than silently
falling back to a guest NIC. That makes TCP/HTTP clients work, but it does
**not** add ICMP
support: `ping` is not a valid smoke test for `--allow-host`.

Naming a foreground run does not make it persistent; it only gives the transient
VM a stable identity while it is running:

```bash
mvmctl machine run --name debug --image alpine -- echo hi
mvmctl machine run -it --name debug --image <dev-image> -- /bin/sh
```

Use the explicit persistent lifecycle when you want the VM to survive:

```bash
mvmctl machine run -d --image alpine          # boots, prints e.g. "blue-fox-3f2a", returns
mvmctl machine shell blue-fox-3f2a            # reconnect (dev PTY)
mvmctl machine exec  blue-fox-3f2a -- ps          # one-shot command in the running machine
mvmctl machine exec  blue-fox-3f2a -it -- /bin/sh   # PTY command in the running machine
mvmctl machine stop  blue-fox-3f2a --yes      # tear it down when done
```

`-d --name <N>` does the same with a name you choose.

**Interactive is dev-only.** `-t`/`--tty` attaches the foreground command to a
PTY and requires DevOnly verbs; it is refused for a sealed/production image
(claim 15 — no interactive access to a sealed microVM) and when stdin is not a
terminal. `machine run -it`
requires an argv after `--`; use `machine shell <name>` (or `machine exec
<name>` with no argv) for the default shell on an already-running machine.

`machine create` accepts either `--image <ref>` or an image-backed manifest, not
both. When `--image` is omitted, it searches the current directory for
`mvm.toml` / `Mvmfile.toml`; `--manifest <path>` selects a file explicitly. The
persisted spec carries the manifest's image, CPU/memory sizing, `mem_initial`,
network defaults, allow-hosts, volumes, and its `[grants]` table.

A workload's grants — what it may consume and where it may reach — can be
declared in four places, resolved **per dimension** from highest precedence to
lowest: CLI flags, a `--grants-file` JSON document, the manifest's `[grants]`
table, and the `~/.mvm/config/config.toml` defaults. Per dimension means a
`--cpu-limit` on the command line does not discard an egress allowlist the
manifest declared; each of CPU, wall clock, and egress is settled on its own.

`machine create` is the verb that reads the `[grants]` table — from `--manifest
<path>`, or from the `mvm.toml` / `Mvmfile.toml` in the current directory when
`--image` is omitted. Transient `machine run` reads no project manifest at all
(its own `--manifest` names a pre-built image, not an `mvm.toml`), so grants
there come from `--cpu-limit`, `--timeout`, `--allow-host`, `--grants-file`, and
the host config. That split is deliberate: discovering an `mvm.toml` from the
working directory would let a manifest in an unrelated checkout cap a run that
never meant to use it.

```toml
# mvm.toml
image = "alpine:3.20"

[grants]
cpu_millicores = 1500      # or cpu_fuel = <instructions>; the two are units, not precisions
wall_clock_secs = 600      # must be > 0; omit to leave the workload unbounded
allow_hosts = ["api.example.com:443"]
```

`[grants].allow_hosts` and `[network].allow_hosts` are two spellings of one
decision, so declaring both is a parse error. The granted form is the one the
egress gate enforces: the run's network policy is *derived* from it, never
supplied alongside it, so the policy in force and the policy the plan was signed
over cannot drift apart. An absent egress grant and an empty allowlist both mean
deny-all.

Every grant is bounded by the host operator's ceiling
(`max_cpu_millicores`, `max_memory_mib`, `max_wall_clock_secs` in
`~/.mvm/config/config.toml`), which no surface above can reach and which is
checked before the plan is signed. The ceiling bounds one workload; two further
keys bound the *sum* across the host — `host_budget_memory_mib` and
`host_budget_cpu_millicores` refuse a boot whose figures, added to every live
machine's admitted charge, would exceed the headroom. Both are unset by
default. The total counts only machines whose supervisor process is actually
alive, so a VM that crashed without cleanup cannot lock the host out, and it
counts each machine's configured maximum rather than its current commitment,
which the memory balloon moves at runtime. Separately, `default_cpu_millicores`
and `default_wall_clock_secs` supply defaults for dimensions nothing else named.
There is no host-wide egress default: one would open outbound access for every
workload that never asked for any. Relative manifest volume host paths
are resolved relative to the manifest file; volume validation keeps the shared
default of read-only mounts unless `:rw` is explicit. `--name` is optional: when
omitted, `machine create` auto-generates a name and prints it (mirroring
`machine run -d`).

`machine start`, `machine exec`, `machine shell`, and `machine stop` require the
named `MachineSpec` to exist first. `machine start` resolves the stored OCI
image through the normal cache/materialization path, emits the same admission
and OCI provenance audit substrate as the transient image runner, then boots
the named VM with any persisted `mem_initial` and volume settings. When the
stored machine requests outbound egress and is OCI-backed (`machine create
--image`, `machine create --manifest` with an image-backed manifest, or
`machine run -d --image`), `machine start` applies the same NIC-less
host-vsock-proxy backend gate as transient `run --image`: only backends that
honestly advertise `{ vsock, no_routable_guest_nic, host_vsock_proxy }` are
allowed, and incapable backends are refused instead of silently falling back to
a guest NIC helper. `no_routable_guest_nic` is a reachability
guarantee: it holds whether the backend attaches a drained/sinked virtio-net
device with no upstream route or presents no NIC device at all. When the named spec came from an image-backed
manifest, `machine create --manifest`
persists the manifest's `net`, `[network].allow_hosts`, `cpus`, `mem`,
`mem_initial`, `[dev].volumes`, and `[dev].init` fields into the durable
machine spec; relative manifest volume paths are resolved against the manifest
directory when persisted. `dev.init` currently requires
`--profile dev` or `--profile permissive`; standard/prod-like profiles refuse
it. `machine start --dry-run` reports the
effective network posture, enforcement tier, dev-init hash/count,
and redacted volume policy without resolving or booting the image; the signed
machine-start receipt carries the same policy summary plus the resolved digest
and start timestamp after a real boot. `exec` / `shell` / `stop` reuse the
existing console/down paths for the running VM. `machine reconfigure <name>`
patches a subset of the stored config (`net`, `allow_host`, `cpus`, `memory`, and the CLI-only `mem_initial`) and relaunches the machine — auto stop + start when running,
persist-only when stopped; identity, image, and volumes are preserved. `machine pack` for portable
signed artifacts and live `machine run <artifact.mvm>` are still follow-up work.
`machine check-artifact` is the current read-only portable-artifact gate: it
verifies the signed manifest, file hashes, format version, sealed-prod verity
requirements, host architecture, and fail-closed admission posture before
printing a preview. Use `mvmctl machine run` for the manifest/flake path that already
exposes named networks and policy bundles.

### Lineage / time-travel

`mvmctl machine timeline` / `revert` / `rewind` / `advance` are the advanced
lineage and time-travel verbs over the checkpoint and image-node stores.
`timeline` is a read-only navigator; the three restore verbs each launch a
fresh, **re-admitted** VM at a prior (or adjacent) state rather than mutating
one in place. Every verb verifies its target against the signed audit chain up
front and fails closed on an un-audited, tampered, or dangling record — the same
gate `machine checkpoint verify` and `machine checkpoint fork` enforce. A
completed checkpoint restore emits a chain-signed `checkpoint.restored` entry
and an image restore an `image.reverted` entry, each carrying the initiating
verb (`revert` / `rewind` / `advance`) as its `via` label.

A target is a checkpoint id or a `sha256:<hex>` content-address; a digest may
name a node in the checkpoint store, the image store, or (rarely) both, in which
case `--kind checkpoint\|image` disambiguates it. Image nodes have no id — their
identity is their digest. `--new-id` and `--hypervisor` apply to checkpoint
restores only; an image restore auto-names its VM and re-runs the node's
digest-pinned reference through the admitted `machine run` path.

| Command | Description |
|---------|-------------|
| `mvmctl machine timeline <id\|digest> [--kind checkpoint\|image] [--json]` | Render a checkpoint or image node's lineage — ancestors back to genesis plus its immediate children — verifying each hop against the signed audit chain. Read-only: no restore, no admission, no boot. A tampered, un-audited, or dangling hop is marked (and the overall verdict fails), but the timeline still renders so it stays usable for navigation. |
| `mvmctl machine revert <id\|digest> [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]` | Restore a prior state: launch a fresh, re-admitted VM at the node the target names. Checkpoint restores fork a new VM identity (`--new-id` names it; `--hypervisor` picks the backend, default `firecracker`); image-node restores re-run the node's digest-pinned reference through the admitted run path and auto-name their VM. |
| `mvmctl machine rewind <id\|digest> [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]` | Restore the target's parent — one step back in the lineage. Same re-admission and fail-closed guarantees as `revert`; refuses a genesis root (no parent) or a structurally broken lineage. |
| `mvmctl machine advance <id\|digest> [--to <child-digest>] [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]` | Restore a child of the target — one step forward. Forward is a tree, so `--to <child-digest>` is required when the target has more than one child (a fork). Same re-admission and fail-closed guarantees as `revert`. |

### Fork / restore

`mvmctl machine fork` and `mvmctl machine restore` are the agent-facing
primitives for branching a running machine or an existing `vm_full` checkpoint
into a fresh child VM. Both capture/branch through the consolidated
`VmBackend`/checkpoint seam and deliver a new identity, authority, and
per-instance secrets; the parent carries no workload authority into the child.
Use `--as <name>` for an explicit child name or `--branch <slug>` for an
auto-generated dev-sandbox name. The lower-level `machine checkpoint fork` and
`machine checkpoint restore` surfaces remain available for power users.

## Sandbox State

| Command | Description |
|---------|-------------|
| `mvmctl machine sandbox gc` | Dry-run cleanup of stale sandbox name-registry entries for stopped or expired VMs |
| `mvmctl machine sandbox gc --dry-run` | Explicit dry-run; reports candidates and does not mutate state |
| `mvmctl machine sandbox gc --apply` | Remove stale stopped/expired registry entries and emit a `SandboxGc` audit entry |
| `mvmctl machine sandbox gc --json` | Print a machine-readable GC summary with candidates, reasons, and removed count |

`sandbox gc` never tears down a live VM. Entries that still appear as starting,
running, or paused in a backend listing are skipped; cleanup only removes stale
host registry records.
`--json` does not change the safety mode: cleanup remains dry-run unless
`--apply` is also passed.

## Checkpoint

`mvmctl machine checkpoint` is the advanced checkpoint store surface for
list/remove/fork/diff and explicit class selection. Recovery tiers are
backend-specific; inspect `mvmctl doctor` before requesting one. Unsupported
save/restore and warm-start requests fail with an actionable error rather than
silently selecting a weaker tier.

| Command | Description |
|---------|-------------|
| `mvmctl machine checkpoint create <name> [--class fs-quick\|vm-full] [--tag <tag>] [--json]` | Capture a checkpoint. `--class vm-full` saves full machine state (memory + disk) via HVF's `saveMachineStateToURL`. Records content hash in the audit chain. |
| `mvmctl machine checkpoint restore <checkpoint> [--json]` | Restore a previously created `vm_full` checkpoint into the original VM identity. Re-hashes content against the recorded metadata before loading. |
| `mvmctl machine checkpoint fork <checkpoint> [--new-id <name>] [--boot] [--json]` | Restore a checkpoint into a new VM identity (new name, separate audit lineage). `vm_full` forks auto-boot; `fs_quick` forks boot only with `--boot`. |
| `mvmctl machine checkpoint ls [--json]` | List checkpoints. |
| `mvmctl machine checkpoint diff <a> <b> [--json]` | Compare two checkpoint metadata/content manifests. |
| `mvmctl machine checkpoint verify <checkpoint> [--json]` | Verify a checkpoint's full lineage against the signed audit chain (recomputed content-address must match both the stored `meta_digest` and the digest signed at creation, at every hop). Exits nonzero on any drift, chain mismatch, missing signed entry, or broken lineage. |
| `mvmctl machine checkpoint rm <checkpoint> [--json]` | Delete a checkpoint and its blobs. |

Checkpoint blobs are stored under the configured checkpoint store (`MVM_HOME` / `~/.mvm` via the core path helpers). The audit chain records `checkpoint.created`, `checkpoint.restored`, and `checkpoint.forked` entries with content hashes; restore and fork refuse tampered checkpoint content before booting.

## Durable Agent Sessions

`mvmctl agent-session` is the operator surface for durable agent sessions: an
agent session outlives the sandbox that runs it, parking (releasing its
sandbox) and resuming later as a fresh admission. It is deliberately not
spelled `session` — `mvmctl machine session` already means machine-session
residency, a warm VM kept alive across `invoke` calls, which is a different
concept over a different store.

| Command | Description |
|---------|-------------|
| `mvmctl agent-session open <id> [--resume-point <sha256:...>] [--member <name>]...` | Record a new session, resident from the start, at generation 1. Refuses if a record already exists under that id. `--member` is repeatable. |
| `mvmctl agent-session ls [--json]` | List every session recorded on this host, one summary line each: id, generation, residency, and — when parked — reason and storage tier. |
| `mvmctl agent-session show <id> [--json]` | Print one session's recorded state in full: residency, generation, storage tier, park reason, journal cursor, resume point, approval head, members, timestamps. An absent session is an error naming the id. |
| `mvmctl agent-session park <id> --reason <reason> [--journal-cursor <n>] [--approval-head <sha256:...>]` | Release an active session's sandbox. `--reason` is one of `approval-wait`, `idle`, `host-shutdown`, `operator`, `retention-demotion`, and selects the storage tier. Emits a `session.parked` chain entry. |
| `mvmctl agent-session resume <id> --backend <name> --image <ref> --image-sha256 <hex> --cpus <n> --mem-mib <n> [--kernel-sha256 <hex>] [--approval-head <sha256:...>]` | Re-admit a parked session under a freshly signed `ExecutionPlan`. Emits a `session.resumed` chain entry. |

`open` is what gives the other four subcommands something to act on: `park` and
`resume` both need a record that already exists, and nothing else on the host
writes one.

`resume` takes the workload material — backend, image reference, rootfs and
kernel SHA-256, vCPUs, memory — as flags because the session record
deliberately does not carry it. An image, a kernel and a sandbox size each
change on their own schedule, and recording them in the record would make it a
second copy of the plan that has to be kept in step with one. Deriving them
from the resume point's supervisor config instead is a later step; taking them
as flags keeps the seam visible rather than guessing.

A resume stops at an admitted plan. It does not restore a memory image and does
not boot a sandbox — the command says so on completion.

`--approval-head` on `resume` is the operator's assertion of where the approval
ledger is *now*. The store refuses when it differs from the head recorded at
park time, so a session cannot silently resume under grants it was never
admitted for. A session parked without a head resumes unfenced, and
`agent-session show` says so in as many words.

Both chain entries are best-effort: if the entry cannot be written the
transition is still reported as done, with a warning, because the store write
already succeeded and failing afterwards would tell an operator a park did not
happen when it did. A caller that needs the entry must verify the chain
separately.

## File Copy

| Command | Description |
|---------|-------------|
| `mvmctl machine cp <host-path> <vm>:/absolute/path` | Copy one regular file from the host into a running VM |
| `mvmctl machine cp <vm>:/absolute/path <host-path>` | Copy one regular file from a running VM to the host |
| `mvmctl machine cp --force <src> <dst>` | Overwrite an existing destination |
| `mvmctl machine cp --create-parents <src> <dst>` | Create destination parent directories |
| `mvmctl machine cp --max-bytes <n> <src> <dst>` | Refuse copies larger than the byte cap. Default: 16 MiB |
| `mvmctl machine cp --json <src> <dst>` | Print a machine-readable copy summary without host paths or file contents |

Exactly one endpoint must use `VM:/absolute/path` form. Guest paths are
validated by the guest agent's filesystem policy before any read or write. Host
paths and file contents are not written to audit logs; successful copies emit
`VmFileCopy` with direction, guest path, and byte count.
`--json` follows the same redaction rule: the summary includes direction, VM
name, guest path, copied byte count, and effective copy options, but not the
host endpoint.

### Run examples

```bash
mvmctl run -- uname -a                                # default image
mvmctl run --manifest minimal -- /bin/true            # named template
mvmctl run --mount .:/work:ro -- ls /work            # share current dir, RO
mvmctl run -e DEBUG=1 -- env | grep DEBUG             # env var injection
mvmctl run --launch-plan ./launch.json                # launch-plan entrypoint
```

### Launch-plan shape

`--launch-plan` accepts either of two JSON shapes — the shape is
auto-detected. Only the entrypoint is consumed (image selection
still comes from `--manifest` or the bundled default in v1). Both
shapes were historically produced by the `mvmforge` toolchain
([migration guide](/guides/mvmforge-migration/)); `mvmctl build compile`
is the canonical producer today.

**LaunchPlan artifact** (top-level `entrypoint`):

```json
{
  "artifact_format_version": "1.0",
  "workload_id": "hello",
  "entrypoint": {
    "command": ["python", "main.py"],
    "working_dir": "/app",
    "env": { "PORT": "8080" }
  },
  "env": { "LOG_LEVEL": "info" }
}
```

**Workload IR manifest** (top-level `apps[]`):

```json
{
  "apps": [
    {
      "name": "hello",
      "entrypoint": {
        "command": ["python", "main.py"],
        "working_dir": "/app",
        "env": { "PORT": "8080" }
      },
      "env": { "LOG_LEVEL": "info" }
    }
  ]
}
```

Multi-app IR manifests are rejected — that's an orchestration concern
that belongs in `mvmd`, not in `mvmctl run`. Env precedence (lowest →
highest): top-level/app `env` → `entrypoint.env` → CLI `--env`.

### Snapshot restore

When the request boots a registered template (`--manifest <name>`) and
that template has a compatible recovery artifact, `mvmctl run` uses the
selected backend's advertised recovery tier instead of cold-booting.

The snapshot path activates only when *all* of the following hold:

- the image source is a **registered template** (the bundled default
  image has no template snapshot to restore from);
- there are **no** live directory shares (extra drives would mismatch the
  snapshot's recorded drive layout);
- the active backend reports snapshot support.

Recovery tiers are not interchangeable. Unsupported live-memory,
machine-state, disk-only, or standby requests fail with an actionable error;
the CLI does not silently fall back to a weaker tier. See the [Sandboxed
Exec](/guides/exec/) guide for the full background.

## Volumes

| Command | Description |
|---------|-------------|
| `mvmctl machine volume create <name>` | Create a locked mvm-managed encrypted local volume archive |
| `mvmctl machine volume create <name> --root <absolute-dir>` | Create the mvm-managed encrypted volume under a specific root |
| `mvmctl machine volume create <name> --host-backed` | Create the previous host-backed managed directory, requiring encrypted backing storage |
| `mvmctl machine volume unlock <name>` | Decrypt a managed volume into its plaintext mount directory |
| `mvmctl machine volume lock <name>` | Seal a managed volume back into its encrypted archive and remove plaintext |
| `mvmctl machine volume catalog` | List managed local volumes |
| `mvmctl machine volume catalog --json` | List managed local volumes as JSON |
| `mvmctl machine volume mount <vm> --volume <name> --guest <absolute-path>` | Register an unlocked managed local virtio-fs volume mount for a VM. Read-only by default |
| `mvmctl machine volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path>` | Register an ad-hoc encrypted host directory as a virtio-fs volume mount |
| `mvmctl machine volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path> --rw` | Register the volume read-write |
| `mvmctl machine volume ls <vm>` | List registered volume mounts |
| `mvmctl machine volume ls <vm> --json` | List registered volume mounts as JSON |
| `mvmctl machine volume unmount <vm> <guest-path>` | Remove a registered volume mount |

Managed local volumes are encrypted by mvm at rest. `volume create` writes a
locked AES-256-GCM encrypted archive plus wrapped per-volume data key metadata
in `~/.mvm/volumes/registry.json`; it does not leave a plaintext directory
behind. `volume unlock` decrypts that archive into a private plaintext mount
directory, `volume mount` refuses the volume while it is locked, and
`volume lock` reseals the directory and removes plaintext after use.

Ad-hoc `--host` mounts and `--host-backed` managed volumes keep the previous
host-backed model: the exact host directory must live on encrypted backing
storage, either a macOS volume that `diskutil` reports as encrypted or a Linux
filesystem whose backing device sits on dm-crypt/LUKS. Those commands fail
closed when mvm cannot confirm that backing storage.

## Default microVM Image

When an image-taking command is invoked without `--flake` or `--manifest`,
`mvmctl` falls back to a bundled minimal image (busybox + the guest agent).
This applies to:

- `mvmctl run -- <cmd>` — boots a fresh transient microVM and runs `<cmd>`
- `mvmctl machine run` — boots a long-running microVM with the same image

The image is the bundled default — a minimal `mkGuest` rootfs shipped
with mvm. Built via Nix on first use, cached at
`~/.mvm/cache/default-microvm/` (kernel + rootfs). To customize, pass
`--manifest` or `--flake` pointing at your own project's `mkGuest`
output (see [Building MicroVM Images](/guides/building-microvm-images)).

Build resolution order on first use:

1. **Builder VM.** mvm bootstraps or reuses the project Linux builder VM,
   runs Nix evaluation and `nix build` inside it, and extracts the rootfs.
   No host-side Nix is required, and there is no interactive step to
   perform first — the builder VM is headless and builds unattended.
   `mvmctl bootstrap` can pre-warm it ahead of time if you'd rather not
   wait on the first build.
2. **Prebuilt artifacts (offline).** If the host is fully offline and the
   builder image is not available, mvm can use the prebuilt
   `default-microvm` artifacts from the GitHub release matching the
   `mvmctl` version, hash-verified per the `*-checksums-sha256.txt`
   manifest (security claim 6).

See [Builder VM](/guides/builder-vm/) for the host-orchestrated build
flow and the distinction between build time and runtime boot time.

## Cache

| Command | Description |
|---------|-------------|
| `mvmctl cache info` | Show cache directory path, disk usage, and a per-entry footprint breakdown (entries belonging to a removed subsystem are flagged `retired`). Sizes are allocated blocks with symlinks and repeated hardlinks counted once, so they match `du -sh` |
| `mvmctl cache prune` | Remove stale temp files; report (but don't delete) retired top-level cache dirs |
| `mvmctl cache prune --dry-run` | Show what would be removed without deleting |
| `mvmctl cache prune --orphan-builds` | Also sweep orphaned builds — built artifacts whose source `mvm.toml` is gone (equivalent to `mvmctl manifest prune --orphans`) |
| `mvmctl cache prune --orphan-dirs` | Also remove retired top-level cache dirs — leftovers from a subsystem mvm no longer has. Only names on the built-in retired list are candidates; a cache still in use is never removed |
| `mvmctl cache prune --deep` | Reclaim regenerable caches too — Stage 0 blobs, the prebuilt default microVM image, pulled OCI layers (each costs a re-fetch/rebuild next time). Implies `--orphan-dirs` |
| `mvmctl cache repair` | Clear a degraded builder VM store so the next build cold-rebuilds it. Refuses while a Stage 0 bootstrap is in flight; auto-stops a running builder VM first |
| `mvmctl cache repair --force` | Clear the store even while a Stage 0 bootstrap lock is held (use only if the lock is stale, e.g. after a crash) |

## Workload Authoring and Inspection

These verbs operate on a workload before and after it runs, rather than on a
running microVM.

| Command | Description |
|---------|-------------|
| `mvmctl init` | Scaffold a new project (`mvm.toml` alongside your `flake.nix`) |
| `mvmctl generate sdk <script>` | Generate a runnable project from an SDK-decorated `.py`/`.ts` source: parses the decorator, emits `flake.nix` + `launch.json`, bundles the source tree into `--out <dir>` |
| `mvmctl template list` | List available templates (bundled plus cached remote) |
| `mvmctl template search <query>` | Search the remote registry for matching templates |
| `mvmctl template show <name>` | Show details for one bundled or remote template |
| `mvmctl deploy <ir.json>` | Build, seal, and record a workload into a local deployment directory (`image.tar.gz`, `rootfs.ext4`, `deploy.json`); optionally ship it to mvmd |
| `mvmctl deploy --from-ir <path>` | Read the Workload IR from a file instead of a positional path or stdin |
| `mvmctl prepare` | Report whether a verified runtime pack is ready for instant launch |
| `mvmctl plugin list` | List the coding agents mvm can emit an integration for |
| `mvmctl plugin install <agent>` | Write that agent's integration files into the project (`--dir`, `--dry-run`, `--force`). Emits config only — mvm runs no agent-facing server |
| `mvmctl bench` | Measure this host's launch latency against the published budgets, printing each percentile beside the budget it is judged against |
| `mvmctl bench --lane <lane>` | Pick the lane: `prepared-cold` (default), `prepared-cold-mount-hit`, `mount-miss`, `artifact-miss`, `warm-claim` |
| `mvmctl bench --runs <n> --warmup <n>` | Sample counts. Below 20 measured runs the report is indicative only, not publication-grade |
| `mvmctl bench --json` | Emit the versioned report JSON — the same shape the CI gate produces, so the two are comparable |
| `mvmctl bench -- <launch>` | Measure a specific launch instead of the reproducible default (`run --no-detect -- /bin/true`) |
| `mvmctl explain <run>` | Explain a run after the fact from the chain-signed audit log |
| `mvmctl watch <ir.json>` | Rebuild a workload when its local inputs change |

## Packs, Bundles, and Dependencies

| Command | Description |
|---------|-------------|
| `mvmctl pack list` | List every recorded pack version, marking each key's active one |
| `mvmctl pack rollback` | Point a pack class's active version at an already-cached one |
| `mvmctl pack prune` | Reclaim non-active pack versions beyond the newest N per key |
| `mvmctl pack download` | Fetch a pack version into the cache without changing the active one |
| `mvmctl pack update` | Fetch the latest pack version and activate it |
| `mvmctl bundle export` | Seal a built template into a signed `.mvmpkg`, signed by the host signer at `~/.mvm/keys/host-signer.ed25519` — the same key that signs `ExecutionPlan` envelopes |
| `mvmctl bundle fetch` | Verify a `.mvmpkg` against the local trust store, reporting the parsed manifest |
| `mvmctl bundle install` | Verify and atomically install a `.mvmpkg` into `~/.mvm/bundles/<sha>/` |
| `mvmctl bundle gc` | Prune installed bundles — a specific `<SHA>` or `--all` |
| `mvmctl artifact pack` / `verify` / `inspect` / `extract` | Pack or verify signed `.mvm` artifacts |
| `mvmctl deps inspect` | Show a sealed application-dep volume's SBOM, CVE, and hash-chained metadata without spawning a VM |
| `mvmctl deps audit` | Re-verify a sealed dep volume against its recorded chain |
| `mvmctl deps capture` / `install` | Capture or install application dependencies into a sealed volume |
| `mvmctl pool warm [COUNT]` | Pre-spawn standby microVMs so the next run claims a warm one |
| `mvmctl pool status [--json]` | Report standby pool occupancy |

## Security

> Plan 40 dropped the standalone `mvmctl security status` verb. Posture checks now live inside `mvmctl doctor`.

## Utilities

| Command | Description |
|---------|-------------|
| `mvmctl shell-init` | Print shell configuration (completions + dev aliases) to stdout |
| `mvmctl completions <bash\|zsh>` | Print a completion script. `shell-init`'s eval block calls this; the hidden `--emit-completions` flag it used to carry is gone |
| `mvmctl ops metrics` | Show runtime metrics (Prometheus text format) |
| `mvmctl ops metrics --json` | Show runtime metrics as JSON |
| `mvmctl ops mcp stdio` | Serve capability-derived `MvmClient` tools as newline-delimited MCP JSON-RPC over local stdin/stdout |
| `mvmctl env uninstall` | Remove Firecracker, the builder microVM image, and all mvm state (confirmation required) |
| `mvmctl env uninstall -y` | Uninstall without confirmation |
| `mvmctl env uninstall --all` | Also remove ~/.mvm/ config dir and /usr/local/bin/mvmctl binary |
| `mvmctl env uninstall --dry-run` | Print what would be removed without removing |

## Global Options
## Capture

Inspect a project environment, produce a reviewable capture report, resolve it to the canonical MVM IR, render Nix artifacts, and optionally verify them in the Linux builder VM.

### `mvmctl capture project`

Inspect a project directory and emit a versioned capture report.

| Option | Description |
|--------|-------------|
| `<path>` | Project directory to inspect |
| `--output <path>` | Output file for the capture report (required) |
| `--run "<cmd>"` | Explicit command to record for later tracing/verification; repeatable |

### `mvmctl capture resolve`

Resolve a capture report into the canonical MVM IR.

| Option | Description |
|--------|-------------|
| `<report>` | Capture report to resolve |
| `--output <path>` | Output file for the canonical IR (required) |

### `mvmctl capture verify`

Render `flake.nix`, `launch.json`, and `workload.json` from the canonical IR and record verification status.

| Option | Description |
|--------|-------------|
| `<environment>` | Canonical IR file produced by `capture resolve` |
| `--manifest-dir <dir>` | Directory containing the project source (defaults to the current directory) |
| `--out-dir <dir>` | Directory for rendered Nix artifacts and `verification.json` (defaults to a temp directory) |
| `--run "<cmd>"` | Verification command to record or execute; repeatable |
| `--exec-in-builder-vm` | Build the rendered flake inside the Linux builder VM via `mvmctl __builder-shell-job`. Requires a bootstrapped builder VM. Default behavior records the command without executing it |
| `--boot-and-replay` | Boot a microVM inside the Linux builder VM and replay the verification command as the guest entrypoint. Requires a bootstrapped builder VM with working microVM support. Mutually exclusive with `--exec-in-builder-vm`; default behavior records the command without executing it |

Output files written to `--out-dir`:

- `flake.nix` — Nix flake defining the guest image.
- `launch.json` — resolved entrypoint and metadata.
- `workload.json` — host-side workload IR.
- `verification.json` — canonical IR plus a `verification` array with one record per `--run` command.

See the capture guide for security boundaries and limitations.

## Global Options

All commands accept these global options:

| Option | Description |
|--------|-------------|
| `--log-format <human\|json>` | Log format: human (default) or json (structured) |
| `--fc-version <VERSION>` | Override Firecracker version (e.g., v1.14.0) |
| `--verbose` (alias `--debug`) | Show verbose `[mvm]` progress messages. Implied when `RUST_LOG` is set. |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MVM_HOME` | The single root for all mvm state (data, cache, config, run, state, share, vms) | `~/.mvm` |
| `MVM_FC_VERSION` | Firecracker version (auto-normalized to `vMAJOR.MINOR`) | Latest stable |
| `MVM_FC_ASSET_BASE` | S3 base URL for Firecracker assets | AWS default |
| `MVM_FC_ASSET_ROOTFS` | Override rootfs filename | Auto-detected |
| `MVM_FC_ASSET_KERNEL` | Override kernel filename | Auto-detected |
| `MVM_BUILDER_MODE` | Builder execution mode: `host` (default) or `vsock`; `auto` is accepted as a legacy alias for `vsock` | `host` |
| `MVM_BUILDER_BACKEND` | Builder VMM selection: `libkrun`, `hvf`, or `qemu`. Defaults to the platform's native builder (macOS 26+ → `hvf`, Linux KVM → `qemu`, otherwise `libkrun`) | Platform default |
| `MVM_BUILDER_LOCK_WAIT_SECS` | Seconds to wait for the shared Nix store image lock when another build holds it; set to `0` to fail fast instead of queueing | `3600` (1 hour) |
| `MVM_NO_PERSISTENT_BUILDER` | Set to `1` to disable automatic routing through a persistent-builder session | Unset |
| `MVM_TEMPLATE_REGISTRY_ENDPOINT` | S3-compatible endpoint URL for template push/pull | None |
| `MVM_TEMPLATE_REGISTRY_BUCKET` | S3 bucket name for templates | None |
| `MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID` | S3 access key ID | None |
| `MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY` | S3 secret access key | None |
| `MVM_TEMPLATE_REGISTRY_PREFIX` | Key prefix inside the bucket | `mvm` |
| `MVM_TEMPLATE_REGISTRY_REGION` | S3 region | `us-east-1` |
| `OPENAI_API_KEY` | Enables LLM-backed template planning for `template init --prompt` | None |
| `MVM_TEMPLATE_PROVIDER` | Prompt planning provider: `auto`, `openai`, `local`, or `heuristic` | `auto` |
| `MVM_TEMPLATE_OPENAI_MODEL` | OpenAI model used for prompt planning | `gpt-5.2` |
| `MVM_TEMPLATE_OPENAI_BASE_URL` | Override OpenAI API base URL for prompt planning | `https://api.openai.com` |
| `MVM_TEMPLATE_LOCAL_MODEL` | Local AI model name sent to an OpenAI-compatible local endpoint | `qwen2.5-coder-7b-instruct` |
| `MVM_TEMPLATE_LOCAL_BASE_URL` | Base URL for an OpenAI-compatible local AI endpoint such as LocalAI or `llama.cpp` server | None |
| `MVM_TEMPLATE_LOCAL_API_KEY` | Optional API key for the local AI endpoint | None |
| `MVM_TEMPLATE_LOCAL_PROBE_TARGETS` | Comma-separated base URLs to probe for a local OpenAI-compatible endpoint in `auto` mode (overrides defaults `http://127.0.0.1:11434` and `http://127.0.0.1:8080`) | Defaults |
| `MVM_TEMPLATE_NO_LOCAL_PROBE` | Set to `1` to skip the local-endpoint probe in `auto` mode (CI / sandboxed environments where loopback connects can hang) | Unset |
| `MVM_PRODUCTION` | Enable production mode checks | `false` |
| `MVM_OCI_POLICY` | OCI production policy TOML used by `mvmctl image pull --prod` and `mvmctl run --image --prod` | `$MVM_HOME/oci-policy.toml` |
| `MVM_OCI_BEARER_TOKEN_<HOST>` | Bearer token for one OCI registry host (`ghcr.io` -> `MVM_OCI_BEARER_TOKEN_GHCR_IO`) | Unset |
| `MVM_OCI_BEARER_TOKEN` | Global fallback bearer token for OCI registry pulls | Unset |
| `RUST_LOG` | Logging level (e.g., `debug`, `mvm=trace`) | `info` |
| `MVM_PHASE_TIMING` | Set to `1`/`true` to print a transient run's per-phase launch breakdown to stderr as two greppable lines: `[mvm] phase-timing:` for the coarse buckets, plus `[mvm] phase-timing-detail:` for whichever sub-phases were measured. Set to `tree` for the same spans rendered as one nested, aligned report grouped by containment — easier to read, but not a stable format to parse | Unset |
| `MVM_LAUNCH_SAMPLE_JSON` | Path a transient run writes its machine-readable launch sample to — build profile, backend, guest sizing, artifact paths, the expensive work the launch performed, and every phase span. Read by the release-only cold-launch benchmark; setting it turns the measurement on without the stderr output. | Unset |
| `MVM_DEV_FLAKE_URL` | Escape hatch for the dev-build's chained `--override-input mvm` target. When set, suppresses the default chained override. (Legacy from the previous iteration's dual-flake layout; today's same-flake-for-both-modes design rarely needs it.) | Unset |
| `MVM_SRC` | Override the source repo path passed to `nix build` during dev builds | Workspace root |
| `MVM_BUILDER_AGENT_BIN` | Override the path to the builder-agent binary baked into the builder VM image | Auto-detected from build closure |
| `MVM_BUILDER_AGENT_PORT` | Vsock port the builder agent listens on | `54_321` |
| `MVM_BUILDER_VM_TIMEOUT_SECS` | Wall-clock cap for one-shot libkrun builder VM runs before the supervisor is killed | `1800` |
| `MVM_TENANT_KEY_<ID>` | Compatibility hook for tenant-scoped key material consumed by shared policy/keystore primitives. Fleet operators should configure tenant keys through `mvmd`. | None |
| `MVM_SKIP_COSIGN_VERIFY` | Set to `1` to bypass cosign signature verification on prebuilt-image downloads and on the runtime-overlay / SDK-sidecar release archives. Documented emergency-rotation escape only; never set in CI or production. | Unset |
| `MVM_SKIP_HASH_VERIFY` | Set to `1` to bypass SHA-256 verification on prebuilt-image downloads. Documented escape hatch only; never set in CI or production. | Unset |
| `MVM_OVERLAY_BASE_URL` | Release base URL the runtime overlay **and** the SDK sidecar are fetched from (both ship in the same release). Point it at a private mirror; `/v<version>` is appended for you. | GitHub Releases |
| `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE` | `build` or `download` — force how a cold cache is populated for the runtime overlay and the SDK sidecar alike, instead of auto-detecting from whether this is a source checkout. | Auto-detect |
