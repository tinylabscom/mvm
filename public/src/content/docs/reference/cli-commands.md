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
`secret`, `bundle`, `deps`, `artifact`) stay top-level.

| Group / top-level | Commands |
|--------|----------|
| Daily drivers (top-level) | `up`, `run`, `invoke`, `ls`, `console`, `down`, `logs`, `dev`, `doctor`, `init` |
| `vm <sub>` | `pause`, `resume`, `snapshot`, `save`, `restore`, `checkpoint`, `cp`, `fs`, `proc`, `diff`, `wait`, `boot-report`, `set-ttl`, `forward`, `sandbox`, `session`, `volume` |
| `build <sub>` | `image` (the former `build`), `compile`, `validate`, `kernel` |
| `ops <sub>` | `metrics`, `bench`, `config`, `mcp` |
| `env <sub>` | `bootstrap`, `cleanup`, `uninstall`, `update`, `sign` |
| `trust <sub>` | `add`/`list`/`remove` (publishers), `attest`, `receipt`, `audit` |
| Already-grouped top-level | `prepare`, `explain`, `image`, `catalog`, `manifest`, `storage`, `network`, `cache`, `pool`, `secret`, `bundle`, `deps`, `artifact` |

**Beginner vs. advanced surfaces.** [`mvmctl machine`](#machine-beginner-ux)
(further down) is the beginner-facing front door — one small command group for
the common "run something in a microVM" cases, and the path the
[getting-started docs](/getting-started/machine-scenarios/) lead with. Every
verb in the grouping above is an **advanced / underlying surface**: `machine`
is a thin UX layer over the *same* signed, audited, OCI-provenance execution
path these verbs use, so the lower-level commands (`up`, `run`, `invoke`,
`vm *`, `build *`, `console`, …) stay fully supported for power users and
scripts. They are **not deprecated and not going away** — reach for them when
you need finer control than `machine` exposes (custom flakes, snapshots,
templates, the guest-RPC surface, fleet-shaped workflows).

| Command | Description |
|---------|-------------|
| `mvmctl up --flake <ref>` | Build and run a VM from a Nix flake |
| `mvmctl up --manifest <path>` | Boot a pre-built manifest (path to `mvm.toml`, its directory, or a legacy slot name; mutually exclusive with `--flake`). Short form: `-m <path>` |
| `mvmctl up --name <name>` | Specify VM name (auto-generated if omitted) |
| `mvmctl up --profile <variant>` | Flake package variant (e.g. worker, gateway) |
| `mvmctl up --cpus N --memory SIZE` | Override vCPU count and memory (supports 512M, 4G, etc.) |
| `mvmctl up -p HOST:GUEST` | Forward a port mapping into the VM (repeatable) |
| `mvmctl up -e KEY=VALUE` | Inject an environment variable (repeatable) |
| `mvmctl up -v host:guest:size` | Mount a volume into the VM (repeatable) |
| `mvmctl up -d` | Run in background (detached mode, via launchd) |
| `mvmctl up --forward` | Auto-forward declared ports after boot (blocks until Ctrl-C) |
| `mvmctl up --hypervisor <backend>` | Backend: `firecracker` (default), `apple-container`, `docker`, or `qemu` |
| `mvmctl up --config <path>` | Runtime config (TOML) for persistent resources/volumes |
| `mvmctl up --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl up --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl up --watch` | Watch flake for changes and auto-rebuild + reboot |
| `mvmctl up --network-preset <preset>` | Network egress policy: `unrestricted` (default), `none`, `registries`, `dev`, `agent` (LLM-inference + GitHub bundle — see [ADR-004](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/004-hypervisor-egress-policy.md)) |
| `mvmctl up --network-allow host:port` | Allow egress to specific host:port (repeatable, mutually exclusive with preset) |
| `mvmctl up --seccomp <tier>` | Seccomp profile: `essential`, `minimal`, `standard` (default), `network`, `unrestricted`. The selected tier is enforced through the guest `seccomp.json` manifest and recorded in the signed admission profile for audit. |
| `mvmctl up --network <name>` | Named dev network to attach VM to (default: "default") |
| `mvmctl machine stop [name]` | Stop VMs by name, or all if omitted |
| `mvmctl ls` | List running VMs (aliases: `ps`, `status`) |
| `mvmctl ls -a` | Show all VMs including stopped |
| `mvmctl ls --json` | Output as JSON |
| `mvmctl machine forward <name> -p PORT` | Forward a port from a running VM to localhost |
| `mvmctl machine logs <name>` | View guest console logs (`-f` to follow, `-n` for line count) |
| `mvmctl machine logs <name> --hypervisor` | View Firecracker hypervisor logs |
| `mvmctl machine diff <name>` | Show filesystem changes in a running VM (created/modified/deleted since boot) |
| `mvmctl machine diff <name> --json` | Output filesystem diff as JSON |
| `mvmctl machine wait <name> --for <component>` | Block until a guest readiness component is `Ready`, `Disabled`, or `Failed`. Targets: `control-plane`, `entrypoint`, `warm-pool`, `integrations`, `probes`, `all` (default). Exit codes: `0` ready, `65` (`EX_DATAERR`) failed, `75` (`EX_TEMPFAIL`) timeout. Plan 76 Phase 2. |
| `mvmctl machine wait <name> --timeout <secs> --interval-ms <ms>` | Tune the deadline and poll cadence. Defaults: 60s / 250ms. |
| `mvmctl machine boot-report <name>` | Print a single readiness snapshot + per-phase boot timings. Plan 76 Phase 4. |
| `mvmctl machine boot-report <name> --json` | Same payload as JSON. |

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Prepare the environment: host tooling, pre-fetch the builder VM image, and optionally preload attested runtime/builder packs when `MVM_BOOTSTRAP_*` pack policy variables are set. `install.sh` runs this automatically unless `MVM_SKIP_BUILDER_PREFETCH=1`. Idempotent — safe to re-run |
| `mvmctl bootstrap --production` | Production mode (skip Homebrew, assume Linux with apt) |
| `mvmctl env bootstrap` | Same as `mvmctl bootstrap` (the `env`-grouped form) |
| `mvmctl dev [up]` | Auto-bootstrap if needed, start dev VM, drop into shell. On macOS, the dev-image builder auto-detects Vz on macOS 26+ Apple Silicon and retries with libkrun when that auto-selected Vz builder path fails; native KVM is used on Linux. |
| `mvmctl dev [up]` | Auto-bootstrap if needed, start dev VM, drop into shell. On macOS, the dev-image builder auto-detects Vz on macOS 26+ Apple Silicon and retries with libkrun when that auto-selected Vz builder path fails; native KVM is used on Linux. |
| `mvmctl dev up --project ~/dir` | Auto-bootstrap then cd into a project directory |
| `mvmctl dev up --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl dev up --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl dev up --shell` (or `-s`) | Force opening an interactive shell after starting (the default behavior) |
| `mvmctl dev up --no-shell` | Start the dev VM without attaching an interactive shell |
| `mvmctl dev up --base <template[@revision]\|slot[@revision]\|bundle-sha>` | On the Vz backend, boot the dev VM from a built template/manifest-slot revision or installed bundle instead of the default dev image. Unknown or unbuilt bases fail before launch; changing the base of an already-running or parked dev VM requires `mvmctl dev down` first. |
| `mvmctl dev down` | Stop the dev VM |
| `mvmctl dev down --reset` | Also delete the cached dev image so the next `dev up` rebuilds from local source |
| `mvmctl dev park` | Vz only: snapshot and stop the running dev VM so the next `dev up` restores from the parked state |
| `mvmctl dev shell` | Open a shell in the running dev VM |
| `mvmctl dev shell --project ~/dir` | Open shell and cd into a project directory |
| `mvmctl dev status` | Show dev environment backend, running state, cached image paths, and safe builder-cache readiness reason |
| `mvmctl dev status --json` | Emit schema-versioned dev status JSON; Vz pinned-base dev VMs include a `base` object with `id`, `revision`, and `rootfs_fingerprint`, while Linux-native hosts include typed KVM, Firecracker, and base-asset readiness labels |
| `mvmctl dev cache inspect` | Inspect dev image and builder-cache readiness without rebuilding, booting, or printing local artifact paths |
| `mvmctl dev cache inspect --json` | Emit the sanitized dev-cache inspection as structured JSON |
| `mvmctl dev rebuild` | Stop, clear cache, and rebuild + restart the dev VM |
| `mvmctl dev rebuild --shell` (or `-s`) | Open an interactive shell after rebuilding |
| `mvmctl dev import-image <path>` | Side-load a pre-built dev image artifact into the cache (air-gapped install path; from plan 36 sealed builder image) |
| `mvmctl doctor` | Run diagnostics + dependency checks + security posture, including per-tenant host-agent daemon state (folded in from the dropped `mvmctl security` verb) |
| `mvmctl doctor --json` | Output diagnostics as JSON |
| `mvmctl env update` | Check for and install mvmctl updates |
| `mvmctl env update --check` | Only check for updates, don't install |
| `mvmctl env update --force` | Force reinstall even if already up to date |
| `mvmctl env update --skip-verify` | Skip cosign signature verification |

## Building

| Command | Description |
|---------|-------------|
| `mvmctl build image <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build image --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build image --flake <ref> --profile <variant>` | Build a specific flake package variant |
| `mvmctl build image --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl build image --json` | Output structured JSON events instead of human-readable output |
| `mvmctl build image -o <path>` | Output path for the built .elf image |
| `mvmctl env cleanup` | Remove old dev-build artifacts and run Nix garbage collection |
| `mvmctl env cleanup --all` | Remove all cached build revisions |
| `mvmctl env cleanup --keep <N>` | Keep the N newest build revisions |
| `mvmctl env cleanup --verbose` | Print each cached build path that gets removed |

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
| `mvmctl build image [PATH] --snapshot` | After build, boot, wait for healthy, and capture a Firecracker snapshot (Firecracker backend only) |
| `mvmctl build image [PATH] --update-hash` | Recompute the Nix fixed-output derivation hash |
| `mvmctl build image [PATH] --vcpus N --mem SIZE --data-disk SIZE` | CLI overrides for resource sizing; persisted to the slot record |
| `mvmctl build image [PATH] --json` | Stream structured build events |

### Running (top-level — already manifest-aware)

`mvmctl up [PATH]` and `mvmctl run [PATH] -- <cmd>` accept a manifest path or its directory and look up the manifest-keyed slot. If no current revision exists, they error with a hint to run `mvmctl build image`. See the [VM Lifecycle](#vm-lifecycle) and [One-shot Exec](#one-shot-run-transient-runner) sections for full flag lists. (Plan 40 dropped the `start` and `run` aliases on `up`.)

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

## Benchmarks

Bench commands are measurement tools. They do not bypass admission: live
microVM runs synthesize and admit signed plans the same way the normal launch
path does. The libkrun live path requires a binary built with
`--features libkrun-live` on a host where libkrun can boot guests; stock builds
fail honestly instead of emitting fake numbers.

| Command | Description |
|---------|-------------|
| `mvmctl ops bench microvm-launch` | Measure serial cold runtime-microVM launch latency for the canonical default runtime image. Defaults: `--runs 20 --warmup 2 --hypervisor libkrun`. |
| `mvmctl ops bench microvm-launch --concurrency N --warmup 0` | Launch `N` admitted probe VMs as one concurrent wave and report P50/P95/P99 launch latency. Use `--max-concurrency` as a safety cap (default 64). `--baseline` is serial-only. |
| `mvmctl ops bench microvm-launch --out <path> --json` | Write the versioned JSON report to `<path>` and also print it to stdout. Without `--out`, reports are written under `<MVM_DATA_DIR>/bench/`. |
| `mvmctl ops bench microvm-launch --baseline <path> --max-regression-pct <pct>` | Compare serial median `total_ready_ms` against a comparable baseline and fail if it regresses beyond the threshold. |
| `mvmctl ops bench microvm-density --count K --max-count M` | Boot and hold `K` admitted libkrun probe VMs, sample each supervisor/VMM process footprint, and report total plus per-instance bytes. `--max-count` is a safety cap (default 16). |
| `mvmctl ops bench microvm-density --out <path> --json` | Write the density JSON report and optionally print it to stdout. Linux samples PSS from `/proc/<pid>/smaps_rollup`; macOS samples `phys_footprint` through `proc_pid_rusage`. |

## Audit

| Command | Description |
|---------|-------------|
| `mvmctl trust audit tail` | Show the last 20 audit events from /var/log/mvm/audit.jsonl |
| `mvmctl trust audit tail -n <N>` | Show the last N audit events |
| `mvmctl trust audit tail -f` | Follow audit log output (poll until Ctrl-C) |

## Local Secrets

| Command | Description |
|---------|-------------|
| `mvmctl secret put <name>` | Store or replace a local secret using hidden interactive input when stdin is a terminal, or piped stdin otherwise |
| `mvmctl secret put <name> --value -` | Store or replace a local secret from stdin |
| `mvmctl secret put <name> --value-file <path>` | Store or replace a local secret from a file |
| `mvmctl secret put <name> --value <value>` | Store or replace a local secret from an inline value. Avoid in interactive shells because the value may be saved in shell history |
| `mvmctl secret get <name>` | Verify that a local secret exists without printing the value |
| `mvmctl secret ls` | List stored secret names only |
| `mvmctl secret rm <name>` | Remove a local secret |
| `mvmctl secret <put|get|ls|rm> --tenant <tenant>` | Use a non-default local tenant namespace. Default: `local` |

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

`mvmctl up` still synthesizes and admits signed execution plans with policy
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

## Networks

| Command | Description |
|---------|-------------|
| `mvmctl network create <name>` | Create a named dev network with its own bridge and subnet |
| `mvmctl network list` | List all dev networks (alias: `ls`) |
| `mvmctl network inspect <name>` | Show details of a named network (JSON) |
| `mvmctl network remove <name>` | Remove a named network (alias: `rm`) |

## Image Catalog

`mvmctl catalog *` is the metadata-only browser for bundled application entries. `mvmctl image *` is reserved for the local OCI image cache under `~/.cache/mvm/oci/`.

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

Production OCI policy reads `MVM_OCI_POLICY` when set, otherwise
`$MVM_DATA_DIR/oci-policy.toml`. The policy allow-lists registries and trusted
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
| `mvmctl machine console <name>` | Interactive PTY shell into a running VM (vsock, no SSH) |
| `mvmctl machine console <name> --command <cmd>` | Run a one-shot command in the VM |

## One-shot Run (transient runner)

`mvmctl run` is the one-shot sandbox UX: it boots a fresh transient microVM,
runs one command, and tears the VM down on exit — like `docker run --rm` but
with a Firecracker microVM as the sandbox. Plan 178 merged the former bare
`mvmctl exec` into `run` (it was already a strict superset); `run` adds a
security `--profile`, OCI `--image`, signed `--receipt`, `--json`/`--dry-run`,
and the SDK `--mode`/`--dev`/`--prod` transport. Arbitrary command dispatch
requires a dev-feature guest agent (the `do_exec` handler is `dev-shell`-gated,
claim 4); production guests should use `mvmctl invoke` (no shell).

| Command | Description |
|---------|-------------|
| `mvmctl run -- <cmd>...` | Boot the bundled default microVM image, run `<cmd>`, exit |
| `mvmctl run --manifest <name-or-path> -- <cmd>...` | Boot a registered manifest/template instead of the default |
| `mvmctl run --image <ref> -- <cmd>...` | Pull or reuse a cached OCI image, emit signed audit-chain provenance for the resolved image, boot its materialized `rootfs.ext4`, run `<cmd>`, exit |
| `mvmctl run --image <ref> --prod -- <cmd>...` | Production OCI-image policy: require `<ref>` to be digest-pinned and cosign-verified by the OCI policy before cache use or boot |
| `mvmctl run --profile standard -- <cmd>` | Default profile: explicit env is allowed; host shares must be read-only |
| `mvmctl run --profile restrictive -- <cmd>` | No env injection and no host directory shares |
| `mvmctl run --profile dev --add-dir .:/work:rw -- <cmd>` | Dev profile: permits writable host shares for local iteration |
| `mvmctl run --profile permissive -- <cmd>` | Escape hatch; requires `MVM_ACK_PERMISSIVE_RUN=1` |
| `mvmctl run --add-dir HOST:GUEST[:MODE] -- <cmd>` | Mount a host directory. `MODE` defaults to `ro`; `rw` requires `--profile dev` or `permissive` |
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

## Machine (beginner UX)

`mvmctl machine` is the beginner-facing command group. It is a thin UX layer
over the existing runtime verbs and state helpers, not a parallel runtime.
Booting machine commands use the same signed-`ExecutionPlan`, audited,
OCI-provenance execution path as the lower-level commands; non-booting state
commands persist declarative specs under `MVM_DATA_DIR`.

The flagship verb is `machine run`, which selects one of three lifecycles by
flag:

- **Transient** (default): boot a fresh microVM from an OCI image, run the
  command, tear the VM down. Routes into the same code path as
  `mvmctl run --image`, inheriting **deny-all networking by default**, opt-in
  egress via `--net` / `--allow-host`, and the same `--profile`, `--volume`,
  `--receipt`, `--json`, and `--dry-run` semantics.
- **Persistent** (`--name <N>` or `-d`/`--detach`): boot a machine that survives
  the command and is reconnectable by name through `machine shell`/`exec`/`stop`.
  `--name` gives it a name; bare `-d` auto-generates one and prints it. With a
  command, the command is run (streamed) and the machine is left up; without one,
  the machine just boots.
- **Interactive** (`-t`/`--tty`, with `-i` accepted so `-it` parses): attach a
  PTY shell. **Dev-only** — refused for a sealed image (claim 15) and when stdin
  is not a terminal. `-t` alone is a transient interactive machine (gone when the
  shell exits); combine with `--name`/`-d` to keep it up.

Persistence and interactivity are independent: `--tty` never changes whether the
machine survives. `--volume` host shares work on every mode — transient,
persistent, and interactive. The syntax is `HOST:/GUEST[:MODE]` (`MODE` defaults
to `ro`; `rw` needs `--profile dev` or `permissive`). On a persistent (`-d`/
`--name`) or interactive (`-t`) machine the host path is canonicalized to an
absolute path and stored in the machine spec, so a later reconnect re-mounts the
same share regardless of your working directory; the host directory must exist at
boot.

SSH sessions are banned in microVMs. `--allow-host <host:22>` is refused, and
the runtime also denies TCP/22 even under broad egress. Dev-tier `ssh_agent`
means only Unix-socket forwarding of the host `SSH_AUTH_SOCK`; it never copies
or mounts private keys, `~/.ssh`, known-hosts material, or SSH config.

| Command | Description |
|---------|-------------|
| `mvmctl machine run --image <ref> -- <cmd>...` | Boot an OCI image, run `<cmd>` with no network, tear down |
| `mvmctl machine run --net --image <ref> -- <cmd>...` | Boot with dev-tier outbound networking enabled |
| `mvmctl machine run --image <ref> --allow-host <host[:port]> -- <cmd>...` | Boot with egress narrowed to the listed host/port entries |
| `mvmctl machine run --image <ref> --profile dev --volume .:/work:rw -- <cmd>` | Same, with a writable host share under the dev profile |
| `mvmctl machine run --image <ref> --cpus <n> --memory <size> -- <cmd>` | Resize the transient VM |
| `mvmctl machine run --image <ref> --dry-run -- <cmd>` | Validate and explain the run plan without booting a VM |
| `mvmctl machine run --image <ref> --json -- <cmd>` | Print a redacted JSON execution summary |
| `mvmctl machine run --image <ref> --receipt <path> -- <cmd>` | Write a signed execution receipt |
| `mvmctl machine run -d --image <ref>` | Boot a **persistent** machine, auto-name it (printed), return |
| `mvmctl machine run --name <name> --image <ref>` | Boot a persistent named machine, return; reconnect via `machine shell <name>` |
| `mvmctl machine run --name <name> --image <ref> -- <cmd>` | Boot a persistent named machine, run `<cmd>` (streamed), leave it up |
| `mvmctl machine run --name <name>` | Reconnect to an existing machine by name (no `--image` needed) |
| `mvmctl machine run --name <name> --image <ref2>` | A changed config auto-recreates the machine (stop + reboot), announced on stderr |
| `mvmctl machine run -it --image <ref>` | **Interactive** dev shell on a transient machine (gone on exit) |
| `mvmctl machine run -it --name <name> --image <ref>` | Interactive dev shell on a persistent machine (left up on exit) |
| `mvmctl machine create --name <name> --image <ref>` | Persist a named OCI-backed machine spec without booting it |
| `mvmctl machine create --name <name> --manifest <path>` | Persist a named machine spec from an image-backed `mvm.toml` / `Mvmfile.toml` |
| `mvmctl machine create --name <name> --image <ref> --net --allow-host <host[:port]>` | Persist a named spec with opt-in egress settings for future lifecycle starts |
| `mvmctl machine create --name <name> --manifest <path>` | Persist an image-backed `mvm.toml` / `Mvmfile.toml` as a named machine spec |
| `mvmctl machine create --name <name> --image <ref> --force` | Overwrite an existing named machine spec |
| `mvmctl machine start --name <name>` | Boot a persisted named machine through the admitted OCI-backed start path |
| `mvmctl machine start --name <name> --dry-run` | Validate and explain the effective machine-start policy without booting a VM |
| `mvmctl machine start --name <name> --dry-run --json` | Print the machine-start preflight summary as redacted JSON |
| `mvmctl machine start --name <name> --json` | Print a redacted JSON start summary instead of plain text |
| `mvmctl machine start --name <name> --receipt <path>` | Write a signed machine-start receipt with effective policy plus the resolved digest and start timestamp |
| `mvmctl machine ls` | List persisted named machine specs |
| `mvmctl machine ls --json` | Print persisted named machine specs as JSON |
| `mvmctl machine inspect <name>` | Show one persisted named machine spec |
| `mvmctl machine inspect <name> --json` | Print one persisted named machine spec as JSON |
| `mvmctl machine rm <name> --yes` | Remove one persisted named machine spec |
| `mvmctl machine rm <name> --yes --json` | Print a JSON deletion summary |
| `mvmctl machine exec --name <name> -- <cmd>...` | Run a command in an already-started named machine |
| `mvmctl machine shell --name <name>` | Attach an interactive shell/console to an already-started named machine |
| `mvmctl machine stop --name <name>` | Stop an already-started named machine |
| `mvmctl machine check-artifact <artifact.mvm>` | Verify a portable artifact and preview its admission posture without extracting or booting |
| `mvmctl machine check-artifact <artifact.mvm> --key <pubkey>` | Verify with an explicit raw Ed25519 public key |
| `mvmctl machine check-artifact <artifact.mvm> --json` | Print the verified artifact/admission preview as JSON |

`machine run --dry-run` also prints an attested-preparation diagnostic on
stderr when the current source cannot use the instant-launch path. The reason
codes match `mvmctl prepare`: mutable OCI tags report `mutable_input`,
digest-pinned OCI or manifest sources without a selected verified pack report
`missing_pack`, local flakes report `private_input`, and remote flakes report
`local_rebuild_required`.

### `machine run` lifecycles in practice

A transient run is the default and needs no flags — it boots, runs the command,
and tears the VM down:

```bash
mvmctl machine run --image alpine -- echo hi      # prints "hi", VM gone
```

A bare `machine run --image alpine -- /bin/sh` is **non-interactive**: it streams
the command's output but forwards no stdin, so an interactive shell sees EOF and
exits at once. For a live shell, add `-it` (dev-only — see below):

```bash
mvmctl machine run -it --image <dev-image> -- /bin/sh   # live shell, VM gone on exit
```

Naming or detaching is the *only* thing that keeps a machine alive past the
command — that is the whole difference between a transient and a persistent run:

```bash
mvmctl machine run -d --image alpine          # boots, prints e.g. "blue-fox-3f2a", returns
mvmctl machine shell --name blue-fox-3f2a     # reconnect (dev PTY)
mvmctl machine exec  --name blue-fox-3f2a -- ps   # one-shot command in the running machine
mvmctl machine stop  --name blue-fox-3f2a     # tear it down when done
```

`--name <N>` does the same with a name you choose; `machine run --name <N>` with
no `--image` reconnects to an existing machine.

**Config change auto-recreates.** A matching config reconnects to the existing
machine. A *different* config (image, CPU, memory, profile, volumes, …)
**recreates** it — `machine run` stops the old instance, overwrites the spec, and
reboots, converging like `compose up` (the machine is cattle; durable data
belongs in `--volume` host shares, which survive the recreate). The recreate is
announced on stderr (`machine 'N': config changed (…) — stopping the old instance
and recreating it`) so an unintended clobber, e.g. a typo'd `--image`, is visible.
To keep two configs side by side, give them different `--name`s.

**Interactive is dev-only.** `-t`/`--tty` attaches a PTY shell and is refused for
a sealed/production image (claim 15 — no interactive access to a sealed microVM)
and when stdin is not a terminal, both failing fast rather than hanging. It never
affects persistence: `-it` alone is transient, `-it` with `--name`/`-d` keeps the
machine. The design rationale and full behavior matrix are recorded in ADR-091
(`specs/adrs/091-unified-machine-run-lifecycle.md`).

`machine create` accepts either `--image <ref>` or an image-backed manifest, not
both. When `--image` is omitted, it searches the current directory for
`mvm.toml` / `Mvmfile.toml`; `--manifest <path>` selects a file explicitly. The
persisted spec carries the manifest's image, CPU/memory sizing, `mem_initial`,
network defaults, allow-hosts, and volumes. Relative manifest volume host paths
are resolved relative to the manifest file; volume validation keeps the shared
default of read-only mounts unless `:rw` is explicit.

`machine start`, `machine exec`, `machine shell`, and `machine stop` require the
named `MachineSpec` to exist first. `machine start` resolves the stored OCI
image through the normal cache/materialization path, emits the same admission
and OCI provenance audit substrate as the transient image runner, then boots
the named VM with any persisted `mem_initial` and volume settings. When the
named spec came from an image-backed manifest, `machine create --manifest`
persists the manifest's `net`, `[network].allow_hosts`, `cpus`, `mem`,
`mem_initial`, `[dev].volumes`, and `[dev].init` fields into the durable
machine spec; relative manifest volume paths are resolved against the manifest
directory when persisted. `dev.init` and `ssh_agent = true` currently require
`--profile dev` or `--profile permissive`; standard/prod-like profiles refuse
them. `machine start --dry-run` reports the
effective network posture, enforcement tier, auth mode, dev-init hash/count,
and redacted volume policy without resolving or booting the image; the signed
machine-start receipt carries the same policy summary plus the resolved digest
and start timestamp after a real boot. `exec` / `shell` / `stop` reuse the
existing console/down paths for the running VM. `machine pack` for portable
signed artifacts and live `machine run <artifact.mvm>` are still follow-up work.
`machine check-artifact` is the current read-only portable-artifact gate: it
verifies the signed manifest, file hashes, format version, sealed-prod verity
requirements, host architecture, and fail-closed admission posture before
printing a preview. Use `mvmctl up` for the manifest/flake path that already
exposes named networks and policy bundles.

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

`mvmctl machine save` / `mvmctl machine restore` are the first-class Vz machine-state verbs. They are thin aliases over the `vm-full` checkpoint path: save captures memory + disk through Vz `saveMachineStateToURL`, restore verifies the sealed checkpoint content and resumes the same VM identity. `mvmctl machine checkpoint` remains the advanced checkpoint store surface for list/remove/fork/diff and explicit class selection. `mvmctl machine snapshot ls` / `mvmctl machine snapshot rm` remain for Firecracker sealed snapshots.

| Command | Description |
|---------|-------------|
| `mvmctl machine save <name> [--tag <tag>] [--json]` | Save a running Vz VM as a `vm_full` checkpoint. Refuses when the active host/backend does not report the `save-restore` snapshot tier. |
| `mvmctl machine restore <checkpoint> [--json]` | Restore a previously saved `vm_full` checkpoint into the original VM identity after content verification. Refuses when the active host/backend does not report the `save-restore` snapshot tier. |
| `mvmctl machine checkpoint create <name> [--class fs-quick\|vm-full] [--tag <tag>] [--json]` | Capture a checkpoint. `--class vm-full` saves full machine state (memory + disk) via Vz's `saveMachineStateToURL`. Records content hash in the audit chain. |
| `mvmctl machine checkpoint restore <checkpoint> [--json]` | Restore a previously created `vm_full` checkpoint into the original VM identity. Re-hashes content against the recorded metadata before loading. |
| `mvmctl machine checkpoint fork <checkpoint> [--new-id <name>] [--boot] [--json]` | Restore a checkpoint into a new VM identity (new name, separate audit lineage). `vm_full` forks auto-boot; `fs_quick` forks boot only with `--boot`. |
| `mvmctl machine checkpoint ls [--json]` | List checkpoints. |
| `mvmctl machine checkpoint diff <a> <b> [--json]` | Compare two checkpoint metadata/content manifests. |
| `mvmctl machine checkpoint rm <checkpoint> [--json]` | Delete a checkpoint and its blobs. |
| `mvmctl machine snapshot ls [--json]` | List sealed Firecracker instance snapshots. |
| `mvmctl machine snapshot rm <name> [--json]` | Delete a sealed Firecracker instance snapshot. |

Checkpoint blobs are stored under the configured checkpoint store (`MVM_DATA_DIR` / `~/.mvm` via the core path helpers). The audit chain records `checkpoint.created`, `checkpoint.restored`, and `checkpoint.forked` entries with content hashes; restore and fork refuse tampered checkpoint content before booting.

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
mvmctl run --add-dir .:/work -- ls /work              # share current dir, RO
mvmctl run --add-dir .:/work:rw -- touch /work/x      # writable, rsynced back
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
that template has a captured snapshot, `mvmctl run` restores from the
snapshot instead of cold-booting — typically sub-second on Linux/KVM.

The snapshot path activates only when *all* of the following hold:

- the image source is a **registered template** (the bundled default
  image has no template snapshot to restore from);
- there are **no** `--add-dir` extras (extra drives would mismatch the
  snapshot's recorded drive layout);
- the active backend reports snapshot support.

On macOS backends without Firecracker (Apple Container, libkrun), vsock
snapshots return `os error 95` (EOPNOTSUPP); restore failures fall back
to cold boot with a warning rather than aborting the exec. See the
[Sandboxed Exec](/guides/exec/) guide for the full background.

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
- `mvmctl up` — boots a long-running microVM with the same image

The image is the bundled default — a minimal `mkGuest` rootfs shipped
with mvm. Built via Nix on first use, cached at
`~/.cache/mvm/default-microvm/` (kernel + rootfs). To customize, pass
`--manifest` or `--flake` pointing at your own project's `mkGuest`
output (see [Building MicroVM Images](/guides/building-microvm-images)).

Build resolution order on first use:

1. **Builder VM.** mvm bootstraps or reuses the project Linux builder VM,
   runs Nix evaluation and `nix build` inside it, and extracts the rootfs.
   No host-side Nix is required, and you do not need to enter
   `mvmctl dev shell` first.
2. **Prebuilt artifacts (offline).** If the host is fully offline and the
   builder image is not available, mvm can use the prebuilt
   `default-microvm` artifacts from the GitHub release matching the
   `mvmctl` version, hash-verified per the `*-checksums-sha256.txt`
   manifest (security claim 6).

See [Builder VM](/guides/builder-vm/) for the host-orchestrated build
flow and the distinction between build time and runtime boot time.

## Prepare

| Command | Description |
|---------|-------------|
| `mvmctl prepare <IMAGE_OR_FLAKE> --policy-hash <SHA256> --backend <firecracker\|libkrun\|vz\|qemu\|docker> --channel <CHANNEL>` | Resolve the attested pack preparation state for an OCI image, flake, or local project path. The resolver verifies matching cached packs against local policy, trust-store keys, revocation metadata, manifest/file hashes, signature expiry, architecture, backend, and channel compatibility |
| `mvmctl prepare <IMAGE_OR_FLAKE> --policy-mode <online-default\|offline-pinned\|mirror-only\|local-rebuild-required> ...` | Select pack policy mode. `offline-pinned` requires `--channel-signing-key CHANNEL=KEY_ID`; `mirror-only` also checks manifest mirror identity through `--mirror-identity <MIRROR>`; `local-rebuild-required` reports builder preparation instead of fast-path eligibility |
| `mvmctl prepare --dry-run <IMAGE_OR_FLAKE> ...` | Report fast-path eligibility without downloading or installing packs. Output includes pack state, refusal reason, cached size when known, trust state, setup-cache state, download requirement, and builder-VM requirement. A verified pack with a required setup-cache miss reports `setup_cache_miss` and requires builder preparation |
| `mvmctl prepare <IMAGE_OR_FLAKE> ...` | Human output includes the stable preparation reason code and a next-step hint when the resolver returns a refusal, cache miss, or builder-VM preparation requirement |
| `mvmctl prepare <OCI_IMAGE> --resolve-oci-digest ...` | Resolve a mutable OCI tag to a Linux platform digest before checking pack eligibility. Without this explicit flag, mutable OCI inputs remain fail-closed and report `mutable_input` |
| `mvmctl prepare <FLAKE> --resolve-flake-lock ...` | Hash a local `flake.lock` before checking pack eligibility, so cached packs must match both the resolved flake reference and lock hash. Remote flake lock resolution is refused until the builder-VM resolver path is wired through |
| `mvmctl prepare <IMAGE_OR_FLAKE> --pack-source <SOURCE> ...` | Install a local or HTTPS attested pack archive through the same quarantine/verification/cache promotion path as `cache install-pack`, then resolve whether it satisfies the requested input. Plain HTTP requires `--allow-http` |
| `mvmctl prepare <IMAGE_OR_FLAKE> --input-kind <oci-image\|flake\|local-path> --pack-kind <runtime\|builder\|image-project> ...` | Override input-kind inference or expected pack kind. `--pack-hash <SHA256>`, repeated `--host-capability`, repeated `--channel-signing-key`, `--mirror-identity <MIRROR>`, `--trust-store <DIR>`, `--revocations <FILE>`, and `--json` are also supported |
| `mvmctl explain <RUN_ID>` | Verify the local hash-chained launch-attestation log, find the requested run id, and print the launch source, pack hashes, policy decision, derivation source, backend identity, command digest, result, and log-chain metadata |
| `mvmctl explain <RUN_ID> --json` | Emit the verified attestation record plus sequence, previous-hash, entry-hash, and log-head metadata as machine-readable JSON |

## Cache

| Command | Description |
|---------|-------------|
| `mvmctl cache info` | Show cache directory path, disk usage, and a per-entry footprint breakdown (unrecognized entries are flagged) |
| `mvmctl cache status` | Show local attested pack cache inventory, metadata readiness, expiry, revocation-check status, and instant-launch eligibility state |
| `mvmctl cache status --json` | Emit the attested pack cache inventory as machine-readable JSON |
| `mvmctl cache install-pack <SOURCE> --policy-hash <SHA256> --backend <firecracker\|libkrun\|vz\|qemu\|docker> --channel <CHANNEL>` | Read a local or HTTPS attested pack tar archive, verify manifest hashes/signatures/trust metadata/revocation policy, and atomically install it into the pack cache. Repeat `--channel` and `--host-capability` as needed; use `--policy-mode`, repeated `--channel-signing-key CHANNEL=KEY_ID`, `--mirror-identity <MIRROR>`, `--trust-store <DIR>`, or `--revocations <FILE>` for local policy inputs. Plain HTTP requires `--allow-http` |
| `mvmctl cache prune` | Remove stale temp files and expired/invalid attested pack entries; pack deletion refuses snapshot or warm-standby protection references; report (but don't delete) unrecognized top-level cache dirs |
| `mvmctl cache prune --dry-run` | Show what would be removed without deleting |
| `mvmctl cache prune --orphan-builds` | Also sweep orphaned builds — built artifacts whose source `mvm.toml` is gone (equivalent to `mvmctl manifest prune --orphans`) |
| `mvmctl cache prune --orphan-dirs` | Also remove unrecognized top-level cache dirs (leftovers from a removed subsystem) |
| `mvmctl cache prune --deep` | Reclaim regenerable caches too — Stage 0 blobs, the prebuilt default microVM image, pulled OCI layers (each costs a re-fetch/rebuild next time). Implies `--orphan-dirs` |
| `mvmctl cache repair` | Clear a degraded builder VM store so the next `dev up`/`build` cold-rebuilds it. Refuses while a Stage 0 bootstrap is in flight; auto-stops a running dev builder first |
| `mvmctl cache repair --force` | Clear the store even while a Stage 0 bootstrap lock is held (use only if the lock is stale, e.g. after a crash) |

## Security

> Plan 40 dropped the standalone `mvmctl security status` verb. Posture checks now live inside `mvmctl doctor`.

## Utilities

| Command | Description |
|---------|-------------|
| `mvmctl shell-init` | Print shell configuration (completions + dev aliases) to stdout |
| `mvmctl shell-init --emit-completions <shell>` | Emit just the shell-completion script (replaces the dropped `mvmctl completions <shell>`) |
| `mvmctl ops metrics` | Show runtime metrics (Prometheus text format) |
| `mvmctl ops metrics --json` | Show runtime metrics as JSON |
| `mvmctl env uninstall` | Remove Firecracker, the builder microVM image, and all mvm state (confirmation required) |
| `mvmctl env uninstall -y` | Uninstall without confirmation |
| `mvmctl env uninstall --all` | Also remove ~/.mvm/ config dir and /usr/local/bin/mvmctl binary |
| `mvmctl env uninstall --dry-run` | Print what would be removed without removing |

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
| `MVM_DATA_DIR` | Root data directory for templates and builds | `~/.mvm` |
| `MVM_FC_VERSION` | Firecracker version (auto-normalized to `vMAJOR.MINOR`) | Latest stable |
| `MVM_FC_ASSET_BASE` | S3 base URL for Firecracker assets | AWS default |
| `MVM_FC_ASSET_ROOTFS` | Override rootfs filename | Auto-detected |
| `MVM_FC_ASSET_KERNEL` | Override kernel filename | Auto-detected |
| `MVM_BUILDER_MODE` | Builder transport: `auto`, `vsock`, or `ssh` | `auto` |
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
| `MVM_OCI_POLICY` | OCI production policy TOML used by `mvmctl image pull --prod` and `mvmctl run --image --prod` | `$MVM_DATA_DIR/oci-policy.toml` |
| `MVM_OCI_BEARER_TOKEN_<HOST>` | Bearer token for one OCI registry host (`ghcr.io` -> `MVM_OCI_BEARER_TOKEN_GHCR_IO`) | Unset |
| `MVM_OCI_BEARER_TOKEN` | Global fallback bearer token for OCI registry pulls | Unset |
| `RUST_LOG` | Logging level (e.g., `debug`, `mvm=trace`) | `info` |
| `MVM_CACHE_DIR` | Override cache directory | `~/.cache/mvm` |
| `MVM_CONFIG_DIR` | Override config directory | XDG default |
| `MVM_STATE_DIR` | Override state directory | XDG default |
| `MVM_SHARE_DIR` | Override share directory | XDG default |
| `MVM_DEV_FLAKE_URL` | Escape hatch for the dev-build's chained `--override-input mvm` target. When set, suppresses the default chained override. (Legacy from the previous iteration's dual-flake layout; today's same-flake-for-both-modes design rarely needs it.) | Unset |
| `MVM_SRC` | Override the source repo path passed to `nix build` during dev builds | Workspace root |
| `MVM_BUILDER_AGENT_BIN` | Override the path to the builder-agent binary baked into the builder VM image | Auto-detected from build closure |
| `MVM_BUILDER_AGENT_PORT` | Vsock port the builder agent listens on | `54_321` |
| `MVM_BUILDER_AUTHORIZED_KEY` | SSH public key authorized to drive the builder VM via SSH transport (vs vsock) | Unset |
| `MVM_BUILDER_VM_TIMEOUT_SECS` | Wall-clock cap for one-shot libkrun builder VM runs before the supervisor is killed | `1800` |
| `MVM_MCP_SESSION_IDLE` | MCP session idle timeout in seconds | `300` |
| `MVM_MCP_SESSION_MAX` | MCP session maximum lifetime in seconds | `1800` |
| `MVM_MCP_MAX_INFLIGHT` | Max concurrent in-flight `tools/call run` invocations | `8` |
| `MVM_MCP_MEM_CEILING_MIB` | Per-call memory ceiling enforced before dispatching to a microVM | `8192` |
| `MVM_TENANT_KEY_<ID>` | Compatibility hook for tenant-scoped key material consumed by shared policy/keystore primitives. Fleet operators should configure tenant keys through `mvmd`. | None |
| `MVM_SKIP_COSIGN_VERIFY` | Set to `1` to bypass cosign signature verification on prebuilt-image downloads. Documented escape hatch only; never set in CI or production. | Unset |
| `MVM_SKIP_HASH_VERIFY` | Set to `1` to bypass SHA-256 verification on prebuilt-image downloads. Documented escape hatch only; never set in CI or production. | Unset |
| `MVM_SKIP_PACK_PREFETCH` | Set to `1` to skip bootstrap pack preloading even when `MVM_BOOTSTRAP_*` pack sources are set. | Unset |
| `MVM_BOOTSTRAP_RUNTIME_PACK_SOURCE` | Local path or HTTPS URL for a runtime pack archive to install during `mvmctl bootstrap`. Requires pack policy variables below. | Unset |
| `MVM_BOOTSTRAP_BUILDER_PACK_SOURCE` | Local path or HTTPS URL for a builder pack archive to install during `mvmctl bootstrap`. Requires pack policy variables below. | Unset |
| `MVM_BOOTSTRAP_PACK_POLICY_HASH` | Local policy hash required when a bootstrap pack source is set. | None |
| `MVM_BOOTSTRAP_PACK_BACKEND` | Backend policy for bootstrap pack verification: `firecracker`, `libkrun`, `vz`, `qemu`, or `docker`. | None |
| `MVM_BOOTSTRAP_PACK_CHANNELS` | Comma-separated allowed artifact channel identities for bootstrap pack verification. | None |
| `MVM_BOOTSTRAP_PACK_HOST_CAPABILITIES` | Optional comma-separated host capability labels exposed to bootstrap pack verification. | Empty |
| `MVM_BOOTSTRAP_PACK_POLICY_MODE` | Pack policy mode for bootstrap verification: `online-default`, `offline-pinned`, `mirror-only`, or `local-rebuild-required`. | `online-default` |
| `MVM_BOOTSTRAP_PACK_CHANNEL_SIGNING_KEYS` | Optional comma-separated `CHANNEL=KEY_ID` pins. Required for `offline-pinned` channels. | Empty |
| `MVM_BOOTSTRAP_PACK_MIRROR_IDENTITY` | Optional mirror identity required by `mirror-only` policy. | None |
| `MVM_BOOTSTRAP_PACK_TRUST_STORE` | Optional trusted-publisher key directory for bootstrap pack verification. Defaults to the normal trusted publisher path. | Default trust store |
| `MVM_BOOTSTRAP_PACK_REVOCATIONS` | Optional local revocation JSON file for bootstrap pack verification. | None |
| `MVM_BOOTSTRAP_PACK_ALLOW_HTTP` | Set to `1` to allow plain-HTTP bootstrap pack downloads. HTTPS or local files are preferred. | Unset |
