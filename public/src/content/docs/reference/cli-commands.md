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
| `vm <sub>` | `pause`, `resume`, `snapshot`, `cp`, `fs`, `proc`, `diff`, `wait`, `boot-report`, `set-ttl`, `forward`, `sandbox`, `session`, `volume` |
| `build <sub>` | `image` (the former `build`), `compile`, `validate`, `kernel` |
| `ops <sub>` | `metrics`, `bench`, `config`, `mcp` |
| `env <sub>` | `bootstrap`, `cleanup`, `uninstall`, `update`, `sign` |
| `trust <sub>` | `add`/`list`/`remove` (publishers), `attest`, `receipt`, `audit` |
| Already-grouped top-level | `image`, `catalog`, `manifest`, `storage`, `network`, `cache`, `pool`, `secret`, `bundle`, `deps`, `artifact` |

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
| `mvmctl down [name]` | Stop VMs by name, or all if omitted |
| `mvmctl ls` | List running VMs (aliases: `ps`, `status`) |
| `mvmctl ls -a` | Show all VMs including stopped |
| `mvmctl ls --json` | Output as JSON |
| `mvmctl vm forward <name> -p PORT` | Forward a port from a running VM to localhost |
| `mvmctl logs <name>` | View guest console logs (`-f` to follow, `-n` for line count) |
| `mvmctl logs <name> --hypervisor` | View Firecracker hypervisor logs |
| `mvmctl vm diff <name>` | Show filesystem changes in a running VM (created/modified/deleted since boot) |
| `mvmctl vm diff <name> --json` | Output filesystem diff as JSON |
| `mvmctl vm wait <name> --for <component>` | Block until a guest readiness component is `Ready`, `Disabled`, or `Failed`. Targets: `control-plane`, `entrypoint`, `warm-pool`, `integrations`, `probes`, `all` (default). Exit codes: `0` ready, `65` (`EX_DATAERR`) failed, `75` (`EX_TEMPFAIL`) timeout. Plan 76 Phase 2. |
| `mvmctl vm wait <name> --timeout <secs> --interval-ms <ms>` | Tune the deadline and poll cadence. Defaults: 60s / 250ms. |
| `mvmctl vm boot-report <name>` | Print a single readiness snapshot + per-phase boot timings. Plan 76 Phase 4. |
| `mvmctl vm boot-report <name> --json` | Same payload as JSON. |

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl env bootstrap` | Full setup from scratch: Homebrew deps (macOS), Firecracker, kernel, rootfs (idempotent — safe to re-run) |
| `mvmctl env bootstrap --production` | Production mode (skip Homebrew, assume Linux with apt) |
| `mvmctl dev [up]` | Auto-bootstrap if needed, start dev VM, drop into shell. On macOS, the dev-image builder auto-detects Vz on macOS 26+ Apple Silicon and retries with libkrun when that auto-selected Vz builder path fails; native KVM is used on Linux. |
| `mvmctl dev up --project ~/dir` | Auto-bootstrap then cd into a project directory |
| `mvmctl dev up --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl dev up --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl dev up --shell` (or `-s`) | Force opening an interactive shell after starting (the default behavior) |
| `mvmctl dev up --no-shell` | Start the dev VM without attaching an interactive shell |
| `mvmctl dev down` | Stop the dev VM |
| `mvmctl dev down --reset` | Also delete the cached dev image so the next `dev up` rebuilds from local source |
| `mvmctl dev shell` | Open a shell in the running dev VM |
| `mvmctl dev shell --project ~/dir` | Open shell and cd into a project directory |
| `mvmctl dev status` | Show dev environment backend, running state, cached image paths, and safe builder-cache readiness reason |
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
| `mvmctl console <name>` | Interactive PTY shell into a running VM (vsock, no SSH) |
| `mvmctl console <name> --command <cmd>` | Run a one-shot command in the VM |

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
over the existing runtime verbs, not a parallel runtime — every `machine`
subcommand translates into the same signed-`ExecutionPlan`, audited, OCI-provenance
execution path as the lower-level commands, so the security posture is identical.

The flagship verb is `machine run`: boot a fresh microVM from an OCI image, run a
command, and tear the VM down. It routes into the same code path as
`mvmctl run --image`, so it inherits **deny-all networking by default** and the
same `--profile`, `--add-dir`, `--receipt`, `--json`, and `--dry-run` semantics.

| Command | Description |
|---------|-------------|
| `mvmctl machine run --image <ref> -- <cmd>...` | Boot an OCI image, run `<cmd>` with no network, tear down |
| `mvmctl machine run --image <ref> --profile dev --add-dir .:/work:rw -- <cmd>` | Same, with a writable host share under the dev profile |
| `mvmctl machine run --image <ref> --cpus <n> --memory <size> -- <cmd>` | Resize the transient VM |
| `mvmctl machine run --image <ref> --dry-run -- <cmd>` | Validate and explain the run plan without booting a VM |
| `mvmctl machine run --image <ref> --json -- <cmd>` | Print a redacted JSON execution summary |
| `mvmctl machine run --image <ref> --receipt <path> -- <cmd>` | Write a signed execution receipt |

Ergonomic opt-in egress (`--net` / `--allow-host`), persistent named machines
(`machine create/start/exec/shell/stop`), and `machine pack` for portable signed
artifacts are planned follow-ups; they are intentionally not yet present rather
than stubbed. Until `--net` lands, image-backed machine runs are network-isolated;
use `mvmctl up` for the manifest/flake path that already exposes named networks
and policy bundles.

## Sandbox State

| Command | Description |
|---------|-------------|
| `mvmctl vm sandbox gc` | Dry-run cleanup of stale sandbox name-registry entries for stopped or expired VMs |
| `mvmctl vm sandbox gc --dry-run` | Explicit dry-run; reports candidates and does not mutate state |
| `mvmctl vm sandbox gc --apply` | Remove stale stopped/expired registry entries and emit a `SandboxGc` audit entry |
| `mvmctl vm sandbox gc --json` | Print a machine-readable GC summary with candidates, reasons, and removed count |

`sandbox gc` never tears down a live VM. Entries that still appear as starting,
running, or paused in a backend listing are skipped; cleanup only removes stale
host registry records.
`--json` does not change the safety mode: cleanup remains dry-run unless
`--apply` is also passed.

## Checkpoint

`mvmctl checkpoint` manages memory-state checkpoints for Vz-backed VMs (`vm-full` class). `mvmctl snapshot ls` / `mvmctl snapshot rm` remain for Firecracker sealed snapshots.

| Command | Description |
|---------|-------------|
| `mvmctl checkpoint create <name> --class <class>` | Capture a checkpoint. `--class vm-full` saves full machine state (memory + disk) via Vz's `saveMachineStateToURL`. Records content hash in the audit chain. |
| `mvmctl checkpoint restore <name> --name <checkpoint>` | Restore a previously created checkpoint. Re-hashes content against the recorded audit entry before loading. |
| `mvmctl checkpoint fork <name> --name <checkpoint> --into <new-name>` | Restore a checkpoint into a new VM identity (new name, separate audit lineage). |
| `mvmctl checkpoint ls [<name>]` | List checkpoints for a VM, or all VMs if name is omitted. |
| `mvmctl checkpoint rm <name> --name <checkpoint>` | Delete a named checkpoint and its blobs. |

Checkpoint blobs are stored under `~/.mvm/vms/<name>/checkpoints/<checkpoint-name>/`. The audit chain records `checkpoint.created` and `checkpoint.restored` entries with content hashes; hash drift between creation and restore is flagged in the restore entry rather than aborting, so operators can review transfers between hosts.

## File Copy

| Command | Description |
|---------|-------------|
| `mvmctl vm cp <host-path> <vm>:/absolute/path` | Copy one regular file from the host into a running VM |
| `mvmctl vm cp <vm>:/absolute/path <host-path>` | Copy one regular file from a running VM to the host |
| `mvmctl vm cp --force <src> <dst>` | Overwrite an existing destination |
| `mvmctl vm cp --create-parents <src> <dst>` | Create destination parent directories |
| `mvmctl vm cp --max-bytes <n> <src> <dst>` | Refuse copies larger than the byte cap. Default: 16 MiB |
| `mvmctl vm cp --json <src> <dst>` | Print a machine-readable copy summary without host paths or file contents |

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
| `mvmctl vm volume create <name>` | Create a locked mvm-managed encrypted local volume archive |
| `mvmctl vm volume create <name> --root <absolute-dir>` | Create the mvm-managed encrypted volume under a specific root |
| `mvmctl vm volume create <name> --host-backed` | Create the previous host-backed managed directory, requiring encrypted backing storage |
| `mvmctl vm volume unlock <name>` | Decrypt a managed volume into its plaintext mount directory |
| `mvmctl vm volume lock <name>` | Seal a managed volume back into its encrypted archive and remove plaintext |
| `mvmctl vm volume catalog` | List managed local volumes |
| `mvmctl vm volume catalog --json` | List managed local volumes as JSON |
| `mvmctl vm volume mount <vm> --volume <name> --guest <absolute-path>` | Register an unlocked managed local virtio-fs volume mount for a VM. Read-only by default |
| `mvmctl vm volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path>` | Register an ad-hoc encrypted host directory as a virtio-fs volume mount |
| `mvmctl vm volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path> --rw` | Register the volume read-write |
| `mvmctl vm volume ls <vm>` | List registered volume mounts |
| `mvmctl vm volume ls <vm> --json` | List registered volume mounts as JSON |
| `mvmctl vm volume unmount <vm> <guest-path>` | Remove a registered volume mount |

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

## Cache

| Command | Description |
|---------|-------------|
| `mvmctl cache info` | Show cache directory path and disk usage |
| `mvmctl cache prune` | Remove stale temp files from the cache |
| `mvmctl cache prune --dry-run` | Show what would be removed without deleting |
| `mvmctl cache prune --orphan-builds` | Also sweep orphaned builds — built artifacts whose source `mvm.toml` is gone (equivalent to `mvmctl manifest prune --orphans`) |

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
