---
title: CLI Commands
description: Complete command reference for mvmctl.
---

## VM Lifecycle

| Command | Description |
|---------|-------------|
| `mvmctl up --flake <ref>` | Build and run a VM from a Nix flake (aliases: `run`, `start`) |
| `mvmctl up --template <name>` | Run from a pre-built template (skip build) |
| `mvmctl up --name <name>` | Specify VM name (auto-generated if omitted) |
| `mvmctl up --profile <variant>` | Flake package variant (e.g. worker, gateway) |
| `mvmctl up --cpus N --memory SIZE` | Override vCPU count and memory (supports 512M, 4G, etc.) |
| `mvmctl up -p HOST:GUEST` | Forward a port mapping into the VM (repeatable) |
| `mvmctl up -e KEY=VALUE` | Inject an environment variable (repeatable) |
| `mvmctl up -v host:guest:size` | Mount a volume into the VM (repeatable) |
| `mvmctl up -d` | Run in background (detached mode, via launchd) |
| `mvmctl up --forward` | Auto-forward declared ports after boot (blocks until Ctrl-C) |
| `mvmctl up --hypervisor <backend>` | Force backend: `firecracker`, `apple-container`, `docker`, or `qemu` |
| `mvmctl up --config <path>` | Runtime config (TOML) for persistent resources/volumes |
| `mvmctl up --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl up --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl up --watch` | Watch flake for changes and auto-rebuild + reboot |
| `mvmctl up --network-preset <preset>` | Network egress policy: `unrestricted` (default), `none`, `registries`, `dev`, `agent` (LLM-inference + GitHub bundle — see [ADR-004](https://github.com/auser/mvm/blob/main/specs/adrs/004-hypervisor-egress-policy.md)) |
| `mvmctl up --network-allow host:port` | Allow egress to specific host:port (repeatable, mutually exclusive with preset) |
| `mvmctl up --seccomp <tier>` | Seccomp profile: `essential`, `minimal`, `standard`, `network`, `unrestricted` (default) |
| `mvmctl up --secret KEY:host` | Bind a secret to a domain (repeatable; see [Config & Secrets](/guides/config-secrets/)) |
| `mvmctl up --network <name>` | Named dev network to attach VM to (default: "default") |
| `mvmctl down [name]` | Stop VMs by name, or all if omitted |
| `mvmctl down -f <config>` | Stop only VMs defined in specified config |
| `mvmctl ls` | List running VMs (aliases: `ps`, `status`) |
| `mvmctl ls -a` | Show all VMs including stopped |
| `mvmctl ls --json` | Output as JSON |
| `mvmctl forward <name> -p PORT` | Forward a port from a running VM to localhost |
| `mvmctl logs <name>` | View guest console logs (`-f` to follow, `-n` for line count) |
| `mvmctl logs <name> --hypervisor` | View Firecracker hypervisor logs |
| `mvmctl diff <name>` | Show filesystem changes in a running VM (created/modified/deleted since boot) |
| `mvmctl diff <name> --json` | Output filesystem diff as JSON |

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Full setup from scratch: Homebrew deps (macOS), Lima, Firecracker, kernel, rootfs |
| `mvmctl bootstrap --production` | Production mode (skip Homebrew, assume Linux with apt) |
| `mvmctl setup` | Create Lima VM and install Firecracker assets (requires limactl) |
| `mvmctl setup --recreate` | Stop microVM, rebuild rootfs from upstream squashfs |
| `mvmctl setup --force` | Re-run all setup steps even if already complete |
| `mvmctl setup --lima-cpus N --lima-mem N` | Configure Lima VM resources (defaults: 8 CPUs, 16 GiB) |
| `mvmctl dev [up]` | Auto-bootstrap if needed, start dev VM, drop into shell. Uses Apple Container on macOS 26+, Lima otherwise. |
| `mvmctl dev up --project ~/dir` | Auto-bootstrap then cd into a project directory |
| `mvmctl dev up --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl dev up --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl dev up --lima` | Force Lima backend even on macOS 26+ |
| `mvmctl dev down` | Stop the Lima development VM |
| `mvmctl dev shell` | Open a shell in the running Lima VM |
| `mvmctl dev shell --project ~/dir` | Open shell and cd into a project directory |
| `mvmctl dev status` | Show dev environment status (Lima VM, Firecracker, Nix versions) |
| `mvmctl doctor` | Run system diagnostics and dependency checks |
| `mvmctl doctor --json` | Output diagnostics as JSON |
| `mvmctl update` | Check for and install mvmctl updates |
| `mvmctl update --check` | Only check for updates, don't install |
| `mvmctl update --force` | Force reinstall even if already up to date |
| `mvmctl update --skip-verify` | Skip cosign signature verification |

## Building

| Command | Description |
|---------|-------------|
| `mvmctl build <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build --flake <ref> --profile <variant>` | Build a specific flake package variant |
| `mvmctl build --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl build --json` | Output structured JSON events instead of human-readable output |
| `mvmctl build -o <path>` | Output path for the built .elf image |
| `mvmctl cleanup` | Remove old dev-build artifacts and run Nix garbage collection |
| `mvmctl cleanup --all` | Remove all cached build revisions |
| `mvmctl cleanup --keep <N>` | Keep the N newest build revisions |
| `mvmctl cleanup --verbose` | Print each cached build path that gets removed |

## Templates

| Command | Description |
|---------|-------------|
| `mvmctl template init <name> --local` | Scaffold a new template directory with flake.nix |
| `mvmctl template init <name> --vm` | Scaffold inside the Lima VM (overrides --local) |
| `mvmctl template init <name> --preset <preset>` | Scaffold preset: minimal, http, postgres, worker, python (default: minimal) |
| `mvmctl template init <name> --prompt "<text>" --local` | Generate a local scaffold from a natural-language prompt. In `auto` mode (default) probes for a local OpenAI-compatible endpoint on loopback (Ollama @ `:11434`, LocalAI @ `:8080`) before falling through to OpenAI. Override the order with `MVM_TEMPLATE_PROVIDER=openai\|local\|heuristic`; skip the probe with `MVM_TEMPLATE_NO_LOCAL_PROBE=1`. The probe issues a brief loopback TCP connect on each invocation, visible to local processes via `netstat` |
| `mvmctl template init <name> --dir <path>` | Base directory for local init (default: current dir) |
| `mvmctl template create <name>` | Create a single template definition |
| `mvmctl template create <name> --data-disk SIZE` | Create template with a data disk (10G, 512M, or plain MB; 0 = none) |
| `mvmctl template create-multi <base>` | Create templates for multiple roles (`--roles worker,gateway`) |
| `mvmctl template build <name>` | Build a template (runs nix build in Lima) |
| `mvmctl template build <name> --force` | Rebuild even if cached |
| `mvmctl template build <name> --snapshot` | Build, boot, wait for healthy, and capture a Firecracker snapshot |
| `mvmctl template build <name> --update-hash` | Recompute the Nix fixed-output derivation hash |
| `mvmctl template build <name> --config <toml>` | Build multiple variants from a template config TOML |
| `mvmctl template push <name>` | Push to S3-compatible registry |
| `mvmctl template push <name> --revision <hash>` | Push a specific revision |
| `mvmctl template pull <name>` | Pull from registry |
| `mvmctl template pull <name> --revision <hash>` | Pull a specific revision |
| `mvmctl template verify <name>` | Verify template checksums |
| `mvmctl template verify <name> --revision <hash>` | Verify a specific revision |
| `mvmctl template list` | List all templates (`--json` for JSON) |
| `mvmctl template info <name>` | Show template details, current revision, artifact sizes, and snapshot status (`--json` for JSON) |
| `mvmctl template edit <name>` | Edit template configuration (--cpus, --mem, --flake, --profile, --role, --data-disk) |
| `mvmctl template delete <name>` | Delete a template (`--force` to skip confirmation) |

## Configuration

| Command | Description |
|---------|-------------|
| `mvmctl config show` | Print current config as TOML |
| `mvmctl config edit` | Open the config file in $EDITOR (falls back to nano) |
| `mvmctl config set <key> <value>` | Set a single config key (e.g. `mvmctl config set lima_cpus 4`) |

## Audit

| Command | Description |
|---------|-------------|
| `mvmctl audit tail` | Show the last 20 audit events from /var/log/mvm/audit.jsonl |
| `mvmctl audit tail -n <N>` | Show the last N audit events |
| `mvmctl audit tail -f` | Follow audit log output (poll until Ctrl-C) |

## Flake Validation

| Command | Description |
|---------|-------------|
| `mvmctl flake check` | Validate a Nix flake before building (current directory) |
| `mvmctl flake check --flake <ref>` | Validate a specific flake path or reference |
| `mvmctl flake check --json` | Output structured JSON instead of human-readable output |

## Networks

| Command | Description |
|---------|-------------|
| `mvmctl network create <name>` | Create a named dev network with its own bridge and subnet |
| `mvmctl network list` | List all dev networks (alias: `ls`) |
| `mvmctl network inspect <name>` | Show details of a named network (JSON) |
| `mvmctl network remove <name>` | Remove a named network (alias: `rm`) |

## Image Catalog

| Command | Description |
|---------|-------------|
| `mvmctl image list` | List available images in the bundled catalog (alias: `ls`) |
| `mvmctl image search <query>` | Search images by name, description, or tag |
| `mvmctl image fetch <name>` | Build an image from the catalog (creates template + runs Nix build) |
| `mvmctl image info <name>` | Show catalog entry details (JSON) |

## Console

| Command | Description |
|---------|-------------|
| `mvmctl console <name>` | Interactive PTY shell into a running VM (vsock, no SSH) |
| `mvmctl console <name> --command <cmd>` | Run a one-shot command in the VM |

## One-shot Exec

`mvmctl exec` boots a fresh transient microVM, runs a single command, and tears it
down on exit — like `cco` or `docker run --rm`, but with a Firecracker microVM
as the sandbox. **Dev-mode only**: the guest agent's Exec handler is compiled in
only when the `dev-shell` Cargo feature is enabled. Production guest builds omit
the feature, so the handler is not present in the binary at all.

| Command | Description |
|---------|-------------|
| `mvmctl exec -- <cmd>...` | Boot the bundled default microVM image, run `<cmd>`, exit |
| `mvmctl exec --template <name> -- <cmd>...` | Boot a registered template instead of the default |
| `mvmctl exec --launch-plan <path> ` | Run the entrypoint from an [mvmforge](https://github.com/tinylabscom/decorationer) document — either the `launch.json` artifact (top-level `entrypoint`) or the Workload IR manifest (top-level `apps[]`). Mutually exclusive with trailing argv |
| `mvmctl exec --add-dir HOST:GUEST[:MODE] -- <cmd>` | Mount a host directory inside the guest. `MODE` is `ro` (default — writes discarded) or `rw` (writes rsynced back to the host after the command exits — see [ADR-002](/contributing/adr/002-writable-add-dir/)). Repeatable |
| `mvmctl exec --env KEY=VAL -- <cmd>` | Inject an environment variable. Repeatable. Overrides any env vars carried by `--launch-plan` |
| `mvmctl exec --cpus <n>` / `--memory <size>` | Resize the transient VM (defaults: 2 vCPUs, 512 MiB) |
| `mvmctl exec --timeout <secs>` | Per-command timeout (default: 60s) |

Examples:

```bash
mvmctl exec -- uname -a                                # default image
mvmctl exec --template minimal -- /bin/true            # named template
mvmctl exec --add-dir .:/work -- ls /work              # share current dir, RO
mvmctl exec --add-dir .:/work:rw -- touch /work/x      # writable, rsynced back
mvmctl exec -e DEBUG=1 -- env | grep DEBUG             # env var injection
mvmctl exec --launch-plan ./launch.json                # mvmforge entrypoint
```

### Launch-plan shape

`--launch-plan` accepts either of mvmforge's two JSON documents — the
shape is auto-detected. Only the entrypoint is consumed (image selection
still comes from `--template` or the bundled default in v1).

**LaunchPlan artifact** (`mvmforge compile`'s `launch.json`, top-level
`entrypoint`):

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

**Workload IR manifest** (`mvmforge emit` stdout, top-level `apps[]`):

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
that belongs in `mvmd`, not in `mvmctl exec`. Env precedence (lowest →
highest): top-level/app `env` → `entrypoint.env` → CLI `--env`.

### Snapshot restore

When the request boots a registered template (`--template <name>`) and
that template has a captured snapshot, `mvmctl exec` restores from the
snapshot instead of cold-booting — typically sub-second on Linux/KVM.

The snapshot path activates only when *all* of the following hold:

- the image source is a **registered template** (the bundled default
  image has no template snapshot to restore from);
- there are **no** `--add-dir` extras (extra drives would mismatch the
  snapshot's recorded drive layout);
- the active backend reports snapshot support.

On macOS / Lima QEMU, vsock snapshots return `os error 95` (EOPNOTSUPP);
restore failures fall back to cold boot with a warning rather than
aborting the exec. See the [Sandboxed Exec](/guides/exec/) guide for
the full background.

## Default microVM Image

When an image-taking command is invoked without `--flake` or `--template`,
`mvmctl` falls back to a bundled minimal image (busybox + the guest agent).
This applies to:

- `mvmctl exec -- <cmd>` — boots a fresh transient microVM and runs `<cmd>`
- `mvmctl up` / `mvmctl run` / `mvmctl start` — boots a long-running microVM
  with the same image

The image is built from `nix/default-microvm/` on first use and cached at
`~/.cache/mvm/default-microvm/` (kernel + rootfs). Nix is required to build
it; pass `--template` or `--flake` if Nix isn't available on your host.

## Cache

| Command | Description |
|---------|-------------|
| `mvmctl cache info` | Show cache directory path and disk usage |
| `mvmctl cache prune` | Remove stale temp files from the cache |
| `mvmctl cache prune --dry-run` | Show what would be removed without deleting |

## Security

| Command | Description |
|---------|-------------|
| `mvmctl security status` | Show security posture evaluation (vsock auth, seccomp, no-SSH, etc.) |
| `mvmctl security status --json` | Output posture report as JSON |

## Setup

| Command | Description |
|---------|-------------|
| `mvmctl init` | First-time setup wizard (deps, Lima VM, default network, XDG dirs) |
| `mvmctl init --non-interactive` | Run setup with defaults, no prompts |
| `mvmctl init --lima-cpus N --lima-mem N` | Configure Lima VM resources |

## Utilities

| Command | Description |
|---------|-------------|
| `mvmctl completions <shell>` | Generate shell completions (bash, zsh, fish, powershell) |
| `mvmctl shell-init` | Print shell configuration (completions + dev aliases) to stdout |
| `mvmctl metrics` | Show runtime metrics (Prometheus text format) |
| `mvmctl metrics --json` | Show runtime metrics as JSON |
| `mvmctl uninstall` | Remove Lima VM, Firecracker, and all mvm state (confirmation required) |
| `mvmctl uninstall -y` | Uninstall without confirmation |
| `mvmctl uninstall --all` | Also remove ~/.mvm/ config dir and /usr/local/bin/mvmctl binary |
| `mvmctl uninstall --dry-run` | Print what would be removed without removing |

## Global Options

All commands accept these global options:

| Option | Description |
|--------|-------------|
| `--log-format <human\|json>` | Log format: human (default) or json (structured) |
| `--fc-version <VERSION>` | Override Firecracker version (e.g., v1.14.0) |

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
| `MVM_SSH_PORT` | Lima SSH local port | `60022` |
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
| `RUST_LOG` | Logging level (e.g., `debug`, `mvm=trace`) | `info` |
