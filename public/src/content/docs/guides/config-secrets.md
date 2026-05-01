---
title: Config & Secrets Injection
description: Inject custom files onto microVM drives at boot time.
---

mvm supports injecting custom files onto the guest's config and secrets drives at boot time. Files are written to the drive images before the VM starts.

## CLI Usage

```bash
mkdir -p /tmp/my-config /tmp/my-secrets

echo '{"gateway": {"port": 8080}}' > /tmp/my-config/app.json
echo 'API_KEY=sk-...' > /tmp/my-secrets/app.env

mvmctl up --template my-app \
    --volume /tmp/my-config:/mnt/config \
    --volume /tmp/my-secrets:/mnt/secrets
```

The `--volume` (`-v` for short) flag uses the format `host_dir:/guest/path`:

| Guest path | Drive | Permissions | Purpose |
|---|---|---|---|
| `/mnt/config` | `/dev/vdb` | Read-only (0444) | Application configuration |
| `/mnt/secrets` | `/dev/vdc` | Read-only (0400) | API keys, tokens, credentials |

Every file in the host directory is written to the corresponding drive image. For persistent volumes with explicit size, use the 3-part format: `--volume host:/guest/path:size`.

## Library API

The same functionality is available programmatically for library consumers:

```rust
use mvm_runtime::vm::microvm::{DriveFile, FlakeRunConfig};

let config = FlakeRunConfig {
    config_files: vec![DriveFile {
        name: "app.json".into(),
        content: serde_json::to_string(&app_config)?,
        mode: 0o444,
    }],
    secret_files: vec![DriveFile {
        name: "app.env".into(),
        content: format!("API_KEY={}", api_key),
        mode: 0o400,
    }],
    ..base_config
};
```

## Secret Bindings

For AI agent workloads, use `--secret` to bind environment variable secrets to specific target domains. This provides domain-scoped secret injection — combine with `--network-preset` to prevent exfiltration:

```bash
mvmctl up --flake . \
    --secret OPENAI_API_KEY:api.openai.com \
    --secret ANTHROPIC_API_KEY:api.anthropic.com:x-api-key \
    --network-preset dev
```

**Binding syntax:**

| Format | Meaning |
|--------|---------|
| `KEY:host` | Read KEY from host env, bind to host (Authorization header) |
| `KEY:host:header` | Custom HTTP header name |
| `KEY=value:host` | Explicit value instead of env lookup |
| `KEY=value:host:header` | Explicit value + custom header |

**What happens at boot:**

1. Secret values are resolved (from host env or explicit) and written to the **secrets drive** (mode 0600)
2. A `secrets-manifest.json` is written to the **config drive** (metadata only, no values)
3. Placeholder env vars (`mvm-managed:KEY`) are set in the guest environment so tools pass existence checks
4. Combined with network allowlists, the VM can only send traffic to the allowed domains

This is the "config-drive injection" approach. The secret values are on the guest's secrets drive but are scoped to specific domains via network policy. A future upgrade will add MITM proxy-based injection where secrets never touch the guest filesystem.

## Design

The `DriveFile` type is content-agnostic — it's just `{name, content, mode}`. It knows nothing about specific file formats or keys. This means:

- Any file format works (JSON, TOML, YAML, env files, certificates, etc.)
- Adding support for new applications doesn't require code changes
- NixOS `EnvironmentFile` can load `.env` files directly as systemd environment variables

## Example: generic flake with config + secrets mounts

The pattern below works with any `mkGuest` flake that reads
`/mnt/config/` and/or `/mnt/secrets/` at boot. See
[`nix/images/examples/`](https://github.com/auser/mvm/tree/main/nix/images/examples)
for concrete flakes (`hello`, `hello-node`, `hello-python`, `llm-agent`).

### Running with host-mounted config and secrets

```bash
mvmctl template build my-template
mvmctl up --template my-template --name my-vm \
    -v ./config:/mnt/config \
    -v ./secrets:/mnt/secrets \
    -p 3000:3000
mvmctl forward my-vm 3000:3000
```

Each `-v` flag mounts a host directory as an ext4 drive read-only by
default. Secrets land at `/mnt/secrets/` (mode 0440 root:mvm by the
init script) and are also re-staged to `/run/mvm-secrets/<svc>/`
with mode 0400 owned by the per-service uid (ADR-002 §W2.1) so
sibling services on the same microVM can't cross-read.

### Custom config + API keys at runtime

```bash
# Create a config directory with whatever shape your flake expects
mkdir -p /tmp/my-config
cat > /tmp/my-config/app.json << 'EOF'
{ "feature_flag": "value" }
EOF

# Create secrets — typically a .env file the service sources
mkdir -p /tmp/my-secrets
cat > /tmp/my-secrets/api-keys.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
EOF

mvmctl up --template my-template --name my-vm \
    -v /tmp/my-config:/mnt/config \
    -v /tmp/my-secrets:/mnt/secrets \
    -p 3000:3000
```

A typical `mkGuest` service uses `preStart` to check for
`/mnt/config/<file>` and falls back to a built-in default; the
`command` script sources `/mnt/secrets/<env-file>` if present so
environment variables are available to the service process.

### Using snapshots for fast startup

Build the template with `--snapshot` to capture a running VM state.
Subsequent runs restore from the snapshot instead of cold-booting,
reducing startup time from minutes to **1-2 seconds**:

```bash
mvmctl template build my-template --snapshot
mvmctl up --template my-template --name my-vm \
    -v ./config:/mnt/config \
    -v ./secrets:/mnt/secrets \
    -p 3000:3000
```

When restoring from a snapshot with `-v` mounts, the guest agent
automatically remounts config/secrets drives and restarts services
with the fresh data.

#### Snapshots + dynamic mounts = instant boots with flexible config

**Key insight:** the snapshot stores OS and application state
(memory, running processes, compiled code caches), but **config and
secrets drives are created fresh at runtime** from your host
directories. This means:

- ✅ **Same snapshot** can serve multiple instances with different
  configs.
- ✅ **Update configs without rebuilding** — change the host files
  and re-up.
- ✅ **Instant boot + dynamic configuration** — get both benefits
  simultaneously.

Example: run three instances from one snapshot with different API
keys:

```bash
mvmctl up --template my-template --name my-vm-prod \
    -v ./prod/config:/mnt/config \
    -v ./prod/secrets:/mnt/secrets \
    -p 3000:3000

mvmctl up --template my-template --name my-vm-staging \
    -v ./staging/config:/mnt/config \
    -v ./staging/secrets:/mnt/secrets \
    -p 3001:3000

mvmctl up --template my-template --name my-vm-dev \
    -v ./dev/config:/mnt/config \
    -p 3002:3000
```

All three restore from the same snapshot (1-2 second boot) but get
different configs and secrets at runtime.

### Monitoring the VM

```bash
mvmctl logs my-vm        # view console output
mvmctl logs my-vm -f     # follow in real time
```
