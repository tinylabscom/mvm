---
title: Config & Secrets Injection
description: Inject custom config files and tightly scoped secret files onto microVM drives at boot time.
---

mvm supports injecting custom files onto the guest's config and secrets drives at boot time. Files are written to the drive images before the VM starts.

:::caution[This is a library API, not a `--mount` flag]
The config and secrets drives are read-only ext4 **drive images** that guest
`/init` mounts from `/dev/vdb` and `/dev/vdc`. They are not host directory
shares, and `--mount` cannot populate them: `/mnt/config` and `/mnt/secrets`
are *protected* paths in the host mount policy, and bare `/mnt` is refused
because a share there would shadow them. A `--mount` guest path must be under
`/data` or `/work`.

The supported way to place files on these drives is the `config_files` /
`secret_files` fields on `FlakeRunConfig` (see [Library API](#library-api)
below). There is no `mvmctl` flag that does it today.
:::

Prefer managed secret references for credentials. Use secrets drives when a
workload genuinely needs file-shaped material such as certificates or a
compatibility config file. See [Secrets and credentials](/guides/secrets-and-credentials/)
for the reference-first model.

## The drives

| Guest path | Drive | Permissions | Purpose |
|---|---|---|---|
| `/mnt/config` | `/dev/vdb` | Read-only (0444) | Application configuration |
| `/mnt/secrets` | `/dev/vdc` | Read-only (0400) | File-shaped secret material |

Both are mounted `ro,noexec,nosuid,nodev` by guest `/init` before the
entrypoint starts.

## Host directory shares

Separately from the drives above, `--mount host_dir:/guest/path[:MODE]` shares
a host directory into the guest. `--volume` remains accepted as a
compatibility alias, but `-v` is global verbosity. The guest path must be
under `/data` or `/work`, `MODE` is `ro` (default) or `rw`, and `:rw` requires
a persistent machine under `--profile dev`:

```bash
mkdir -p /tmp/my-config
echo '{"gateway": {"port": 8080}}' > /tmp/my-config/app.json

mvmctl machine run --manifest my-app --name app -d \
    --mount /tmp/my-config:/data/config:ro
```

The third field is the mode, not a size.

## Library API

The same functionality is available programmatically for library consumers:

```rust
use mvm_runtime::microvm::FlakeRunConfig;
use mvm_vmm::host::drive_file::DriveFile;

fn with_config_and_secrets(
    base_config: FlakeRunConfig,
    app_config: &serde_json::Value,
    api_key: &str,
) -> Result<FlakeRunConfig, serde_json::Error> {
    Ok(FlakeRunConfig {
        config_files: vec![DriveFile {
            name: "app.json".into(),
            content: serde_json::to_string(app_config)?,
            mode: 0o444,
        }],
        secret_files: vec![DriveFile {
            name: "app.env".into(),
            content: format!("API_KEY={api_key}"),
            mode: 0o400,
        }],
        ..base_config
    })
}
```

## Managed Secrets

`mvmctl machine run` has no `--secret` flag (removed).

Use `mvmctl secret put` to store local secret refs, then bind those refs
through `mvm.toml` or the SDKs. That is the supported path for managed
secrets.

The managed-secret model is:

1. Store a secret ref locally with `mvmctl secret put <name>`
2. Declare that ref in `mvm.toml` or with `mvm.secret(...)`
3. The guest sees only a normal env var name with an opaque token
4. Host-mediated broker verbs such as `mvm.web_fetch` and `mvm.web_search`
   release the real value at request time when policy allows it. These are
   host-side broker tool names, not functions exported by the Python or
   TypeScript SDK.

Managed secret refs are host-mediated only. Guest HTTPS CONNECT egress
is not a substitution path.

## Design

The `DriveFile` type is content-agnostic — it's just `{name, content, mode}`. It knows nothing about specific file formats or keys. This means:

- Any file format works (JSON, TOML, YAML, env files, certificates, etc.)
- Adding support for new applications doesn't require code changes
- NixOS `EnvironmentFile` can load `.env` files directly as systemd environment variables

## Example: generic flake with config + secrets mounts

The pattern below works with any `mkGuest` flake that reads
`/data/config/` and/or `/data/secrets/` at boot. Write your own — see
[Building MicroVM Images](/guides/building-microvm-images) for the
`mkGuest` API surface, or [Nix Flakes](/guides/nix-flakes) for a
worked LLM-agent example showing the pattern end-to-end.

### Running with host-mounted config and secrets

```bash
mvmctl machine build --flake ./openclaw
mvmctl machine run --flake ./openclaw --name oc --port 3000:3000 \
    --mount nix/examples/openclaw/config:/data/config \
    --mount nix/examples/openclaw/secrets:/data/secrets
```

Each `--mount` flag shares a host directory into the guest, read-only by
default. Material placed on the *secrets drive* (`/mnt/secrets/`, mode 0440
root:mvm by the init script) is additionally re-staged to
`/run/mvm-secrets/<svc>/` with mode 0400 owned by the per-service uid
(ADR-001 §W2.1) so sibling services on the same microVM can't cross-read.
That re-staging applies to the drive, not to a `--mount` share.

### Custom config + API keys at runtime

```bash
# Create a config directory with whatever shape your flake expects
mkdir -p /tmp/my-config
cat > /tmp/my-config/app.json << 'EOF'
{ "feature_flag": "value" }
EOF

# Create a secret-reference file the service understands
mkdir -p /tmp/my-secrets
cat > /tmp/my-secrets/secret-refs.env << 'EOF'
ANTHROPIC_API_KEY_REF=anthropic-api-key
EOF

mvmctl machine run --flake ./openclaw --name oc --port 3000:3000 \
    --mount /tmp/oc-config:/data/config \
    --mount /tmp/oc-secrets:/data/secrets
```

A typical `mkGuest` service uses `preStart` to check for
`/data/config/<file>` and falls back to a built-in default; the
`command` script sources `/data/secrets/<env-file>` if present so
environment variables are available to the service process.

### Using snapshots for faster startup

There is no `--snapshot` flag on `machine build`. Snapshots are taken from a
running machine with the (hidden) `mvmctl machine snapshot` verb on a backend
that supports it; subsequent runs can restore instead of cold-booting. Published latency numbers must name the backend, host, artifact,
and readiness boundary.

```bash
mvmctl machine build --flake ./openclaw
mvmctl machine run --flake ./openclaw --name oc --port 3000:3000 \
    --mount nix/examples/openclaw/config:/data/config \
    --mount nix/examples/openclaw/secrets:/data/secrets
```

When restoring from a snapshot with `--mount` shares, the guest agent
automatically remounts config/secrets drives and restarts services
with the fresh data.

#### Snapshots + dynamic mounts

**Key insight:** the snapshot stores OS and application state
(memory, running processes, compiled code caches), but **config and
secrets drives are created fresh at runtime** from your host
directories. This means:

- ✅ **Same snapshot** can serve multiple instances with different
  configs.
- ✅ **Update configs without rebuilding** — change the host files
  and restart the machine.
- ✅ **Instant boot + dynamic configuration** — get both benefits
  simultaneously.

Example: run three instances from one snapshot with different API
keys:

```bash
# Production gateway with prod Anthropic key
mvmctl machine run --manifest openclaw --name oc-prod \
    --port 3000:3000 \
    --mount ./prod/config:/data/config \
    --mount ./prod/secrets:/data/secrets

# Staging gateway with test key
mvmctl machine run --manifest openclaw --name oc-staging \
    --port 3001:3000 \
    --mount ./staging/config:/data/config \
    --mount ./staging/secrets:/data/secrets

# Dev gateway with no key (localhost-only testing)
mvmctl machine run --manifest openclaw --name oc-dev \
    --port 3002:3000 \
    --mount ./dev/config:/data/config
```

All three restore from the same snapshot (1-2 second boot) but get
different configs and secrets at runtime.

### Monitoring the VM

```bash
mvmctl machine logs my-vm        # view console output
mvmctl machine logs my-vm -f     # follow in real time
```
