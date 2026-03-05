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

mvmctl run --template my-app \
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

The same functionality is available programmatically for library consumers like [mvmd](https://github.com/auser/mvmd):

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

## Design

The `DriveFile` type is content-agnostic — it's just `{name, content, mode}`. It knows nothing about specific file formats or keys. This means:

- Any file format works (JSON, TOML, YAML, env files, certificates, etc.)
- Adding support for new applications doesn't require code changes
- NixOS `EnvironmentFile` can load `.env` files directly as systemd environment variables

## Example: OpenClaw

The [OpenClaw example](/nix/examples/openclaw/) demonstrates all of these features. It ships with a default config baked into the image, but you can override it by mounting host directories.

### Running with example config

```bash
mvmctl template build openclaw
mvmctl run --template openclaw --name oc \
    -v nix/examples/openclaw/config:/mnt/config \
    -v nix/examples/openclaw/secrets:/mnt/secrets \
    -p 3000:3000
mvmctl forward oc 3000:3000
```

The default config uses `auth.mode: "none"` — no token is required to access the Control UI. The gateway binds to loopback inside the VM with a TCP proxy forwarding external connections, so all connections appear local and are auto-approved by OpenClaw (no device pairing prompts). To enable token auth, set `"auth": { "mode": "token" }` in your config and `OPENCLAW_GATEWAY_TOKEN` in `secrets/api-keys.env`.

### Running with custom config and API keys

```bash
# Create config directory with OpenClaw gateway settings
mkdir -p /tmp/oc-config
cat > /tmp/oc-config/openclaw.json << 'EOF'
{
  "gateway": {
    "mode": "local",
    "channelHealthCheckMinutes": 0,
    "auth": { "mode": "none" },
    "reload": { "mode": "off" },
    "controlUi": {
      "dangerouslyAllowHostHeaderOriginFallback": true
    }
  }
}
EOF

# Create secrets directory with API keys
mkdir -p /tmp/oc-secrets
cat > /tmp/oc-secrets/api-keys.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
EOF

mvmctl run --template openclaw --name oc \
    -v /tmp/oc-config:/mnt/config \
    -v /tmp/oc-secrets:/mnt/secrets \
    -p 3000:3000
```

The OpenClaw service's `preStart` script checks for `/mnt/config/openclaw.json` and uses it (with `envsubst` expansion) instead of the built-in default. The `command` script sources `/mnt/config/env.sh` and `/mnt/secrets/api-keys.env` if they exist, making environment variables available to the gateway process.

### Using snapshots for fast startup

Build the template with `--snapshot` to capture a running VM state. Subsequent runs restore from the snapshot instead of cold-booting, reducing startup time significantly:

```bash
mvmctl template build openclaw --snapshot
mvmctl run --template openclaw --name oc \
    -v nix/examples/openclaw/config:/mnt/config \
    -v nix/examples/openclaw/secrets:/mnt/secrets \
    -p 3000:3000
```

When restoring from a snapshot with `-v` mounts, the guest agent automatically remounts config/secrets drives and restarts services with the fresh data.

### Running commands inside the VM

The OpenClaw CLI is available inside the VM via `mvmctl vm exec`:

```bash
mvmctl vm exec oc -- openclaw nodes pending
mvmctl vm exec oc -- openclaw nodes approve <id>
mvmctl vm exec oc -- openclaw nodes status
```

See [nix/examples/openclaw/](https://github.com/auser/mvm/tree/main/nix/examples/openclaw) for the full example with sample config and secrets files.
