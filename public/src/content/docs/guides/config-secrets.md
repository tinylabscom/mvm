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
    --config-dir /tmp/my-config \
    --secrets-dir /tmp/my-secrets
```

## Guest Mount Points

| Drive | Mount | Permissions | Purpose |
|-------|-------|-------------|---------|
| `/dev/vdb` | `/mnt/config/` | Read-only (0444) | Application configuration |
| `/dev/vdc` | `/mnt/secrets/` | Read-only (0400) | API keys, tokens, credentials |

Every file in the `--config-dir` directory is written to the config drive. Every file in `--secrets-dir` is written to the secrets drive.

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

```bash
mkdir -p /tmp/oc-config /tmp/oc-secrets

# Application configuration
cat > /tmp/oc-config/openclaw.json << 'EOF'
{"gateway": {"port": 18789, "bind": "0.0.0.0"}, "auto_model_selection": true}
EOF

# API keys — any provider, any format
cat > /tmp/oc-secrets/openclaw-secrets.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
EOF

mvmctl run --template openclaw \
    --config-dir /tmp/oc-config \
    --secrets-dir /tmp/oc-secrets
```
