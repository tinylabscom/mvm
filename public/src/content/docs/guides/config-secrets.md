---
title: Config & Secrets Injection
description: Deliver config files and file-shaped secrets to a microVM through shares and volumes.
---

Config files and file-shaped secrets reach a workload through host directory
shares and registered volumes under `/data` or `/work`, described below.

:::caution[No config or secrets drive is attached]
Earlier releases mounted a read-only config drive at `/mnt/config` and a
secrets drive at `/mnt/secrets` from the image's own init. Images no longer
carry an init — the universal initramfs agent is PID 1 on every boot — and no
boot attaches either drive. The `config_files` / `secret_files` fields on
`FlakeRunConfig` are accepted and deliver nothing to the guest. `/mnt/config`
and `/mnt/secrets` stay reserved: the host mount policy refuses a share there,
and bare `/mnt` is refused because a share there would shadow them.
:::

Prefer managed secret references for credentials. Use a share or volume when a
workload genuinely needs file-shaped material such as certificates or a
compatibility config file. See [Secrets and credentials](/guides/secrets-and-credentials/)
for the reference-first model.

## Host directory shares

`--mount host_dir:/guest/path[:ro]` shares
a host directory into a **transient** run. The guest path must be
under `/data` or `/work`. Directory shares are read-only snapshots: the
directory is materialized into a throwaway image at boot, so a `:rw` request
is refused — a write would land in the discarded snapshot, never in the host
directory.

```bash
mkdir -p /tmp/my-config
echo '{"gateway": {"port": 8080}}' > /tmp/my-config/app.json

mvmctl run --manifest my-app \
    --mount /tmp/my-config:/data/config:ro
```

A persistent machine (`-d`, or `--name` with `--port`) refuses directory
shares outright under every profile — it cannot attach a live host directory,
and `machine run` and `machine create` say so before anything boots. Register
a snapshot-backed volume instead, or attach a sized disk image:

```bash
# Snapshotted into an ext4 image before each machine start; host edits
# become visible after the machine's next stop/start.
mvmctl machine volume mount app --volume config \
    --host /tmp/my-config --guest /data/config

# Durable read-write disk image. The third field is a size, which is what
# distinguishes a disk spec from a directory share's `:ro` mode field.
# Any profile that allows volumes accepts it; `--profile dev` is not needed.
mvmctl machine run --manifest my-app --name app -d \
    --mount app-data.img:/data/state:4G:rw
```

## Managed Secrets

A managed secret stays on the host; the guest holds a placeholder. The model is:

1. Store the value and bind it to its destinations with
   `mvmctl secret set <name> --provider <provider>` (or `--host <host>
   --type <type>` for an uncatalogued destination). `--from op://…`,
   `bw://…`, `keychain://…`, `env://…` or `file://…` reads the value from
   where it already lives instead of a prompt.
2. Bind it to a run with `--secret <name>[:HOST,...]` on `mvmctl run` or
   `mvmctl machine run`, declare it for every run of a project in `mvm.toml`'s
   `[secrets]` table (names and destinations only), or declare it with
   `mvm.secret(...)` in an SDK workload and pass the compiled IR with
   `--from-workload-ir`.
3. The guest sees only a normal environment variable holding an opaque
   `mvm-secret-…` placeholder.
4. The per-VM host network endpoint substitutes the real value into request
   headers bound for the secret's destinations — including HTTPS requests an
   ordinary client tunnels with `CONNECT`, which the endpoint terminates under
   a per-VM certificate the guest trusts. Traffic to any other destination is
   relayed without being opened.

```bash
mvmctl secret set anthropic --provider anthropic
mvmctl machine run --flake . --name agent -d --secret anthropic
```

```toml
# mvm.toml
[secrets]
anthropic = { hosts = ["api.anthropic.com"] }
```

See the
[agent sandbox guide](/guides/agent-sandbox/) for what the guest receives,
what the host checks, and what the audit chain records.

## Example: generic flake with config + secrets mounts

The pattern below works with any `mkGuest` flake that reads
`/data/config/` and/or `/data/secrets/` at boot. Write your own — see
[Building MicroVM Images](/guides/building-microvm-images) for the
`mkGuest` API surface, or [Nix Flakes](/guides/nix-flakes) for a
worked LLM-agent example showing the pattern end-to-end.

### Running with host config and secrets directories

```bash
mvmctl machine build --flake ./openclaw
mvmctl machine volume mount oc --volume config \
    --host "$PWD/nix/examples/openclaw/config" --guest /data/config
mvmctl machine volume mount oc --volume secrets \
    --host "$PWD/nix/examples/openclaw/secrets" --guest /data/secrets
mvmctl machine run --flake ./openclaw --name oc --port 3000:3000
```

`--port` makes `oc` a persistent machine, and a persistent machine cannot
attach a live host directory, so the directories are registered rather than
passed with `--mount`. Each registration snapshots its directory into a
read-only ext4 image at every start: host edits appear after the machine's
next stop and start. `--host` must be absolute and on encrypted storage, and
the registration can come before the machine exists.

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

mvmctl machine volume mount oc --volume config --host /tmp/my-config --guest /data/config
mvmctl machine volume mount oc --volume secrets --host /tmp/my-secrets --guest /data/secrets
mvmctl machine run --flake ./openclaw --name oc --port 3000:3000
```

A typical `mkGuest` service uses `preStart` to check for
`/data/config/<file>` and falls back to a built-in default; the
`command` script sources `/data/secrets/<env-file>` if present so
environment variables are available to the service process.

### Preparing a warm standby

For a frequently used verified image, `mvmctl pool warm --image alpine` prepares
an image-keyed standby. A compatible `machine run` may claim it; `mvmctl pool
status` shows the current pool. `mvmctl image pull --warm` combines a verified
registry pull with warming.

A standby is a prelaunched supervisor, not a saved running workload or a
reusable named snapshot template. It does not preserve a prior workload's
processes, session, files, or credentials. Keep configuration and file-shaped
secrets on the registered-volume path described above; each launch applies its
own mounts and admission policy.

Register each environment's files on its own machine:

```bash
mvmctl machine volume mount oc-prod --volume config --host "$PWD/prod/config" --guest /data/config
mvmctl machine volume mount oc-prod --volume secrets --host "$PWD/prod/secrets" --guest /data/secrets
mvmctl machine volume mount oc-staging --volume config --host "$PWD/staging/config" --guest /data/config
mvmctl machine volume mount oc-staging --volume secrets --host "$PWD/staging/secrets" --guest /data/secrets
mvmctl machine volume mount oc-dev --volume config --host "$PWD/dev/config" --guest /data/config
```

These are registered host-directory mounts, not snapshot-time refreshes. They
apply to their named machines and do not claim that one saved workload can be
reused for multiple environments.

### Monitoring the VM

```bash
mvmctl machine logs my-vm        # view console output
mvmctl machine logs my-vm -f     # follow in real time
```
