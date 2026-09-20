# Claude Code in a microVM

Runs Anthropic's Claude Code CLI inside an mvm guest: its own kernel, no
guest NIC, default-deny egress with a two-host allow-list, and a read-only
rootfs. Two profiles:

- **`default`** — interactive workbench. Accessible (dev-tier) image; you
  attach a real PTY with `mvmctl machine console` and run `claude`.
- **`headless`** — sealed image whose baked entrypoint is
  `claude --bare -p`, fed by the stdin input plane. No shell, no console.

The image contains no Node.js and no glibc: it bakes the first-party
native musl binary, pinned by version + SHA-256 from the release
manifest at `downloads.claude.ai`.

## Credentials

The guest authenticates with an API key (`sk-ant-…`, from
platform.claude.com — the browser OAuth flow cannot run in a headless
guest). Put it in a file and mount that read-only; the wrapper exports it
if `ANTHROPIC_API_KEY` isn't already set:

```bash
mkdir -p ~/.mvm/config/secrets
printf '%s\n' 'sk-ant-…' > ~/.mvm/config/secrets/anthropic
chmod 0400 ~/.mvm/config/secrets/anthropic
```

**Interim posture, stated honestly:** the guest holds the raw key in
memory and env. Egress policy limits where it could be sent (the
allow-list is the API host plus the Console key-check host), but a
compromised workload could read it. The placeholder-substitution posture
(guest never sees the key) is the plan's W5.

## Interactive workbench

```bash
mvmctl machine run --flake examples/claude-code --name claude -d \
  --profile dev \
  --mount "$PWD/claude-workspace.img:/work:8G:rw" \
  --mount "$HOME/.mvm/config/secrets:/data/secrets:ro"

mvmctl machine console claude
# inside the guest:
claude
```

Notes:

- The workspace is a **sized disk image** (`HOST:/GUEST:SIZE:rw`), not a
  live host folder — mvm has no writable host-directory share. Move files
  in and out with `mvmctl machine cp <host-path> claude:/work/...` (and
  back). The image file persists across VM restarts.
- Agent state (`CLAUDE_CONFIG_DIR`) lands on `/work/.claude`
  automatically when `/work` is writable, so sessions survive a stop;
  guest `$HOME` is tmpfs and does not.
- One console session at a time; detach and reattach as needed.
- A transient secrets share is fine for `mvmctl run`; a **persistent**
  machine refuses live directory shares, so register the secrets
  directory as a snapshot-backed volume instead:

  ```bash
  mvmctl machine volume mount claude --volume secrets \
    --host "$HOME/.mvm/config/secrets" --guest /data/secrets
  ```

## Headless (sealed)

```bash
echo "Summarize the files under /work/src" | \
  mvmctl machine run --flake examples/claude-code --flake-profile headless \
    --entrypoint --stdin - \
    --mount "$PWD/claude-workspace.img:/work:8G:rw" \
    --mount "$HOME/.mvm/config/secrets:/data/secrets:ro"
```

The task arrives on stdin, the answer leaves on the console/stdout path,
and the exit code is the run's status. `--bare` skips all discovery
(hooks, MCP, CLAUDE.md), so the only inputs are the key file, the stdin
task, and whatever is mounted under `/work`.

## Network posture

`mvm.toml` admits exactly two hosts — `api.anthropic.com:443` (the API)
and `platform.claude.com:443` (the interactive startup key check) — and
turns on AI token metering, which recognises Anthropic responses
natively. Everything else is refused at the host-side egress gate with an
immediate 403 (Claude Code renders a refused optional host as a connect
error; the baked `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` keeps it
from asking in the first place). If you want Claude Code to fetch
packages or clone over HTTPS inside the guest, add those origins
explicitly, e.g. `--allow-host registry.npmjs.org:443`
`--allow-host github.com:443`.

## Zero-authoring fallback

No flake build required — the curated `node` runtime can run Claude Code
straight from npm (slower start, larger closure, glibc-free musl image):

```bash
mvmctl machine run --runtime node --memory 2G \
  --allow-host api.anthropic.com:443 --allow-host registry.npmjs.org:443 \
  --allow-host platform.claude.com:443 \
  --env ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" --env NODE_USE_ENV_PROXY=1 \
  -it -- npx -y @anthropic-ai/claude-code@latest
```

## Updating the pinned binary

Bump `version` in `nix/images/examples/llm-agent/default.nix` and refresh both
platform checksums from
`https://downloads.claude.ai/claude-code-releases/<version>/manifest.json`.
