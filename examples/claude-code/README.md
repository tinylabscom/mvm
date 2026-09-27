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

The guest never holds the API key. Store it on the host once, bound to the
Anthropic API:

```bash
mvmctl secret set anthropic --provider anthropic
```

The command prompts for the key (`sk-ant-…`, from platform.claude.com; the
browser OAuth flow cannot run in a headless guest), so it does not land in
shell history. `--provider anthropic` binds it to `api.anthropic.com` and
nowhere else.

Every run below passes `--secret anthropic`. The guest then sees
`ANTHROPIC_API_KEY` set to an opaque `mvm-secret-…` placeholder. Claude Code
sends that placeholder as its `x-api-key` header; the host network endpoint
terminates the TLS connection to `api.anthropic.com` under a per-VM
certificate the guest trusts, swaps the placeholder for the real key, and
opens its own verified TLS connection to Anthropic. The same placeholder sent
anywhere else, or in a URL or request body, is refused and recorded in the
audit log. `mvmctl trust audit tail --chain` shows a `secret.substituted`
entry for each request that carried the key.

What this does not stop: a compromised agent can still send any request it
likes to `api.anthropic.com` with your key attached. Use a key with a spend
limit.

The Console key check Claude Code's interactive mode makes at startup goes
to `platform.claude.com`, which the `anthropic` binding does not cover. If
that check needs the key, bind it there too:
`mvmctl secret set anthropic --host api.anthropic.com --host platform.claude.com --type bearer`.

## Interactive workbench

```bash
mvmctl machine run --flake examples/claude-code --name claude -d \
  --profile dev --secret anthropic \
  --mount "$PWD/claude-workspace.img:/work:8G:rw"

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
- The secret binding is recorded beside the machine and re-validated on
  every start, and `mvmctl secret rm anthropic` refuses while the machine
  still names it.

## Headless (sealed)

```bash
echo "Summarize the files under /work/src" | \
  mvmctl machine run --flake examples/claude-code --flake-profile headless \
    --entrypoint --stdin - --secret anthropic \
    --mount "$PWD/claude-workspace.img:/work:8G:rw"
```

The task arrives on stdin, the answer leaves on the console/stdout path,
and the exit code is the run's status. `--bare` skips all discovery
(hooks, MCP, CLAUDE.md), so the only inputs are the placeholder, the stdin
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
  --secret anthropic --env NODE_USE_ENV_PROXY=1 \
  -it -- npx -y @anthropic-ai/claude-code@latest
```

Never pass the key itself with `--env`: that puts it in the guest's
environment, which is exactly what `--secret` exists to avoid.

## Updating the pinned binary

Bump `version` in `nix/images/examples/llm-agent/default.nix` and refresh both
platform checksums from
`https://downloads.claude.ai/claude-code-releases/<version>/manifest.json`.
