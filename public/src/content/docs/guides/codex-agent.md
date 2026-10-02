---
title: Codex with MVM
description: Use the signed agent/codex policy pack for a Codex workload, and know why the Codex CLI cannot connect to MVM's local MCP server yet.
---

MVM has two places it can meet Codex: the signed `agent/codex` policy pack,
which decides what a Codex workload in a microVM may reach, and the local MCP
server, which would give a Codex session on the host a set of MVM tools. The
pack is published and works. The MCP connection does not work with current
Codex releases, for the reason [below](#the-mcp-server-refuses-codexs-handshake).

Neither one confines Codex's own shell and file tools when Codex runs on the
host. To put the agent itself behind the microVM boundary, it has to run in the
guest; see [Agent sandbox](/guides/agent-sandbox/).

Repository contributors run MVM runtime commands in the project builder VM, not
on the macOS development host.

## Pull the pack

`agent/codex` is a profile. It includes the `runtime/node` group pack, and
`pull` fetches exactly the pack it is given, so pull both:

```sh
mvmctl search codex
mvmctl pull agent/codex
mvmctl pull runtime/node
mvmctl pack registry ls
```

Each `pull` verifies the pack's Sigstore signature against the publisher trust
policy, checks every payload file against the signed manifest, installs the
pack content-addressed, and pins the manifest digest in
`$MVM_HOME/registry/packs.lock.toml`. With `agent/codex` installed and
`runtime/node` missing, every command that resolves the profile stops and names
the pack to pull.

## What it grants

`mvmctl policy show agent/codex` prints the merged policy and the layer each
part came from:

```toml
# layer: group `llm-apis` (built-in) (built-in)
# layer: group `github` (built-in) (built-in)
# layer: group `runtime/node` (pack) (pack)
# layer: profile `agent/codex` (pack) overrides (pack)
[network]
allow = [
    "api.anthropic.com:443",
    "api.openai.com:443",
    "github.com:443",
    "api.github.com:443",
    "registry.npmjs.org:443",
    "nodejs.org:443",
    "objects.githubusercontent.com:443",
]

[[secrets.bind]]
name = "openai"
hosts = ["api.openai.com"]
```

Everything else is denied. Ask about one destination or secret without booting
anything:

```sh
mvmctl why --host api.openai.com:443 --profile agent/codex
mvmctl why --host registry.npmjs.org:443 --profile agent/codex
mvmctl why --secret openai --profile agent/codex
```

## Store the secret the pack binds

The profile binds a stored secret named `openai` to `api.openai.com`. The name
is part of the signed pack, so the secret has to be stored under it:

```sh
mvmctl secret set openai --provider openai
```

`mvmctl policy validate agent/codex --strict` reports a bound secret the store
does not hold. The guest never receives the value: it gets a placeholder in
`OPENAI_API_KEY`, and the host substitutes the real key into requests to
`api.openai.com` only.

## Run under the pack

Select the pack with `--policy`. It lowers into the same signed
`ExecutionPlan` the equivalent `--allow-host` and `--secret` flags produce:

```sh
mvmctl run --policy agent/codex -- codex exec "summarize the repo"
```

The pack is policy only. It ships no image and installs nothing, so the image
the run boots has to carry the Codex CLI already; no published image or
template does. Two things an image author needs to know:

- **Codex does not read `OPENAI_API_KEY`.** With only that variable set,
  Codex 0.147.0 and 0.160.0 sent their model requests with no `Authorization`
  header and were refused. Codex authenticates from its own login state:
  `codex login --with-api-key` reads a key on stdin and stores it, after which
  the key is sent. The placeholder in the guest environment does not reach
  Codex by itself.
- **Codex opens a WebSocket to `api.openai.com` first** and falls back to
  HTTPS when that fails.

Neither behaviour has been exercised inside a guest; they were observed on a
host against the live API.

What was checked in a guest is the pack. A guest booted under it holds a
placeholder in `OPENAI_API_KEY`; a request to `api.openai.com` carrying that
placeholder leaves the host with the stored key in its place, recorded as
`secret.substituted` in the audit chain; `api.github.com` and
`registry.npmjs.org` answer; and every unlisted destination is refused at the
tunnel, each with an `egress blocked` line on the host.

Add a destination the pack does not name with `--allow-host`, or compose your
own profile after the pack. Later entries take precedence, and a deny from any
layer still wins:

```sh
mvmctl run --policy agent/codex --policy ./mine.toml -- codex exec "summarize the repo"
```

## Keep the pack current

```sh
mvmctl pack registry update agent/codex
mvmctl pack registry rm agent/codex
```

`update` adopts a newer published version when there is one and re-verifies
the pinned one when there is not. A reference may pin a version,
`agent/codex@1.0.0`; a version other than the one in the lockfile is refused
until it is pulled.

## The MCP server refuses Codex's handshake

`codex mcp add mvm -- mvmctl ops mcp stdio` registers the server, and Codex
starts it from the directory the session runs in. The session then fails to
initialize it. Codex 0.147.0 and 0.160.0 open with MCP protocol version
`2025-06-18`; `mvmctl ops mcp stdio` accepts an `initialize` only for
`2025-11-25`, plus the stateless `2026-07-28` form, and answers any other
version with an error instead of negotiating. No MVM tool is listed in a Codex
session.

Until the server negotiates the version, drive MVM from Codex through the
`mvmctl` CLI itself, as [Agent tool contract](/guides/agent-tool-contract/)
describes. The clients that do connect are covered in
[Claude Code](/guides/claude-code-mcp/), [OpenCode](/guides/opencode-agent/)
and [Goose](/guides/goose-agent/).
