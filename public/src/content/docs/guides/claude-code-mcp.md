---
title: Claude Code with MVM tools
description: Connect Claude Code to MVM's local MCP server while keeping policy and guest execution boundaries explicit.
---

Claude Code can call MVM's MCP tools through a local stdio process. This gives
Claude Code an MVM tool surface; it does **not** confine Claude Code's own
shell, file-editing, or other tools. To run the agent itself inside a microVM,
use the [agent sandbox guide](/guides/agent-sandbox/) instead.

Run this integration on a host where `mvmctl` can manage machines. Repository
contributors run MVM runtime commands in the project builder VM, not on the
macOS development host.

## Set a narrow tool policy

In the project directory, add `policy/mcp-readonly.toml`:

```toml
description = "Read-only machine discovery for the local MCP client"

[overrides.tools]
allow = ["mvm.machine.list"]
```

Reference that policy from the project's `mvm.toml`:

```toml
[policy]
profile = "./policy/mcp-readonly.toml"
```

The file is a profile, so its own policy sits under `[overrides]`. A top-level
`[tools]` table is the group form: a profile that carries one does not parse,
and a project whose policy does not parse has no MCP server at all.

An active `[tools]` section admits only listed tools. This example allows
machine listing but refuses create, exec, stop, and unlisted tools. From the
project directory, check that the policy resolves and query individual tools
before connecting the client:

```sh
mvmctl policy validate
mvmctl policy show
mvmctl why --tool mvm.machine.list
mvmctl why --tool mvm.machine.stop
```

[Policy and profiles](/guides/policy-and-profiles/) covers the rest of the
policy language.

The MCP gate uses this project's resolved policy. A policy that exists but
fails to resolve prevents the server from starting. Without any `[tools]`
section, the MCP adapter has no tool gate; do not treat a missing policy as a
read-only configuration. Per-tool command, route, and secret detail is not
enforced at the MCP JSON-argument boundary. See
[Policy and profiles](/guides/policy-and-profiles/) for that limit.

## Connect Claude Code

From the project root, register the local server with project scope:

```sh
claude mcp add --transport stdio --scope project mvm -- sh -c 'cd "$CLAUDE_PROJECT_DIR" && exec mvmctl ops mcp stdio'
claude mcp get mvm
```

Claude Code supplies `CLAUDE_PROJECT_DIR` to a local MCP process; changing to
that directory makes MVM select the intended `mvm.toml` even if the client's
server launch directory differs. The server communicates with Claude Code over
local stdin/stdout, not a network listener. Claude Code may ask you to approve
a project-scoped server before it starts. See [Claude Code's MCP
documentation](https://code.claude.com/docs/en/mcp) for its current config and
approval controls.

In Claude Code, inspect `/mcp`, then ask it to list MVM machines. The only
permitted MVM tool in this example is `mvm.machine.list`; an attempted stop
must receive a policy denial. Keep Claude Code's own tool permissions separate:
MVM cannot stop an agent from using a native shell tool on the host.

If a tool rule says `ask`, `mvmctl ops mcp stdio` prompts on its controlling
terminal. A client session with no answering terminal is denied rather than
silently approved. This MCP-local decision is recorded in the local tool-gate
audit; it is not a substitute for the chain-signed audit of decisions inside
an admitted VM. For VM-bound execution and its audit boundary, see
[Agent tool contract](/guides/agent-tool-contract/).

This setup was checked with Claude Code 2.1.278, which opens the session with
MCP protocol version `2025-11-25`. The server echoes that version and
`2025-06-18`, answers an `initialize` naming any other version with
`2025-11-25`, and also serves the stateless `2026-07-28` form.

## The signed agent pack

The official registry publishes `agent/claude`, a signed policy profile for a
Claude Code workload running in a microVM. It is separate from the MCP setup
above: the pack governs what a guest may reach, not which MVM tools the host
client may call. It composes the `runtime/python` group pack, and `pull`
fetches exactly the pack it is given, so pull both:

```sh
mvmctl pull agent/claude
mvmctl pull runtime/python
mvmctl why --host api.anthropic.com:443 --profile agent/claude
mvmctl why --secret anthropic --profile agent/claude
```

`mvmctl policy show agent/claude` prints the merged result:

```toml
# layer: group `llm-apis` (built-in) (built-in)
# layer: group `github` (built-in) (built-in)
# layer: group `runtime/python` (pack) (pack)
# layer: profile `agent/claude` (pack) overrides (pack)
[network]
allow = [
    "api.anthropic.com:443",
    "api.openai.com:443",
    "github.com:443",
    "api.github.com:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "objects.githubusercontent.com:443",
]

[[secrets.bind]]
name = "anthropic"
hosts = ["api.anthropic.com"]
```

The profile binds a stored secret named `anthropic`. Store it under that name
before a run selects the pack; the guest receives a placeholder in
`ANTHROPIC_API_KEY`, never the value:

```sh
mvmctl secret set anthropic --provider anthropic
mvmctl run --policy agent/claude -- claude -p "summarize the repo"
```

The pack is policy only. It ships no image and installs nothing, so the image
the run boots has to carry Claude Code already; no published image or template
does. A guest booted under the pack was checked directly: it holds a
placeholder in `ANTHROPIC_API_KEY`, a request to `api.anthropic.com` carrying
it leaves the host with the stored key in its place, `api.github.com` and
`pypi.org` answer, and every unlisted destination is refused at the tunnel.
Claude Code itself has not been run inside a guest for this guide.
[Agent sandbox](/guides/agent-sandbox/) describes the placeholder and the
host-side substitution, and [Policy and profiles](/guides/policy-and-profiles/#pack-policy-signed-official-profiles-and-groups)
describes how a pack is verified, pinned and composed.
