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

[tools]
allow = ["mvm.machine.list"]
```

Reference that policy from the project's `mvm.toml`:

```toml
[policy]
profile = "./policy/mcp-readonly.toml"
```

An active `[tools]` section admits only listed tools. This example allows
machine listing but refuses create, exec, stop, and unlisted tools. Inspect
the resolved project policy before connecting the client, as described in
[Policy and profiles](/guides/policy-and-profiles/). You can also query
individual tools:

```sh
mvmctl why --tool mvm.machine.list
mvmctl why --tool mvm.machine.stop
```

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
