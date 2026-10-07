---
title: OpenCode with MVM
description: Connect OpenCode to MVM's local MCP server under a narrow tool policy, and use the signed agent/opencode policy pack for an OpenCode workload in a microVM.
---

MVM meets OpenCode in two places. On the host, OpenCode can call MVM's MCP
tools through a local stdio process. In a microVM, the signed `agent/opencode`
policy pack decides what an OpenCode workload may reach. The two are
independent: the MCP gate governs which MVM tools the host client may call, and
the pack governs a guest's network and secrets.

Neither one confines OpenCode's own shell and file tools when OpenCode runs on
the host. To put the agent itself behind the microVM boundary, it has to run in
the guest; see [Agent sandbox](/guides/agent-sandbox/).

Run the host integration on a host where `mvmctl` can manage machines.
Repository contributors run MVM runtime commands in the project builder VM, not
on the macOS development host.

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

The file is a profile, so its own policy sits under `[overrides]`. An active
`[tools]` section admits only listed tools: this one allows machine listing and
refuses create, stop, and every unlisted tool. From the project directory,
check that the policy resolves and query individual tools before connecting
the client:

```sh
mvmctl policy validate
mvmctl policy show
mvmctl why --tool mvm.machine.list
mvmctl why --tool mvm.machine.stop
```

The MCP gate uses this project's resolved policy. A policy that exists but
fails to resolve prevents the server from starting. Without any `[tools]`
section, the MCP adapter has no tool gate; do not treat a missing policy as a
read-only configuration. Per-tool command, route, and secret detail is not
enforced at the MCP JSON-argument boundary. See
[Policy and profiles](/guides/policy-and-profiles/) for that limit.

## Connect OpenCode

Add the server to `opencode.json` in the project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mvm": {
      "type": "local",
      "command": ["mvmctl", "ops", "mcp", "stdio"],
      "enabled": true
    }
  }
}
```

Then check the connection from the same directory:

```sh
opencode mcp list
```

OpenCode starts a local server in the project directory, which is how MVM
finds the `mvm.toml` whose policy gates the tools. The server speaks over
local stdin/stdout, not a network listener. `opencode mcp list` reports `mvm`
as connected once the handshake and the tool listing succeed. See
[OpenCode's MCP documentation](https://opencode.ai/docs/mcp-servers/) for its
current config keys.

The tool listing shows every tool the server offers; the policy is applied
when a tool is called. With the policy above, `mvm.machine.list` returns the
machine list and `mvm.machine.stop` returns a policy denial. Keep OpenCode's
own permissions separate: MVM cannot stop an agent from using a native shell
tool on the host.

If a tool rule says `ask`, `mvmctl ops mcp stdio` prompts on its controlling
terminal. A client session with no answering terminal is denied rather than
silently approved. This MCP-local decision is recorded in the local tool-gate
audit; it is not a substitute for the chain-signed audit of decisions inside
an admitted VM. For VM-bound execution and its audit boundary, see
[Agent tool contract](/guides/agent-tool-contract/).

This setup was checked with OpenCode 1.18.22, which opens the session with MCP
protocol version `2025-11-25`. The server echoes that version and
`2025-06-18`, answers an `initialize` naming any other version with
`2025-11-25`, and also serves the stateless `2026-07-28` form.

## The signed agent pack

The official registry publishes `agent/opencode`, a signed policy profile for
an OpenCode workload running in a microVM:

```sh
mvmctl search opencode
mvmctl pull agent/opencode
mvmctl pack registry ls
```

`pull` verifies the pack's Sigstore signature against the publisher trust
policy, checks the payload against the signed manifest, installs the pack
content-addressed, and pins the manifest digest in
`$MVM_HOME/registry/packs.lock.toml`. `agent/opencode` composes only built-in
groups, so there is no second pack to pull.

`mvmctl policy show agent/opencode` prints the merged policy and the layer
each part came from:

```toml
# layer: group `llm-apis` (built-in) (built-in)
# layer: group `github` (built-in) (built-in)
# layer: profile `agent/opencode` (pack) overrides (pack)
[network]
allow = [
    "api.anthropic.com:443",
    "api.openai.com:443",
    "github.com:443",
    "api.github.com:443",
]

[[secrets.bind]]
name = "anthropic"
hosts = ["api.anthropic.com"]

[[secrets.bind]]
name = "openai"
hosts = ["api.openai.com"]
```

Everything else is denied. Ask about one destination or secret without booting
anything:

```sh
mvmctl why --host api.anthropic.com:443 --profile agent/opencode
mvmctl why --secret openai --profile agent/opencode
```

## Store the secrets the pack binds

OpenCode routes across providers, so the profile binds two stored secrets,
`anthropic` and `openai`. The names are part of the signed pack, so the
secrets have to be stored under them:

```sh
mvmctl secret set anthropic --provider anthropic
mvmctl secret set openai --provider openai
```

Both are required. A run that selects the pack while either is missing stops
before anything boots and names the missing secret, and
`mvmctl policy validate agent/opencode --strict` reports the same thing
without a run. The guest never receives a value: it gets placeholders in
`ANTHROPIC_API_KEY` and `OPENAI_API_KEY`, and the host substitutes each real
key only into requests to that provider's host.

## Run under the pack

Select the pack with `--policy`. It lowers into the same signed
`ExecutionPlan` the equivalent `--allow-host` and `--secret` flags produce:

```sh
mvmctl run --policy agent/opencode -- opencode run "summarize the repo"
```

The pack is policy only. It ships no image and installs nothing, so the image
the run boots has to carry OpenCode already; no published image or template
does.

A guest booted under this pack was checked directly. It holds placeholders in
`ANTHROPIC_API_KEY` and `OPENAI_API_KEY`; a request to either provider carrying
its placeholder leaves the host with the stored key in its place, recorded as
`secret.substituted` in the audit chain; `api.github.com` answers; and every
unlisted destination is refused at the tunnel, each with an `egress blocked`
line on the host. Reach one of those with `--allow-host`, or with a profile
composed after the pack. OpenCode itself has not been run inside a guest for
this guide.

## Keep the pack current

```sh
mvmctl pack registry update agent/opencode
mvmctl pack registry rm agent/opencode
```

`update` adopts a newer published version when there is one and re-verifies
the pinned one when there is not. A reference may pin a version,
`agent/opencode@1.0.0`; a version other than the one in the lockfile is
refused until it is pulled. [Policy and profiles](/guides/policy-and-profiles/#pack-policy-signed-official-profiles-and-groups)
describes how a pack is verified, pinned and composed.
