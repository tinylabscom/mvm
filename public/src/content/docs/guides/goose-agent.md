---
title: Goose with MVM
description: Connect Goose to MVM's local MCP server under a narrow tool policy, and use the signed agent/goose policy pack for a Goose workload in a microVM.
---

MVM meets Goose in two places. On the host, Goose can load MVM's MCP server as
a stdio extension. In a microVM, the signed `agent/goose` policy pack decides
what a Goose workload may reach. The two are independent: the MCP gate governs
which MVM tools the host client may call, and the pack governs a guest's
network and secrets.

Neither one confines Goose's own developer tools when Goose runs on the host.
To put the agent itself behind the microVM boundary, it has to run in the
guest; see [Agent sandbox](/guides/agent-sandbox/).

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

`policy validate` prints a note that `[tools]` is not enforced by the runtime.
That note is about a workload in a VM; the MCP gate described here does
enforce these whole-tool decisions.

The MCP gate uses this project's resolved policy. A policy that exists but
fails to resolve prevents the server from starting. Without any `[tools]`
section, the MCP adapter has no tool gate; do not treat a missing policy as a
read-only configuration. Per-tool command, route, and secret detail is not
enforced at the MCP JSON-argument boundary. See
[Policy and profiles](/guides/policy-and-profiles/) for that limit.

## Connect Goose

For one session, name the server on the command line from the project
directory. The `mvm:` prefix names the extension; without it Goose names the
extension after the command:

```sh
goose session --with-extension "mvm:mvmctl ops mcp stdio"
```

To load it in every session, add it to Goose's `config.yaml`
(`~/.config/goose/config.yaml`; `goose info` prints the path in use):

```yaml
extensions:
  mvm:
    enabled: true
    type: stdio
    name: mvm
    cmd: mvmctl
    args:
      - ops
      - mcp
      - stdio
    timeout: 300
```

Goose starts the extension in the directory the session runs in, which is how
MVM finds the `mvm.toml` whose policy gates the tools. A session started
elsewhere reads a different project's policy, or none. The server speaks over
local stdin/stdout, not a network listener. See
[Goose's extension documentation](https://goose-docs.ai/docs/getting-started/using-extensions)
for its current config keys.

The tool listing shows every tool the server offers; the policy is applied
when a tool is called. With the policy above, `mvm.machine.list` returns the
machine list and `mvm.machine.stop` returns a policy denial. Keep Goose's own
extensions separate: MVM cannot stop an agent from using a native shell tool
on the host.

If a tool rule says `ask`, `mvmctl ops mcp stdio` prompts on its controlling
terminal. A client session with no answering terminal is denied rather than
silently approved. This MCP-local decision is recorded in the local tool-gate
audit; it is not a substitute for the chain-signed audit of decisions inside
an admitted VM. For VM-bound execution and its audit boundary, see
[Agent tool contract](/guides/agent-tool-contract/).

This setup was checked with Goose 1.52.0, which uses the stateless MCP
protocol version `2026-07-28`. The server answers that form and an
`initialize` for `2025-11-25`, and refuses an `initialize` naming any other.

## The signed agent pack

The official registry publishes `agent/goose`, a signed policy profile for a
Goose workload running in a microVM:

```sh
mvmctl search goose
mvmctl pull agent/goose
mvmctl pack registry ls
```

`pull` verifies the pack's Sigstore signature against the publisher trust
policy, checks the payload against the signed manifest, installs the pack
content-addressed, and pins the manifest digest in
`$MVM_HOME/registry/packs.lock.toml`. `agent/goose` composes only built-in
groups, so there is no second pack to pull.

`mvmctl policy show agent/goose` prints the merged policy and the layer each
part came from:

```toml
# layer: group `llm-apis` (built-in) (built-in)
# layer: group `github` (built-in) (built-in)
# layer: profile `agent/goose` (pack) overrides (pack)
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
mvmctl why --host api.openai.com:443 --profile agent/goose
mvmctl why --secret anthropic --profile agent/goose
```

## Store the secrets the pack binds

Goose drives both major providers, so the profile binds two stored secrets,
`anthropic` and `openai`. The names are part of the signed pack, so the
secrets have to be stored under them:

```sh
mvmctl secret set anthropic --provider anthropic
mvmctl secret set openai --provider openai
```

Both are required. A run that selects the pack while either is missing stops
before anything boots and names the missing secret, and
`mvmctl policy validate agent/goose --strict` reports the same thing without a
run. The guest never receives a value: it gets placeholders in
`ANTHROPIC_API_KEY` and `OPENAI_API_KEY`, and the host substitutes each real
key only into requests to that provider's host.

## Run under the pack

Select the pack with `--policy`. It lowers into the same signed
`ExecutionPlan` the equivalent `--allow-host` and `--secret` flags produce:

```sh
mvmctl run --policy agent/goose -- goose run --no-session -t "summarize the repo"
```

The pack is policy only. It ships no image and installs nothing, so the image
the run boots has to carry Goose already; no published image or template does.

A guest booted under this pack was checked directly. It holds placeholders in
`ANTHROPIC_API_KEY` and `OPENAI_API_KEY`; a request to either provider carrying
its placeholder leaves the host with the stored key in its place, recorded as
`secret.substituted` in the audit chain; `api.github.com` answers; and every
unlisted destination is refused at the tunnel, each with an `egress blocked`
line on the host. Reach one of those with `--allow-host`, or with a profile
composed after the pack. Goose itself has not been run inside a guest for
this guide.

## Keep the pack current

```sh
mvmctl pack registry update agent/goose
mvmctl pack registry rm agent/goose
```

`update` adopts a newer published version when there is one and re-verifies
the pinned one when there is not. A reference may pin a version,
`agent/goose@1.0.0`; a version other than the one in the lockfile is refused
until it is pulled. [Policy and profiles](/guides/policy-and-profiles/#pack-policy-signed-official-profiles-and-groups)
describes how a pack is verified, pinned and composed.
