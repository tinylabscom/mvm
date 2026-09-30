---
title: Policy and profiles
description: Compose what a workload may do from reusable TOML policy groups and authored profiles, resolve it, and run it — every layer lowered into the same signed ExecutionPlan the flags produce.
---

What a workload may do — where it can connect, which stored secrets it can
use and where, which host directories it sees, which environment variables it
may be handed, and how much CPU, memory and time it gets — can be written down
once and reused, instead of retyped as flags on every run.

There are three layers:

1. **Groups**: named, reusable TOML fragments.
2. **Profiles**: compose groups and other profiles, with platform conditions
   and overrides.
3. **The resolved manifest**: the merged result, which becomes the signed
   `ExecutionPlan`.

```sh
mvmctl policy show agent-apis                 # what a profile allows, layer by layer
mvmctl run --policy agent-apis -- claude -p "summarize the repo"
mvmctl policy resolve agent-apis -o agent.json
mvmctl run --plan agent.json -- claude -p "summarize the repo"
```

Ask one question of the resolved policy without booting anything:

```sh
mvmctl why --host api.github.com:443
mvmctl why --path ./src
mvmctl why --tool shell --profile agent-apis
```

Without `--profile` or `--plan`, `why` discovers the current project's
`mvm.toml`. Host, path and secret answers reflect enforced policy. Tool policy
is authored ahead of its runtime mediation, so tool answers explicitly say
that the rule is not enforced yet.

Not to be confused with `--profile restrictive|standard|dev|permissive`, the
run's [security tier](/guides/policy-profiles/). That flag already existed, so
authored policy uses `--policy`. The two combine: the tier still refuses shares
or env a policy asks for when the tier forbids them.

## How a policy reaches the plan

A resolved policy is lowered into exactly the values the launch flags carry:
`--allow-host`, endpoint routes, `--secret`, `--mount`, `--allow-env`,
`--cpu-limit` and `--timeout`. From there it goes through the same steps every
launch goes through: grant resolution, secret binding, plan synthesis, signing,
and admission. A profile and the equivalent flags therefore produce the same
signed plan. A test holds that true by admitting both and comparing the plans.

Nothing about a policy is trusted on its own authority. `--plan FILE` accepts a
resolved manifest, not a plan: the file is re-validated when it is read, and
admission synthesizes and signs the plan itself. A file that carries an
execution plan or a signature is refused.

## Groups

```toml
# ~/.mvm/config/policy/groups/team-apis.toml
description = "Our internal APIs"
required = false        # true: once included, no profile below may exclude it

[network]
allow = ["api.internal.example:443", "metrics.internal.example:8443"]
deny  = ["*.staging.internal.example"]   # beats any allow, from any layer
# block = true                           # no egress at all; nothing below can undo it

[[network.routes]]                       # method and path rules at one destination
id = "github-read"
host = "api.github.com"
intercept = true
rules = [{ method = "GET", path = "/repos/acme/**", outcome = "allow" }]

[[secrets.bind]]                         # stored with `mvmctl secret set`
name = "github"
hosts = ["api.github.com"]               # may only narrow the stored allow-list

[[shares.mount]]
host = "../fixtures"                     # relative to this file
guest = "/data/fixtures"
writable = false

[shares]
deny = ["/home"]                         # no share may come from here

[env]
allow = ["APP_MODE", "RUST_LOG"]         # once any layer lists names, --env is confined to them
deny  = ["DEBUG"]
# readmit = ["LD_PRELOAD"]               # escape hatch: user-authored profiles only

[tools]                                  # recorded, not yet enforced
allow = ["git"]

[resources]                              # every value is a ceiling; the smallest wins
cpu_millicores = 1500
wall_clock_secs = 900
max_cpus = 4
max_memory = "4G"
```

### Built-in groups

`mvmctl policy groups` lists them, together with your own:

| Group | What it allows |
| --- | --- |
| `registries` | npm, crates.io and PyPI, with their download hosts. The same hosts as `--network-preset registries`. |
| `github` | `github.com` and `api.github.com`. |
| `llm-apis` | `api.anthropic.com` and `api.openai.com`. |
| `offline` | Blocks the network. Marked `required`. |

A test checks that these hosts match the maintained network presets exactly.

## Profiles

```toml
# ~/.mvm/config/policy/profiles/agent.toml
description = "Our coding agent"
extends = "agent-apis"            # or a list, applied in order: ["agent-apis", "./base.toml"]

[groups]
include = ["team-apis", "registries"]
exclude = ["github"]              # drop a group a parent included (not a required one)

[[when]]                          # applies only where every listed predicate matches
os = "macos"                      # linux | macos
arch = ["aarch64"]                # x86_64 | aarch64
backend = ["hvf", "libkrun"]      # the run's --hypervisor, or the host's default
include = ["registries"]
[when.overrides.resources]
max_memory = "8G"

[overrides.network]               # this profile's own policy, applied after its groups
allow = ["docs.example.com"]
```

Built-in profiles:

| Profile | What it is |
| --- | --- |
| `default` | Allows no network, secrets or shares. The base the others extend. |
| `dev-network` | `default` plus `registries`. |
| `agent-apis` | `default` plus `llm-apis` and `github`. |
| `offline` | `default` plus `offline`. |

### Resolution order

- A profile's parents (`extends`) come first, in order, depth first. A profile
  reached twice (a diamond) is applied once.
- The groups every profile in the chain selects are gathered into one set and
  applied first, in the order they were included.
- Then each profile's matching `[[when]]` blocks and its `[overrides]` follow,
  parents before children.
- A cycle is an error that names the whole loop.
- An `extends` chain deeper than ten levels is an error.

### Merge rules

These are the security contract of composition:

| Rule | Effect |
| --- | --- |
| Allows are unioned | Hosts, secrets, shares, env names and tools from every layer add up. |
| Denies are unioned, and a deny beats an allow | Anything a deny covers is removed from the result, whichever layer allowed it. The note says which layer did what. |
| Blocked network stays blocked | Once a layer sets `network.block = true`, every allowed host and route is dropped. A later `block = false` is an error, not a no-op. |
| Required groups cannot be excluded | `groups.exclude` naming a required group that is already included is an error. |
| Secret destinations only narrow | A later layer naming the same secret may list a subset of the hosts, never a host outside them. The launch then checks the result against the allow-list stored with `mvmctl secret set`, which no layer can widen. |
| A share is writable only if every layer says so | Two different host sources for one guest path is an error. |
| Resources are ceilings | The smallest value from any layer wins, and a flag cannot exceed it. |
| Escape hatches are user-only | `env.readmit` (re-admitting a variable the hygiene denylist refuses) is honoured only in a profile from your policy directory or a path you pass. A project's profile or group is refused, and so will be a pack's. |
| Route rules cannot be extended | A route a later layer declares for a destination an earlier layer already routes is an error: composition cannot add rules to someone else's route. |

Every error names the file, the layer and the offending key:

```text
/home/me/.mvm/config/policy/profiles/leaky.toml: profile `leaky` overrides: `network.block`: cannot turn the network back on: group `offline` (built-in) blocked it
```

### Flags on top of a policy

Flags are the last, most specific layer. They follow the same rules:

- `--allow-host` adds to the policy's allow-list and cannot reach a denied host.
- `--net`, `--network-preset` and `--allow-endpoint` cannot reopen a blocked
  network. Under a deny list, `--net` and `--network-preset` are refused; name
  the hosts with `--allow-host` instead.
- `--secret NAME:HOSTS` may only narrow a secret the policy binds, and cannot
  bind a denied one. Nor can the project's `mvm.toml` `[secrets]` table.
- `--cpu-limit` and `--timeout` apply only when tighter than the policy's.
- `--cpus` and `--memory` must fit within `max_cpus` and `max_memory`.
- `--mount` cannot come from a denied source.
- `--env` must name an allowed variable when the policy lists any.

## Where policy comes from

The first match wins:

1. `--plan FILE`: a resolved manifest. It is mutually exclusive with every
   flag that authors policy: `--policy`, `--net`, `--network-preset`,
   `--allow-host`, `--allow-endpoint`, `--peer`, `--cpu-limit`,
   `--grants-file`, `--mount`, `--allow-env` and `--secret`.
2. `--policy NAME|PATH`.
3. The project's `mvm.toml` (the `--manifest` file, or the one in a local
   `--flake` directory):

   ```toml
   [policy]
   profile = "agent-apis"            # a name or a path relative to mvm.toml
   include = ["./policy/extra.toml"] # extra groups

   [network]
   allow_hosts = ["api.example.com"] # the project's own needs
   ```

4. Nothing: the run behaves exactly as its flags say.

`--policy` replaces the project's `[policy]` table. The project's
`[network] allow_hosts` still applies on top of it, as a project layer:
allowed hosts union, and a block or deny from the profile still wins.

This resolution is the same for every verb that names a project:
`mvmctl run`, `mvmctl machine run`, `mvmctl machine create` and
`mvmctl machine start --manifest`. So "add it to `mvm.toml`" is the same
remedy whichever verb runs the workload. `machine create` and
`machine start --manifest` record the resolved network and resource grants
in the machine's spec. A spec cannot yet hold secrets, shares, re-admitted
variables or endpoint routes, so a policy that carries any of those is
refused there instead of being half applied.

A reference is read three ways:

- A **path** starts with `/`, `./` or `../`, or ends in `.toml`. A relative
  path resolves against the file that names it.
- A **name** is looked up in `$MVM_HOME/config/policy/profiles/` (or
  `groups/`), then among the built-ins. Your file shadows a built-in of the
  same name.
- A **pack reference** is `namespace/name[@version]`. It is parsed and refused
  for now: signed packs are not yet supported.

What a profile *reached from a project* declares is project content, not
yours. It can tighten, but it cannot use an escape hatch.

## Commands

| Command | What it does |
| --- | --- |
| `mvmctl policy show [PROFILE] [--format toml\|json\|plan]` | The merged policy, as TOML with its layers, as JSON with provenance for every item, or as the grants, egress rules, routes and bindings the signed plan would carry. Without `PROFILE`, it reads the project's `[policy]` (`--project DIR`, default `.`). |
| `mvmctl policy resolve [PROFILE] [-o FILE]` | Write the resolved manifest that `run --plan` accepts. |
| `mvmctl policy validate [PROFILE\|PATH] [--strict]` | Check a profile, or a single profile or group file. `--strict` turns every note into an error, refuses the unenforced `[tools]` section, and checks each bound secret against the store. |
| `mvmctl policy diff A B [--json]` | What each side allows or denies that the other does not. |
| `mvmctl policy groups [--json]` | Built-in and user groups and profiles. |
| `mvmctl why --host H[:P] \| --path P \| --tool T \| --secret S [--profile PROFILE \| --plan FILE] [--json]` | Resolve one deterministic allow/deny answer without starting a VM. |

`--backend KIND` on `show`, `resolve`, `validate` and `diff` matches `[[when]]`
blocks against a backend other than the host's default.

## Schema

Profiles, groups and the resolved manifest have a JSON Schema generated from
the Rust types they are parsed into. See the
[policy schema reference](/reference/policy-schema/). Unknown keys are refused
everywhere, so a misspelt restriction is an error rather than a silently
missing one.

## Not yet

- `[tools]` is parsed, merged and shown, but nothing enforces it.
- Pack profiles (`namespace/name`) are refused.
- Endpoint routes from a policy are refused on a persistent machine
  (`machine run --name`), the same as `--allow-endpoint`: they would not be
  recorded beside the machine's spec. `machine create` refuses a policy that
  binds secrets, shares or re-admitted variables for the same reason.
- `net = true` in `mvm.toml` still reaches only `machine create`. Name
  destinations in `[network] allow_hosts` to have every verb apply them.
