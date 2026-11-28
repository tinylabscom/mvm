---
title: Policy and profiles
description: Compose what a workload may do from reusable TOML or JSON policy groups and authored profiles, resolve it, and run it — every layer lowered into the same signed ExecutionPlan the flags produce.
---

What a workload may do — where it can connect, which stored secrets it can
use and where, which host directories it sees, which environment variables it
may be handed, and how much CPU, memory and time it gets — can be written down
once and reused, instead of retyped as flags on every run.

There are three layers:

1. **Groups**: named, reusable policy fragments, written in TOML or JSON.
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

`--policy` is repeatable, and the formats mix: each entry is a profile or a
group (runtime packs ship groups), composing over the ones before it, so the
last one takes precedence. This stacks a team template
under your own tightening without a wrapper profile:

```sh
mvmctl run --policy ./org-base.toml --policy ./team.toml --policy ./mine.json -- make test
```

That is exactly equivalent to a profile whose `extends` lists the same
references in the same order.

### Configured local defaults

Set ordered launch policies in `$MVM_HOME/config/config.toml`:

```toml
default_policy = ["agent-apis", "/etc/policy/team.toml"]
```

Selection is explicit `--plan`, otherwise repeated `--policy`, otherwise the
project's `[policy]` profile/include, otherwise `default_policy`. Project
`[network] allow_hosts` still contributes when selecting authored profiles.
Configured defaults are fallback selections, not mandatory organization
restrictions: explicit flags or a project policy replace them. Use the
existing mandatory policy/admission controls for restrictions a caller must
not replace. Malformed or unreadable configuration refuses launch rather than
silently dropping configured restrictions.

The same ordered composition applies to `run`, `machine run`, and policy
selection during persistent machine creation. Explicit local network
restrictions remain effective when an installed application's signed network
defaults are folded. A signed application ceiling cannot be widened by local
policy. This does not change the existing rule that signed network defaults
apply when no local network selection exists.

Ask one question of the resolved policy without booting anything:

```sh
mvmctl why --host api.github.com:443
mvmctl why --host api.github.com:443 --method GET --request-path /repos/org/project
mvmctl why --path ./src
```

Without `--profile` or `--plan`, `why` discovers the current project's
`mvm.toml`. A routed host with method/path rules is not a blanket allow:
pass both `--method` and `--request-path` to check one HTTP request. A tool
marked `ask` needs runtime approval and is not pre-authorized; per-tool argv
restrictions are evaluated when a call supplies argv, not by a name-only query.

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

For a single `run` or `machine run`, the project's `mvm.toml` is parsed once
for its authored policy, endpoint routes, approval backends, and secret
declarations. Editing it after policy resolution starts does not change those
choices partway through that launch. This is launch-time consistency, **not**
an atomic policy apply: unless the project is explicitly activated as below,
later launches still read authored files. Running workloads are not rolled
over by an edit.

## Committed project policy

On a Linux Firecracker host, an explicit activation commits the first policy
generation for a local flake project:

```sh
mvmctl policy activate ./my-project
```

`PROJECT` is required. Build the project's Firecracker manifest slot before
activation; this command does not build it. The slot and its current revision
must match the captured manifest's boot declaration. Image-reference and Wasm
projects are refused. HVF, libkrun, QEMU, and other backends are not supported
by this activation path; there is no automatic backend fallback.

Activation requires **whole-host quiescence**, not just an idle project. Stop
all workloads first, including paused instances. The coordinator serializes
activation against local launches and restores and refuses a live workload,
an unknown backend probe, or an untracked transient session. It does not stop
workloads for you. The separate resident `mvm-policy-coordinator` helper is
started or contacted automatically; no second daemon-start command is needed.

Generation 1 captures the parsed manifest, selected defaults, contributing
profile/group text, platform predicates, and effective policy. This initial
source format supports local policy files and built-in references, not
signed-pack policy references. Top-level manifest `include` files for launch
defaults are also refused: their mutable bytes are not captured by generation 1.
Policy profile/group includes remain part of the captured policy closure. Manifest and local policy files must satisfy
the owned regular-file checks; direct symlinks and multiply linked files are
refused. The captured closure is independently revalidated by the host owner
and its generation identity is bound into signed admission.

After activation, project launches and restores consume the committed manifest
and policy rather than staged edits. Editing a CPU ceiling or deleting a
policy selection from `mvm.toml` does not widen the committed authority.
Missing, corrupt, mismatched, or incomplete activation state refuses execution
instead of reverting to authored files. A slot rebuilt from a different boot
declaration is also refused; activation does not freeze the whole source tree
or replace normal artifact verification.

A committed `cpu_millicores` ceiling requires a CPU-share grant in the signed
plan. The entrypoint path does not yet carry that grant and therefore refuses
such a policy before boot; `max_cpus` is a separate vCPU-count ceiling.

Persistent machine starts recheck the stored generation and resource bounds.
That path refuses committed shares, environment grants, secret bindings, and
network routes that its stored spec cannot retain, as well as extra machine
routes, peers, or ports. Once any project is activated, Firecracker restore
requires the original admitted plan on disk; a missing plan is no longer
accepted as a legacy cache miss. These host-wide restore prerequisites also
matter for otherwise unactivated projects on the same host.

This is **initial activation only**, not `policy apply`, policy-file watching,
or live rollover. Repeating activation cannot publish staged changes as a new
generation. There is no supported deactivation or generation-update workflow
in this slice; do not delete coordinator state to bypass it. Ordinary projects
that have never been activated retain their existing authored-policy behavior.
`policy show`, `policy resolve`, and `why` inspect authored inputs; their output
is not proof of the generation admitted for an activated run.

The trust boundary remains a trusted Linux host enforcing policy against an
untrusted workload. This does not add malicious-host protection or expand
other backends' security guarantees.

### Observe the coordinator without a service manager

The coordinator is spawned by whichever command first needs it and left
running detached. Neither that direct launch path nor coordinator observation
requires systemd or any other service manager. Observation never starts it:

```sh
mvmctl policy coordinator
```

On Linux and macOS this connects once to the existing coordinator socket. It
reads the kernel peer PID and UID before sending a status request, requires
the peer UID to match the caller, and checks that the reply's protocol, PID,
UID, canonical home and detached lifetime agree. It reports the observed PID,
UID and home; `--json` returns those same fields. A missing home or socket,
stopped listener, unsupported platform or mismatched reply is a refusal.
A managed-lifetime self-claim is refused, not treated as verified service
provenance. No service manager is contacted.

Observation does not initialize a missing MVM home, create configuration or
signing keys, append command-audit records, or start telemetry/update checks.
The nonblocking connection and status exchange share one five-second IPC
budget; partial reads and writes cannot renew it.
This does not bound filesystem canonicalization or arbitrary OS scheduling
stalls. Status replies are limited to 4 KiB before allocating their bodies.

The report is a process observation on that connection, not service provenance.
It does not establish readiness, current authority, permission to commit,
restart supervision, reaping or survival across reboot. This diagnostic check
does not confine same-user processes or prove that a peer has not passed its
connected socket to another process. Activation and recovery keep their
existing locks and admission checks; observation grants no authority.

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
| Allows are unioned | Hosts, secrets, user-authored shares, env names and tools add up. A signed pack cannot add a host share. |
| Tool `ask` sits between | `deny` beats `ask` beats `allow` for whole-tool decisions. |
| Tool detail only narrows | A later layer may repeat or restrict the `argv`, `routes` and `secrets` an earlier layer set for a tool, never extend them; per-tool `deny` argv patterns union. An `executable` must be a normalized absolute guest path; later layers cannot add one to an existing detail or redirect it. |
| Denies are unioned, and a deny beats an allow | Anything a deny covers is removed from the result, whichever layer allowed it. The note says which layer did what. A host is compared as one identity on both sides: case, one trailing dot, IPv6 text and the `::ffff:a.b.c.d` form of an IPv4 address do not make a different host. Write an IPv6 address with a port bracketed (`[2001:db8::1]:443`); an unbracketed deny such as `2001:db8::1:443` is refused as ambiguous. Numeric spellings such as `2130706433` or `0x7f.1` are refused as allow entries. |
| Blocked network stays blocked | Once a layer sets `network.block = true`, every allowed host and route is dropped. A later `block = false` is an error, not a no-op. |
| Required groups cannot be excluded | `groups.exclude` naming a required group that is already included is an error. |
| Secret destinations only narrow | A later layer naming the same secret may list a subset of the hosts, never a host outside them. The launch then checks the result against the allow-list stored with `mvmctl secret set`, which no layer can widen. |
| A share is writable only if every layer says so | Two different host sources for one guest path is an error. |
| Signed packs cannot mount host directories | A pack's `shares.mount` entries are stripped with a note; `shares.deny` can still narrow a user-authored share. |
| Resources are ceilings | The smallest value from any layer wins, and a flag cannot exceed it. |
| Escape hatches are user-only | `env.readmit` (re-admitting a variable the hygiene denylist refuses) is honoured only in a profile from your policy directory or a path you pass. In a project or pack layer the entry is stripped with a note, never honoured. |
| Signed packs cannot import local policy | A pack-authored `extends` or group include may name an unshadowed built-in or another installed, verified pack. A filesystem path or a name resolved from your policy directory is refused, so local files cannot silently become part of a signed pack's policy. |
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

### Templates that ship their own policy

A remote template can carry its own policy. Its `template.toml` declares
the files, relative to the template directory:

```toml
[policy]
profile = "policy/base.toml"    # a profile file shipped in the template
include = ["policy/apis.toml"]  # extra groups
```

The `include` list may also name a versioned signed pack that provides a
group, for example `"runtime/python@1.0.0"`. Run
`mvmctl pull runtime/python@1.0.0` first. The template does not download the
pack as a template file, install it, or grant it trust; generation verifies the
installed pack while resolving the policy and refuses a missing or
unverifiable pack.

`mvmctl generate template <name> <dir>` downloads declared local files with
the rest of the template, copies them into the project, and writes a
`[policy]` table into the generated `mvm.toml` referencing them. Every
launch of the project then composes the template's policy with any groups
added to the generated `[policy] include` list. An explicit `--policy` replaces
the project's `[policy]` table for that launch; list every policy you want in
that invocation. Declared local paths must stay inside the template
directory, and pack references must specify an exact version. Generation
refuses — naming the template and the policy reference — when a declared
policy file or pack is missing or does not resolve,
so a broken template fails at generation time, not on the first run.

The template's policy is project content: it can tighten, and it cannot
use escape hatches. A group the template marks `required` cannot be
excluded by anything composed above it.

## Where policy comes from

The first match wins:

1. `--plan FILE`: a resolved manifest. It is mutually exclusive with every
   flag that authors policy: `--policy`, `--net`, `--network-preset`,
   `--allow-host`, `--allow-endpoint`, `--peer`, `--cpu-limit`,
   `--grants-file`, `--mount`, `--allow-env` and `--secret`.
2. `--policy NAME|PATH` (repeatable; later entries take precedence over
   earlier ones).
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

- A **path** starts with `/`, `./` or `../`, or ends in `.toml` or `.json`. A
  relative path resolves against the file that names it.
- A **name** is looked up as `<name>.toml` and then `<name>.json` in
  `$MVM_HOME/config/policy/profiles/`, failing that in `groups/`, then among
  the built-ins; a profile wins when both exist.
  Your file shadows a built-in of the same name.
- A **pack reference** is `namespace/name[@version]`. It resolves only when the
  signed pack is installed, pinned in the lockfile, and valid under the
  publisher trust policy. Pull it with `mvmctl pull namespace/name[@version]`.
  See [Pack policy](#pack-policy-signed-official-profiles-and-groups) below.

The document format is TOML by default; a `.json` extension reads the same
types as JSON, which suits policy files generated by other tools. The
resolved manifest (`policy resolve` output, read back by `--plan`) is always
JSON.

What a profile *reached from a project* declares is project content, not
yours. It can tighten, but it cannot use an escape hatch.

### Pack policy: signed profiles and groups

The pack registry source is the `mvm-packs` repository. Published legacy
`agent/` and `runtime/` packs carry keyless (Sigstore) signatures from the
`mvm-packs` workflow identity. `mvmctl search`
lists what the registry offers and `mvmctl pull ns/name[@version]` fetches a
pack: the signature is verified against the publisher trust policy, the
payload is checked file-by-file against the signed manifest, the pack is
installed content-addressed, and the exact manifest digest is pinned in a
lockfile.

An installed pack can carry its own policy documents — `pack/profile.toml`,
`pack/group.toml`, or both. A pack with a profile composes exactly where its
reference sits in the `--policy` order:

```sh
mvmctl run --policy agent/claude@1.0.1 --policy ./mine.toml -- make test
```

A pack with only a group, such as `runtime/python`, can be the root `--policy`
reference or be included by a profile's `[groups] include = ["runtime/python"]`
or a project's `[policy] include`.

An application can compose a signed pack's policy with its own groups in
`mvm.toml` without selecting the pack as its boot image:

```toml
[policy]
include = ["runtime/python", "./policy/app.toml"]
```

Pull and pin the pack before launching the application. The installed pack is
verified again when the policy loads; an application group can deny a host the
pack allows, and that deny wins. A generated template can use the same
`[policy]` table to expose its shipped policy to the application.

`pull` follows pack references in the signed profile, verifying and pinning
each dependency; the policy-only `agent/claude@1.0.1` includes `runtime/python`.
If a root pack also declares a signed workload image, `run` and `machine run`
select that image when no explicit boot source was supplied. The image's
`mvm.toml`, `flake.nix`, and `flake.lock` are verified as signed payload; the
pack's exact version and manifest digest are bound into the execution plan
and rechecked at host admission. An explicit source takes precedence and the
pack contributes policy only.
[Author and publish a signed pack](/guides/pack-authoring/) covers writing
one, and the client guides under
[AI agent integration](/guides/ai-agent-integration/) cover the published
agent packs.

A pack layer is verified every time it loads: the signature is re-checked
against the publisher policy and the manifest digest against the lockfile,
so a tampered cache entry cannot reopen what the pack denied. It composes
under the same rules as every non-user layer — denies stick, resource
bounds are ceilings, and `env.readmit` and `shares.mount` entries the pack
carries are stripped with notes, never honoured.

With no publisher policy file, the exact current `mvm-packs` publish workflow
identity is trusted for `agent/` and `runtime/`. The former `mvm-templates`
identity is not trusted by the built-in policy. The reserved `mvm/` namespace
trusts only the exact current workflow identity, never a wildcard; official
packs also require the independently signed fresh MVM revocation feed.
To make your own trust decision — pin other
publishers, or refuse packs outright — write
`$MVM_HOME/registry/publishers.toml`; it
replaces the default wholesale, and a malformed file fails closed rather
than silently widening trust. The built-in historical digest exception and
cutoff do not constrain explicit operator policy. One publisher may use the
`*` namespace to accept a signing identity for non-reserved namespaces, and an exact
`namespace = ...` entry always wins over the wildcard.

The repository rename changed its workflow identity. Packs signed under the
former repository identity fail closed under the built-in default; re-pull a
version published under the current workflow identity. The built-in policy
does not automatically trust both identities.

## Commands

| Command | What it does |
| --- | --- |
| `mvmctl policy show [PROFILE...] [--format toml\|json\|plan]` | The merged policy, as TOML with its layers, as JSON with provenance for every item, or as the grants, egress rules, routes and bindings the signed plan would carry. Several profiles compose in order, the last taking precedence. Without `PROFILE`, it reads the project's `[policy]` (`--project DIR`, default `.`). |
| `mvmctl policy resolve [PROFILE...] [-o FILE]` | Write the resolved manifest that `run --plan` accepts. Several profiles compose in order, the last taking precedence. |
| `mvmctl policy validate [PROFILE\|PATH...] [--strict]` | Check the profiles a launch would compose, or a single profile or group file. `--strict` turns every note into an error and checks each bound secret against the store. |
| `mvmctl policy diff A B [--json]` | What each side allows or denies that the other does not. |
| `mvmctl policy groups [--json]` | Built-in and user groups and profiles. |
| `mvmctl why --host H[:P] [--method METHOD --request-path PATH] \| --path P \| --secret S [--profile PROFILE... \| --plan FILE] [--json]` | Resolve one deterministic allow/deny answer without starting a VM. For routed hosts, include method and path to check the endpoint rule. Several profiles compose in order, the last taking precedence. |

`--backend KIND` on `show`, `resolve`, `validate` and `diff` matches `[[when]]`
blocks against a backend other than the host's default.

## Schema

Profiles, groups and the resolved manifest have a JSON Schema generated from
the Rust types they are parsed into. See the
[policy schema reference](/reference/policy-schema/). Unknown keys are refused
everywhere, so a misspelt restriction is an error rather than a silently
missing one.

## Tool-specific policy

MVM does not govern which tools an application calls. Authored profiles and
groups, resolved manifests, and local MCP startup reject legacy `[tools]`
sections rather than silently discarding their restrictions. Signed plans
with retired `tools` or `tool_policy` fields, bundles with `[tool]`, and
persisted machines with tool rules refuse to start. Grant
ingress, egress and other permissions through system-level policy instead.
Tool-specific routes and secrets are not converted into broader VM grants.

## Not yet

- Pack profiles require an installed, pinned, publisher-verified signed pack;
  use `mvmctl pull namespace/name` before selecting one.
- Endpoint routes from a policy are refused on a persistent machine
  (`machine run --name`), the same as `--allow-endpoint`: they would not be
  recorded beside the machine's spec. `machine create` refuses a policy that
  binds secrets, shares or re-admitted variables for the same reason.
- `net = true` in `mvm.toml` still reaches only `machine create`. Name
  destinations in `[network] allow_hosts` to have every verb apply them.
