---
title: pi with MVM
description: Use the signed agent/pi policy pack for a pi workload in a microVM, and what pi needs from it that the pack does not grant by default.
---

The official registry publishes `agent/pi`, a signed policy profile for a pi
workload running in a microVM. That pack is the whole integration: pi has no
MCP client, so there is no host-side MVM tool surface to connect, and
`mvmctl plugin` emits no pi integration. On the host, pi reaches MVM the way
any program does, by running `mvmctl`; see
[Agent tool contract](/guides/agent-tool-contract/).

The pack does not confine pi's own tools when pi runs on the host. To put the
agent behind the microVM boundary it has to run in the guest; see
[Agent sandbox](/guides/agent-sandbox/).

Repository contributors run MVM runtime commands in the project builder VM, not
on the macOS development host.

## Pull the pack

```sh
mvmctl search agent/pi
mvmctl pull agent/pi
mvmctl pack registry ls
```

`pull` verifies the pack's Sigstore signature against the publisher trust
policy, checks the payload against the signed manifest, installs the pack
content-addressed, and pins the manifest digest in
`$MVM_HOME/registry/packs.lock.toml`. `agent/pi` composes only built-in
groups, so there is no second pack to pull.

## What it grants

`mvmctl policy show agent/pi` prints the merged policy and the layer each part
came from:

```toml
# layer: group `llm-apis` (built-in) (built-in)
# layer: group `github` (built-in) (built-in)
# layer: profile `agent/pi` (pack) overrides (pack)
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
```

Everything else is denied, and that includes two things pi reaches for:

```sh
mvmctl why --host api.anthropic.com:443 --profile agent/pi
mvmctl why --host generativelanguage.googleapis.com:443 --profile agent/pi
mvmctl why --host registry.npmjs.org:443 --profile agent/pi
```

- pi 0.70.6 defaults to the `google` provider. The pack admits the Anthropic
  and OpenAI APIs and binds only the Anthropic secret, so the second answer is
  a denial. Select the provider the pack covers with `--provider anthropic`.
- pi is distributed through npm, and the pack does not admit the npm registry:
  the third answer is a denial too. An image that carries pi already needs
  nothing more. One that installs it at run time needs the Node runtime group
  as well, described under [Add the npm registry](#add-the-npm-registry).

## Store the secret the pack binds

The profile binds a stored secret named `anthropic` to `api.anthropic.com`.
The name is part of the signed pack, so the secret has to be stored under it:

```sh
mvmctl secret set anthropic --provider anthropic
```

`mvmctl policy validate agent/pi --strict` reports a bound secret the store
does not hold. The guest never receives the value: it gets a placeholder in
`ANTHROPIC_API_KEY`, and the host substitutes the real key into requests to
`api.anthropic.com` only.

## Run under the pack

Select the pack with `--policy`. It lowers into the same signed
`ExecutionPlan` the equivalent `--allow-host` and `--secret` flags produce:

```sh
mvmctl run --policy agent/pi -- pi --provider anthropic -p "summarize the repo"
```

The pack is policy only. It ships no image and installs nothing, so the image
the run boots has to carry pi already; no published image or template does.

A guest booted under this pack was checked directly. It holds a placeholder in
`ANTHROPIC_API_KEY`; a request to `api.anthropic.com` carrying that placeholder
leaves the host with the stored key in its place, recorded as
`secret.substituted` in the audit chain; `api.github.com` answers; and
`registry.npmjs.org`, the Google API host and every other unlisted destination
are refused at the tunnel, each with an `egress blocked` line on the host. pi
itself has not been run inside a guest for this guide.

## Add the npm registry

`runtime/node` is a group pack, not a profile, so it cannot be passed to
`--policy`; a profile includes it. Pull it, then write a profile that extends
the agent pack and includes the group:

```sh
mvmctl pull runtime/node
```

```toml
# policy/pi.toml
description = "pi, with the npm registry for an in-guest install"
extends = "agent/pi"

[groups]
include = ["runtime/node"]
```

`mvmctl policy show ./policy/pi.toml` then lists `registry.npmjs.org:443`,
`nodejs.org:443` and `objects.githubusercontent.com:443` beside the pack's own
hosts, with a `runtime/node` layer between the built-in groups and the pack's
overrides. Select the file the same way:

```sh
mvmctl run --policy ./policy/pi.toml -- pi --provider anthropic -p "summarize the repo"
```

## Keep the pack current

```sh
mvmctl pack registry update agent/pi
mvmctl pack registry rm agent/pi
```

`update` adopts a newer published version when there is one and re-verifies
the pinned one when there is not. A reference may pin a version,
`agent/pi@1.0.0`; a version other than the one in the lockfile is refused
until it is pulled. [Policy and profiles](/guides/policy-and-profiles/#pack-policy-signed-official-profiles-and-groups)
describes how a pack is verified, pinned and composed.
