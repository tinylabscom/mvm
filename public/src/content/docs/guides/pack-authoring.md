---
title: Author and publish a signed pack
description: Write a policy pack as a group or a profile, check it locally, publish it through the mvm-templates signing workflow, and decide which publishers your hosts trust.
---

A pack is a named, versioned, signed bundle of policy and, optionally, a
buildable workload image. It carries a policy group, a policy profile, or both,
under a `namespace/name@version` reference,
and `mvmctl` verifies its signature every time it is pulled and every time a
policy that names it is loaded. The official registry is the
[`mvm-templates`](https://github.com/tinylabscom/mvm-templates) repository.

This guide uses two published packs as its worked examples: `runtime/node`, a
group, and `agent/codex`, a profile that includes it. For the policy language
itself, see [Policy and profiles](/guides/policy-and-profiles/).

## What a pack contains

A pack source is a directory in `mvm-templates`:

```text
pack-sources/runtime/node/
├── pack.toml          version and description
└── pack/
    └── group.toml     the policy document
```

`pack.toml` is the pack's identity. The namespace and name come from the two
directory levels, and the file supplies the rest:

```toml
version = "1.0.0"
description = "Node.js runtime policy: the npm registry, Node downloads, and GitHub release assets for native-module prebuilds."
```

- The version is a strict semantic version such as `1.0.0`.
- The description must not be empty. It is what `mvmctl search` prints and
  matches against.
- The registry build accepts a namespace or name made of lowercase letters,
  digits, `_` and `-`, starting with a letter or digit. The client accepts the
  same set plus `.`, up to 64 characters, and requires the last character to be
  a letter or digit too.

Everything under `pack/` is the signed payload. Policy loading reads
`pack/group.toml` and `pack/profile.toml`; image-bearing packs additionally
declare an `mvm.toml` and its neighboring Nix source and lock.

## An image-bearing pack

An optional `[image]` table in `pack.toml` names a signed workload manifest:

```toml
version = "1.1.0"
description = "Python runtime policy and image"

[image]
manifest = "pack/image/mvm.toml"
```

The payload must include `pack/image/mvm.toml`, `pack/image/flake.nix`, and
`pack/image/flake.lock`. The image manifest may contain only
`schema_version`, `flake`, `profile`, and `name`; `flake = "."` (or no `flake`
field) selects only the neighboring signed source. The publisher workflow
and client refuse missing source files, unlisted payload, external flake
selectors, and host-grant fields. An image source never authorizes a host
directory share or a guest network device.

When `run` or `machine run` names an installed image-bearing pack with
`--policy` and no explicit boot source, the signed image is built and booted.
The exact pack reference and manifest digest enter the signed execution plan
and chain-signed audit record. Host admission reopens the installed pack under
the current lock and publisher trust before boot. An explicit image, manifest,
flake, deployment, or runtime source keeps its own boot-source precedence;
the pack still contributes its policy. The separate `machine run --entrypoint`
boot path refuses an image-bearing pack; use the ordinary machine run path.

## A group pack

A group is a reusable fragment: hosts, secret bindings, shares, environment
names, resource ceilings. This is `runtime/node`'s `pack/group.toml`, whole:

```toml
description = "Hosts a Node.js workload needs: npm packages and tarballs, Node runtime downloads, and GitHub release assets for prebuilt native modules."

[network]
allow = [
  "registry.npmjs.org:443",
  "nodejs.org:443",
  "github.com:443",
  "objects.githubusercontent.com:443",
]
```

A group pack is used by including it in a profile's `[groups] include` or a
project's `[policy] include`; `--policy runtime/node` also selects it directly
as the root policy. It does not need a `pack/profile.toml` for that use.

## A profile pack

A profile composes groups and adds its own policy under `[overrides]`. This is
`agent/codex`'s `pack/profile.toml`, whole:

```toml
description = "What an OpenAI Codex agent workload may reach and which stored secrets it may use. The Codex CLI ships through npm, so the Node runtime pack composes underneath."

[groups]
include = ["llm-apis", "github", "runtime/node"]

[[overrides.secrets.bind]]
name = "openai"
hosts = ["api.openai.com"]
```

A profile pack is what `--policy agent/codex`, a profile's `extends`, and a
project's `[policy] profile` select.

Three things in that file are worth copying:

- **It names secrets and destinations, never values.** `name = "openai"` is a
  name in the operator's own secret store. Whoever runs the pack stores a
  secret under exactly that name; a run without it stops before anything boots.
- **It includes another pack by reference.** `runtime/node` resolves on the
  consumer's host from their own installed, verified copy. `mvmctl pull`
  follows pack references in the signed profile, verifying and pinning each
  dependency under the consumer's publisher trust policy.
- **Its secret binding is under `[overrides]`.** A top-level `[secrets]` or
  `[network]` table is the group form and does not parse in a profile.

## What a pack cannot do

A pack layer composes under the same rules as every layer you did not write
yourself, plus one of its own:

- **It cannot import local policy.** A pack's `extends` or group include may
  name a built-in or another installed, verified pack. A filesystem path, or a
  name that resolves from the consumer's policy directory, is refused.
- **It cannot use an escape hatch.** An `env.readmit` entry in a pack is
  stripped with a note, never honoured.
- **It cannot mount a host directory.** `shares.mount` entries in a pack are
  stripped with a note; `shares.deny` may still narrow a share the user added.
- **It cannot undo a deny.** Denies union across layers and beat any allow, a
  blocked network stays blocked, and resource values are ceilings.
- **It cannot widen a stored secret.** A binding may only narrow the
  destination list recorded with `mvmctl secret set`.

The [merge rules](/guides/policy-and-profiles/#merge-rules) give each of these
in full.

## Check it before you publish

From a checkout of `mvm-templates`, validate each document with the client
that will load it:

```sh
mvmctl policy validate ./pack-sources/runtime/node/pack/group.toml
mvmctl policy validate ./pack-sources/agent/codex/pack/profile.toml
```

A profile that includes other packs resolves them from your own lockfile.
`mvmctl pull` fetches its published dependencies; a pack it names that is not
published yet has nothing to resolve against until it is. For a profile,
`mvmctl policy show` on the same path prints the merged result with the layer
each line came from, which is the quickest way to see that it grants what you
meant and nothing more. Add `--strict` to `validate` to turn every note into
an error; it also checks each bound secret against your own store, so it fails
for a secret you have not stored.

## Publish

Open a pull request against `mvm-templates` that adds or changes a directory
under `pack-sources/`. Merging to `main` runs `.github/workflows/publish.yml`,
which:

1. builds a manifest for each source pack, listing every payload file with its
   SHA-256 digest and size;
2. signs each manifest keyless with `cosign sign-blob`, under the workflow's
   GitHub OIDC identity, and writes the Sigstore bundle beside it;
3. regenerates the registry index, `packs/index.json`;
4. checks the result with `scripts/validate-packs.py`;
5. commits the published layout under `packs/`.

```text
packs/index.json
packs/runtime/node/1.0.0/manifest.json
packs/runtime/node/1.0.0/manifest.sigstore.json
packs/runtime/node/1.0.0/files/pack/group.toml
```

The manifest is the signed object. For `runtime/node@1.0.0` it is:

```json
{
  "description": "Node.js runtime policy: the npm registry, Node downloads, and GitHub release assets for native-module prebuilds.",
  "files": [
    {
      "path": "pack/group.toml",
      "sha256": "8048340a8fb7fcb294031cc2373937934b6f713d0da952652d9ea386d6d019ec",
      "size": 284
    }
  ],
  "reference": "runtime/node@1.0.0",
  "schema_version": 1
}
```

**A published version is immutable.** Change a source without changing its
version and the build stops, naming the pack and telling you to bump the
version in `pack.toml`. Publish a fix as a new version; consumers move to it
with `mvmctl pack registry update`.

The same check the workflow runs is available in a checkout:

```sh
python3 scripts/validate-packs.py
```

It validates the published `packs/` tree, not `pack-sources/`: every manifest
field, each file's digest and size, and that a signature bundle sits beside
each manifest. It does not verify a signature; `mvmctl pull` does.

## What a consumer does

```sh
mvmctl search node
mvmctl pull runtime/node
mvmctl pack registry ls
```

`pull` downloads the manifest, the bundle and each declared file, verifies the
signature against the publisher trust policy, checks every file against the
manifest, installs the pack content-addressed under `$MVM_HOME/cache/registry-packs/`,
and pins the manifest digest in `$MVM_HOME/registry/packs.lock.toml`:

```toml
schema_version = 1

[[packs]]
reference = "runtime/node@1.0.0"
manifest_sha256 = "e10d2c7f070e00a1b5d8c713568c0aebe608cc4e346c091a4cb25057ffd25bd3"
```

The same verification runs again on every load. A cached file changed after
installation no longer matches the manifest, and the pack is reported as not
installed until `mvmctl pull` restores it.

## Decide who may publish

With no trust policy file, `mvmctl` trusts exactly one signing identity, in
every namespace: the official registry's publish workflow.

```text
https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main
```

under the issuer `https://token.actions.githubusercontent.com`. To make your
own decision, write `$MVM_HOME/registry/publishers.toml`. It replaces the
default wholesale. This one keeps the official workflow for `runtime` packs
only:

```toml
schema_version = 1

[[publishers]]
namespace = "runtime"
issuer = "https://token.actions.githubusercontent.com"
accepted_identities = [
  "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main",
]
```

With that file in place `mvmctl pull runtime/go` succeeds and
`mvmctl pull agent/pi` is refused: `no trusted publisher is configured for
namespace agent`. An entry with `namespace = "*"` applies to every namespace
that has no entry of its own, and an exact entry wins over it. A pack signed
by an identity the entry does not list is refused with both identities in the
error. A file that does not parse fails closed: nothing verifies, and nothing
that names a pack loads, until it is fixed.

## Serve packs from your own registry

`MVM_PACK_REGISTRY` replaces the registry base URL. `mvmctl` reads
`packs/index.json` and the per-version files beneath that base, over HTTPS or
from a `file://` path:

```sh
MVM_PACK_REGISTRY=file:///srv/mvm-packs mvmctl search
MVM_PACK_REGISTRY=file:///srv/mvm-packs mvmctl pull runtime/node
```

A mirror of the official `packs/` tree verifies under the default trust
policy, because the signatures are unchanged. Packs you sign yourself need
your signing identity in `publishers.toml`, and they need the Sigstore bundle
format cosign v3 writes, which is what the official workflow pins.

The index is a small JSON document, and unknown fields in it are refused:

```json
{
  "schema_version": 1,
  "packs": [
    {
      "namespace": "runtime",
      "name": "node",
      "description": "Node.js runtime policy: the npm registry, Node downloads, and GitHub release assets for native-module prebuilds.",
      "versions": ["1.0.0"]
    }
  ]
}
```

## Limits

- A pack always carries policy and may declare a signed workload image. A
  policy-only pack installs nothing in a guest; an image-bearing pack selects
  its image only when named by `--policy` and no explicit boot source
  was supplied.
- `mvmctl pull` follows signed profile dependencies. Cycles, conflicting
  versions, more than 128 packs, or an unpublished dependency stop the pull.
  Packs already installed before a later dependency fails remain pinned, but a run
  cannot load a missing dependency.
- A `[tools]` section in a pack composes like any other, and has the
  enforcement limits listed under
  [Not yet](/guides/policy-and-profiles/#not-yet).
- The official registry signs on `main` only. A pack on a branch or in a fork
  has no signature the default trust policy accepts.
