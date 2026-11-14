---
title: Configuration file
description: Write a project mvm.toml and compose its source, sizing, network grants, and policy references.
---

`mvm.toml` is the project configuration file. It chooses a workload source
and records local machine defaults. Put it beside your project; mvm also
accepts the name `Mvmfile.toml`, but refuses both names in one directory.

Start with one file. For repeated CPU and memory settings, `include` can
apply small local launch-default files before the root file. For reusable
permissions, `[policy]` names a profile and includes groups, including
groups from installed, verified packs. **These are separate composition
paths:** manifest includes never supply a source or permissions.

## A local image-backed machine

```toml
image = "alpine:3.20"
cpus = 1
mem = "512M"
net = false
```

Save this as `mvm.toml`, then create and start a named machine:

```sh
mvmctl machine create alpine-dev --manifest ./mvm.toml
mvmctl machine start alpine-dev
mvmctl machine stop alpine-dev
```

`net = false` keeps outbound network access closed by default. A host
directory is not automatically mounted into the guest.

## What goes in the file

| Field | Purpose |
| --- | --- |
| `image` or `flake` | Choose one source: an OCI image or a Nix flake. If neither is set, the flake defaults to `.`. |
| `cpus`, `mem` | Size the local machine. `mem` is the guest memory cap. |
| `include` | Ordered relative TOML files containing only `include`, `cpus`, and `mem`. |
| `net` | Request the built-in development network preset when `true`; `false` is the default. |
| `[network].allow_hosts` | Name specific outbound destinations instead of relying on the preset. |
| `[policy].profile`, `[policy].include` | Select an authored profile and compose reusable groups or verified pack policy. |
| `[dev].volumes` | Attach explicit disk images to a persistent development machine. |

The root `profile` key selects a **flake package**, not the `--profile`
run security tier or the authored `[policy].profile`. Unknown keys are
rejected instead of silently ignored.

## Reuse launch defaults

For a project with shared resource settings, write `defaults/small.toml`:

```toml
cpus = 1
mem = "512M"
```

Then select it in the root `mvm.toml`:

```toml
image = "alpine:3.20"
include = ["defaults/small.toml"]
cpus = 2
```

Includes are processed in order, relative to the file naming them, before
the root values. Here the effective size is two CPUs and 512 MiB. An included
file can include another defaults file, but repeated files, cycles, missing
files, and paths escaping the project directory are refused. The root must
name its own `image`, `flake`, or `wasm` source when using includes. Only
`cpus` and `mem` can be inherited: network, GPU, volumes, secrets, grants,
policy selection, and other fields in a defaults file are rejected.
Signed pack image manifests remain self-contained and cannot use local
includes.

To allow one destination and reuse a policy group across projects, add
these sections to the file above after creating the
[policy group](/guides/policies/#compose-a-project-policy):

```toml
[network]
allow_hosts = ["api.github.com:443"]

[policy]
profile = "default"
include = ["./policy/api-group.toml"]
```

The network allowlist and authored policy compose; a deny in either
policy still wins. An explicit `--policy` replaces the `[policy]`
selection, but the project's `[network].allow_hosts` still applies.
Stored secret values do **not** belong in this file; project `[secrets]`
entries may name stored bindings and destinations, not plaintext values.
See [Secrets and credentials](/guides/secrets-and-credentials/).

## Source builds and host defaults

For a flake-backed project, run `mvmctl init .` to create `mvm.toml` and
`flake.nix`. The flake defines the guest contents; the manifest selects
the source and launch settings. `mvmctl machine build` discovers the file
from the current directory, and `mvmctl machine run --manifest .` runs
the built slot. The full [manifest guide](/guides/manifests/) covers
builds, slot drift, and additional fields.

Host-local defaults are a different file:
`$MVM_HOME/config/config.toml`. For example, `default_policy` there
selects a fallback launch policy; it does not impose a mandatory ceiling
on an explicit project or CLI selection. See [Policies](/guides/policies/)
for the composition and precedence rules.
