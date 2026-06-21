---
title: "Machine: Use This For"
description: Scenario-led guide to mvmctl machine — pick the task you're trying to do, get the commands, and know the boundaries.
---

`mvmctl machine` is the beginner-facing way to run a real microVM: pick the task
you're doing below, copy the commands, done. Every machine boot uses the same
signed, audited, deny-all-by-default execution path as the lower-level verbs —
the `machine` group is a thinner UX over it, not a weaker one.

New to mvm? `machine run --image` needs no flake and no host Nix. Read the
[limitations page](/guides/machine-limitations/) once so you don't infer
guarantees mvm doesn't make, then come back here.

## Sandbox untrusted code

You have code — an LLM's output, a stranger's script, an unvetted binary — and
want to run it where it can't touch your machine. This is the headline use case.

```bash
mvmctl machine run --image alpine -- sh -c 'echo hi; id'
```

The guest gets **no network** (deny-all default), no host filesystem beyond what
you share, and is torn down when the command exits. To let it reach exactly one
host, narrow egress instead of opening everything:

```bash
mvmctl machine run --image alpine --allow-host api.example.com:443 -- \
  curl -sS https://api.example.com/health
```

## Run one command in a fresh image-backed VM

The `docker run --rm` shape: boot an OCI image, run a command, tear down.

```bash
mvmctl machine run --image python:3.12 -- python -c 'print(2 + 2)'
```

First run pulls and materializes the image; later runs reuse the cache when the
resolved image and policy still match. For production, pin a digest and
configure your registry trust policy.

## Keep a named machine around

When you want a machine you can boot, exec into, and stop repeatedly — a small
persistent dev box — create a named spec once and drive its lifecycle:

```bash
mvmctl machine create --name devbox --image debian:12   # persist a spec, no boot
mvmctl machine start  --name devbox                     # boot it
mvmctl machine exec   --name devbox -- bash -lc 'uname -a'
mvmctl machine shell  --name devbox                     # interactive (dev profile)
mvmctl machine stop   --name devbox                     # stop, keep the spec
mvmctl machine ls                                       # what's persisted
mvmctl machine rm     devbox --yes                      # remove the spec
```

## Give the guest a writable workspace

Share a host directory into the machine. Read-only is the default; a writable
share requires the dev profile (a sealed prod machine won't take one).

```bash
mvmctl machine run --image node:22 --profile dev --add-dir .:/work:rw -- \
  node /work/build.js
```

## Forward your SSH agent (dev-tier)

Let a dev machine use your host SSH agent for `git`/`ssh` auth **without** ever
copying a key. It forwards only your `SSH_AUTH_SOCK` socket, and is enabled
through the manifest (`[auth] ssh_agent = true`) on a dev-capable profile —
there is no `--ssh-agent` flag, by design.

```toml
# ci.toml
image = "debian:12"
profile = "dev"

[auth]
ssh_agent = true
```

```bash
mvmctl machine create --name ci --manifest ./ci.toml
mvmctl machine start  --name ci
mvmctl machine exec   --name ci -- ssh-add -l   # lists host identities, no keys copied
```

Prerequisites and the exact bounds are in
[Machine limitations § SSH-agent](/guides/machine-limitations/#ssh-agent-dev-tier-only).

## Declare a machine in a file

Instead of long flag lists, describe an image-backed machine in an
`mvm.toml` / `Mvmfile.toml` and create from it. Unknown keys are rejected, so a
typo fails fast instead of silently doing nothing.

```bash
mvmctl machine create --name app --manifest ./mvm.toml
mvmctl machine inspect app --json
```

The manifest carries image, network defaults, allow-hosts, CPU/memory, initial
memory, volumes, dev-init, and ssh-agent. See
[Manifests](/guides/manifests/) for the schema.

## Preview a portable artifact

You have a portable `.mvm` artifact and want to know if this host would admit it
— signature, hash, format, and architecture — without booting:

```bash
mvmctl machine check-artifact ./app.mvm
```

The full `machine pack` / `machine run <artifact>` round-trip is **preview, not
yet shipped** — see [Machine limitations § Portable artifacts](/guides/machine-limitations/#portable-artifacts-are-preview).
Use the lower-level [`mvmctl artifact`](/reference/cli-commands/) verbs to pack
and run today.

## See also

- [Machine command reference](/reference/cli-commands/#machine-beginner-ux) —
  every `machine` verb and flag.
- [Machine limitations & scope](/guides/machine-limitations/) — the boundaries.
- [First-Use Happy Paths](/getting-started/happy-paths/) — the same idea
  organized by audience (CLI / SDK / bundle / dev) instead of by task.
