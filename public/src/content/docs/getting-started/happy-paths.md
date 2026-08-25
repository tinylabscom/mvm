---
title: First-Use Happy Paths
description: Three-command paths to get a microVM running for each mvm audience.
---

mvm has six primary audiences. Each one has a **three-command happy
path** that takes you from "I have a thing to run" to "it's running
under mvm." Pair each path with `mvmctl doctor --workflow <name>` to
preflight only the host requirements that matter for your audience —
nothing more, nothing less.

| Audience | Preflight | What you're doing |
|---|---|---|
| [CLI user with an OCI image](#cli-image-user) | `--workflow cli-run` | Run a command in a transient image-backed microVM. |
| [CLI user with a flake](#cli-user) | `--workflow cli-run` | Boot a microVM from a Nix flake. |
| [Python SDK user](#python-sdk) | `--workflow python-sdk` | Run a `@mvm.app()`-decorated Python script. |
| [TypeScript / Node SDK user](#typescript-sdk) | `--workflow typescript-sdk` | Run an `mvm.app()` TypeScript app. |
| [Prebuilt bundle operator](#bundle-run) | `--workflow bundle-run` | Launch a signed `.mvmpkg` artifact. |
| [Interactive shell user](#dev-shell) | `--workflow dev-shell` | Boot a dev-tier image and drop into an interactive shell. |

The preflight filter (plan 74 W5 / ADR-017 §1) only fails on missing
prerequisites your workflow actually needs. A bundle operator no
longer sees a "missing `cargo`" failure they don't care about; an
interactive-shell user no longer needs host rustup.

## <a id="cli-image-user"></a>CLI user with an OCI image

You have an OCI image reference and want to run one command in a fresh
microVM without writing a flake or installing host Nix.

```bash
mvmctl doctor --workflow cli-run                # preflight
mvmctl run --image alpine -- uname -a           # pull/cache, boot, run, tear down
mvmctl image inspect alpine                     # inspect cached provenance
```

The first run may pull and materialize the image. Subsequent runs reuse the
cache when the resolved image and policy inputs still match. Production image
runs should use digest-pinned refs and the existing OCI policy verification
path.

For the higher-level `mvmctl machine` workflow map, see
[Machine use cases](/guides/machine-use-cases/). For explicit network, volume,
macOS, GPU, and architecture limits, see
[Machine limitations](/guides/machine-limitations/).

**Failure recovery:**

- `image verification failed` → use a digest-pinned image and configure the OCI
  policy expected by your environment.
- `host nix not required` errors → none expected. Image-backed one-shot runs do
  not require host Nix.
- Network failures from inside the guest → current one-shot image networking is
  governed by the runtime network policy. The planned `machine` UX will expose
  a simpler explicit `--net` / `--allow-host` surface.

## <a id="cli-user"></a>CLI user with a flake

You have a `flake.nix` (or want to scaffold one) and want a microVM
booted from it.

```bash
mvmctl doctor --workflow cli-run                # preflight
mvmctl machine run --flake . --cpus 2 --memory 1024      # build + boot
mvmctl machine stop --all                                     # tear down
```

The first run downloads the builder VM image (or builds it from a
source checkout); subsequent runs reuse the warm builder. Skip the
`--cpus` / `--memory` flags to get the defaults from
`~/.mvm/config.toml`.

**Failure recovery:**

- `host nix not required` errors → none expected. mvm's builder VM
  owns Nix; the host doesn't need it.
- `skipped — dev VM not running; run mvmctl bootstrap to verify` →
  that's just doctor telling you tool checks were skipped because the
  builder VM is asleep. It's not a failure; `mvmctl machine run` boots
  it on demand.
- `disk space < N GiB` → free space on `~/.mvm/` (default cache
  location); `mvmctl cache info` shows what's there.

## <a id="python-sdk"></a>Python SDK user

You have a Python file with an `@mvm.app()` decorator. mvm compiles
the script to an artifact, builds the rootfs, and exposes it as a
callable function.

```bash
mvmctl doctor --workflow python-sdk                              # preflight
mvmctl build compile my_app.py --out /tmp/my-app                 # compile (static parse)
echo '[[], {"name":"ari"}]' | \
  mvmctl machine run --entrypoint --flake /tmp/my-app            # build + boot + call → "hello ari"
```

`mvmctl build compile` parses the decorator statically; user code does not
execute on the host (only inside the microVM). `mvmctl machine run --entrypoint`
invokes the baked function, taking its arguments as an `[args, kwargs]` JSON
payload on stdin (empty ⇒ `[[], {}]`). See
[SDK guide](/guides/sdk/) for the decorator surface.

**Failure recovery:**

- `app_deps_gate refused` (prod profile) → CVE finding in your
  dependencies' sealed volume. `mvmctl deps inspect <vol>` shows
  the offending entries; `--dev` admits high-severity findings for
  local iteration.
- `compile error: missing @mvm.app() decorator` → the file must
  declare exactly one decorated function.

## <a id="typescript-sdk"></a>TypeScript / Node SDK user

Same shape as the Python flow with a `.ts` (or `.js`) entry file.

```bash
mvmctl doctor --workflow typescript-sdk                          # preflight
mvmctl build compile my-app.ts --out /tmp/my-app                 # compile (static parse)
echo '[[], {"name":"ari"}]' | \
  mvmctl machine run --entrypoint --flake /tmp/my-app            # build + boot + call → "hello ari"
```

The preflight specifically checks the local TypeScript runner
(`bun`, `tsx`, or `deno`) — pick the one your project uses. `doctor
--workflow typescript-sdk` flags it if none of them are available.

**Failure recovery:**

- `no TypeScript runner found` → install one of `bun`, `tsx`, or
  `deno`. mvm picks whichever is on `$PATH`.

## <a id="bundle-run"></a>Prebuilt bundle operator

You're not building anything — you have a signed `.mvmpkg` artifact
to launch.

```bash
mvmctl doctor --workflow bundle-run             # preflight (no host rust needed)
mvmctl machine check-artifact ./my-app.mvm   # verify the signed artifact before launch
mvmctl machine stop --all                                     # tear down
```

`bundle-run` doctor scope explicitly drops `prerequisites` and
`tools` — a missing host `cargo` or builder-VM Nix doesn't block
bundle launches. The platform + security + disk-space checks
remain.

**Failure recovery:**

- `bundle signature invalid` → the `.mvmpkg`'s manifest signature
  didn't match the local trust store. Source bundles from a
  trusted publisher; `mvmctl bundle fetch <path>` exits non-zero
  on mismatch without launching.
- `bundle pin missing` (audit-chain admission) → the supervisor's
  signed-plan path failed to find a matching `PlanArtifact`. Pull
  a fresh copy from the publisher.

## <a id="dev-shell"></a>Interactive shell user

You want a shell inside a microVM — for building, testing, or just
exploring. There's no standalone dev VM to boot into anymore: the
builder VM is headless (it only exists to run `nix build` on your
behalf), so an interactive shell means booting a dev-tier *workload*
and attaching your terminal to it.

```bash
mvmctl doctor --workflow dev-shell              # preflight (no host rust needed)
mvmctl machine run --image alpine -it -- /bin/sh  # boot + drop into shell
# inside the shell: do work; exit / Ctrl+D tears the VM down
```

`machine run -it` boots a fresh transient microVM and is foreground-only
— exiting the shell tears the VM down, the same as any other transient
`machine run`. For a shell you can leave running and re-enter later, use
a persistent machine instead: `mvmctl machine create devbox
--image alpine`, then `mvmctl machine start devbox` and `mvmctl machine
shell devbox`.

**Failure recovery:**

- `skipped — dev VM not running; run mvmctl bootstrap to verify` →
  only relevant when your source is `--flake` (an OCI `--image` run
  pulls the image directly and never touches the builder VM);
  `mvmctl bootstrap` pre-fetches the builder VM image, or builds it
  locally from a source checkout where the in-repo flakes are always
  preferred over published artifacts.
- Shell exits immediately with no output → `mvmctl machine logs
  <name>` shows the kernel/init transcript; pass `--name` on the run
  so you have a name to look it up by.

## See also

- [`mvmctl doctor`](/reference/cli-commands/#doctor) — the full
  diagnostic command, including the `--workflow` flag added by
  plan 74 W5.
- [Quick Start](/getting-started/quickstart/) — the broader
  feature tour.
- [Your First MicroVM](/getting-started/first-microvm/) — write a
  Nix flake from scratch.
- [SDK guide](/guides/sdk/) — the Python and TypeScript decorator
  surface in detail.
- [Sandboxed Exec](/guides/exec/) — one-shot transient microVMs
  for `docker run --rm`-style use.
- [Machine use cases](/guides/machine-use-cases/) — scenario-led
  `mvmctl machine` workflows.
- [Machine limitations](/guides/machine-limitations/) — explicit
  backend and feature limits for machine UX.
