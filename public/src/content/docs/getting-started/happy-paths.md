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
| [`mvmctl dev` user](#dev-shell) | `--workflow dev-shell` | Drop into a builder-VM shell for tinkering. |

The preflight filter (plan 74 W5 / ADR-050 §1) only fails on missing
prerequisites your workflow actually needs. A bundle operator no
longer sees a "missing `cargo`" failure they don't care about; a
`mvmctl dev` user no longer needs host rustup.

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
mvmctl up --flake . --cpus 2 --memory 1024      # build + boot
mvmctl down                                     # tear down
```

The first run downloads the builder VM image (or builds it from a
source checkout); subsequent runs reuse the warm builder. Skip the
`--cpus` / `--memory` flags to get the defaults from
`~/.mvm/config.toml`.

**Failure recovery:**

- `host nix not required` errors → none expected. mvm's builder VM
  owns Nix; the host doesn't need it.
- `dev VM not running — run mvmctl dev up to verify` → that's just
  doctor telling you tool checks were skipped because the builder
  VM is asleep. It's not a failure; `mvmctl up` boots it on
  demand.
- `disk space < N GiB` → free space on `~/.mvm/` (default cache
  location); `mvmctl cache info` shows what's there.

## <a id="python-sdk"></a>Python SDK user

You have a Python file with an `@mvm.app()` decorator. mvm compiles
the script to an artifact, builds the rootfs, and exposes it as a
callable function.

```bash
mvmctl doctor --workflow python-sdk                              # preflight
mvmctl compile my_app.py --out /tmp/my-app && mvmctl up my-app   # compile + boot
mvmctl invoke my-app --input name='ari'                          # call
```

`mvmctl compile` parses the decorator statically; user code does not
execute on the host (only inside the microVM). `mvmctl invoke` accepts
function arguments via `--input key=value` (repeatable). See
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
mvmctl compile my-app.ts --out /tmp/my-app && mvmctl up my-app   # compile + boot
mvmctl invoke my-app --input name='ari'                          # call
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
mvmctl up --bundle ./my-app.mvmpkg              # boot
mvmctl down                                     # tear down
```

`bundle-run` doctor scope explicitly drops `prerequisites` and
`tools` — a missing host `cargo` or builder-VM Nix doesn't block
bundle launches. The platform + security + disk-space checks
remain.

**Failure recovery:**

- `bundle signature invalid` → the `.mvmpkg`'s manifest signature
  didn't match the local trust store. Source bundles from a
  trusted publisher; `mvmctl bundle verify <path>` exits non-zero
  on mismatch without launching.
- `bundle pin missing` (audit-chain admission) → the supervisor's
  signed-plan path failed to find a matching `PlanArtifact`. Pull
  a fresh copy from the publisher.

## <a id="dev-shell"></a>`mvmctl dev` user

You want a shell with a real Linux toolchain — for building, testing,
or just exploring.

```bash
mvmctl doctor --workflow dev-shell              # preflight (no host rust needed)
mvmctl dev                                      # boot + drop into shell
# inside the shell: do work; exit / Ctrl+D returns you to the host
```

`mvmctl dev` auto-bootstraps the first time (downloads the dev image
or builds it locally from `nix/images/dev-shell/`). Your project
directory is bind-mounted at `/work`. Background services keep
running after you exit; `mvmctl dev down` stops them.

**Failure recovery:**

- `builder VM image missing` → `mvmctl dev up` downloads or builds
  it. From a source checkout, the in-repo flakes are always
  preferred over published artifacts.
- `dev shell exited immediately with no command output` → check
  `~/.mvm/dev/console.log` for the kernel/init transcript. Plan
  72 W5.D documented the nine bring-up bugs that produced this
  symptom; if you hit one of them the log names it.

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
