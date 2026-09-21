---
title: Writing Nix Flakes
description: Create custom Nix flakes that build microVM images for mvm.
---

:::note[Health checks run in the guest]
`healthChecks` is rendered into `/etc/mvm/probes.d/<name>.json` in the image.
The guest agent scans that directory at boot and runs each check on its own
interval; results come back over vsock. The top-level `services`,
`volumeMounts` and `serviceGroup` arguments are still recorded rather than
acted on — the multi-service supervisor is not wired. `entrypoint.services`
is unwired for the same reason: it falls through to a recovery shell.
:::

mvmctl uses Nix flakes to produce reproducible microVM images. You run `mvmctl machine build` from the host, and mvm runs Nix evaluation and `nix build` inside the Linux builder VM. The result is a kernel and rootfs that can boot on any supported runtime backend, including Firecracker, HVF, libkrun, and QEMU.

You do not need to enter a dev shell to build a flake. The dev shell is only for manually debugging the Linux build environment. See [Builder VM](/guides/builder-vm/) for the full host-vs-builder model.

## Minimal Flake

```nix
{
  inputs = {
    mvm.url = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-app";
        packages = [ pkgs.curl ];

        # `entrypoint` is required and takes exactly one of
        # `shell` / `command` / `services`.
        entrypoint.command = [
          "${pkgs.python3}/bin/python3" "-m" "http.server" "8080"
        ];

        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
        };
      };
    };
}
```

## mkGuest API

| Parameter | Description |
|-----------|-------------|
| `name` | **Required.** VM name (used in image filename) |
| `entrypoint` | **Required.** Exactly one of `shell` / `command` / `services`; see [Building MicroVM Images](/guides/building-microvm-images#entrypoint-forms) |
| `packages` | Nix packages to include in the rootfs (default: `[]`) |
| `hypervisor` | Default hypervisor (default: `"firecracker"`) |
| `vcpus` | Resource default (default: `1`) |
| `memory_mib` | Resource default (default: `256`) |
| `dev` | Explicit accessible-vs-sealed override (default: inferred from `entrypoint`) |
| `uids` | `{ agent; entrypoint; }` privilege-model override |
| `extraFiles` | `{ "/abs/path" = { content; mode?; }; }` baked into the rootfs |
| `kernel`, `bootCommand`, `builderUid`, `withAuditProbe` | Advanced overrides |
| `healthChecks.<name>.healthCmd` | Health check command (exit 0 = healthy); **required** per check |
| `healthChecks.<name>.healthIntervalSecs` | How often to run the check (default: 30) |
| `healthChecks.<name>.healthTimeoutSecs` | Timeout for each check (default: 10) |
| `serviceGroup` | Accepted and recorded, but **not enforced** — nothing acts on it |
| `services.<name>` | Accepted and recorded, but **not enforced** — the multi-service supervisor is not wired |
| `volumeMounts."<guest-path>"` | Accepted and recorded, but **not enforced**. See "Volume Mounts" below. |

The argument set is not variadic, so any name not in this table is an
evaluation error. There is no `hostname` argument (the guest hostname comes
from `name`) and no `users` argument.

## Volume Mounts

`volumeMounts` declares which volumes the guest expects at boot. Each entry maps an absolute guest path to a volume name and read-only flag:

```nix
mkGuest {
  name = "worker";
  packages = with pkgs; [ python311 ];
  volumeMounts = {
    "/mnt/work"   = { volume = "workspace"; readOnly = false; };
    "/mnt/inputs" = { volume = "fixtures"; readOnly = true; };
  };
}
```

The declarations are recorded under `passthru.mvm.unenforced.volumeMounts`:

```sh
nix eval .#mvm-worker.passthru.mvm.unenforced.volumeMounts --json
```

**Nothing consumes them yet.** `mkGuest` accepts the attribute set, checks only
that it *is* an attribute set, and records it; there is no eval-time validation
of guest paths or volume names, and no host code attaches a device from this
declaration. Runtime volume mounting is driven by the kernel cmdline the host
writes, independently of this argument.

When you do declare a guest path that the host will later mount, note that the
host-side mount policy (`mvm_core::crypto::policy::MountPathPolicy`) allows
only paths under `/data` and `/work` — `/mnt` is deliberately excluded so a
share cannot shadow the runtime's own `/mnt/config` and `/mnt/secrets` drives.

**Reproducibility boundary:** volume *contents* do not influence the image hash. The flake hash captures the *declaration* of the mounts, not the data behind them. Volumes are the explicit mutable layer; the rootfs stays immutable + verity-protected.

`volumeMounts` is optional; the default is `{}`.

## What mkGuest Provides

`mkGuest` handles everything automatically:

- **Firecracker kernel** (vmlinux) — tuned for microVM workloads
- **Busybox init** — sub-5s boot, no systemd overhead
- **Overlay-aware runtime boot** — the `/init` path, `/mvm/runtime` mount
  point, and policy needed to boot from a sealed runtime overlay
- **Guest agent** — vsock-based health checks, status reporting, snapshot
  coordination; baked into dev/fallback images and supplied by the runtime
  overlay on sealed required-overlay boots
- **Networking** — none. A workload microVM boots with no guest NIC at all;
  egress leaves only over vsock to the per-VM `mvm-network-endpoint`.
- **Drive mounting** — `/mnt/config` (ro, `/dev/vdb`), `/mnt/secrets` (ro,
  `/dev/vdc`), `/mnt/data` (rw). These are drive images mounted by `/init`,
  not host `--mount` shares.

## Runtime overlay contract

`mkGuest` images are **overlay-aware** by default: they carry the
`/mvm/runtime` mount point and boot logic needed to use the sealed runtime
overlay when the selected backend/policy attaches one.

For sealed images on admitted block-backed backends, mvm now uses a
`RequiredOverlay` contract:

- The workload rootfs keeps the mount point and boot logic.
- The guest runtime binaries come from a separate read-only,
  verity-protected runtime overlay.
- The overlay is **version-matched** to the host `mvmctl` build, not "whatever
  overlay is newest in cache".

Operationally, this means:

- Updating the runtime overlay is the normal way to update guest runtime
  binaries for **future boots**.
- You can prebuild that artifact explicitly with
  `mvmctl build runtime-overlay build` (or `just runtime-overlay` in a
  source checkout) so later required-overlay boots do not pay guest-binary
  rebuild cost on the hot path.
- A stopped VM picks up the newer overlay on its next `machine start` /
  `machine restart`.
- A running VM keeps the overlay version it already booted with until restart;
  mvm does not live-remount a different runtime overlay into an active guest.

## Adding Services

:::caution[Not wired yet]
`services` is accepted and recorded in `passthru.mvm.unenforced`, but nothing
supervises it — the multi-service supervisor is not built. `mkGuest` emits an
evaluation-time warning when you set it. The shape below is the declared
surface, not running behaviour.
:::

The declared shape of a `services.<name>` entry:

```nix
services.my-app = {
  # Setup (runs once as root before the service starts)
  preStart = "mkdir -p /tmp/data";

  # Long-running process (supervised, auto-restart on failure)
  command = "${pkgs.nodejs}/bin/node /app/server.js";

  # Environment variables
  env = {
    PORT = "8080";
    NODE_ENV = "production";
  };

  # Run as a specific user (default: serviceGroup, which defaults to "mvm")
  user = "app";

  # Log to a file instead of console
  logFile = "/var/log/my-app.log";
};
```

## Health Checks

Health checks defined in `healthChecks` are automatically written to `/etc/mvm/probes.d/<name>.json` at build time. The guest agent picks them up on boot:

```nix
healthChecks.my-app = {
  healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/health";
  healthIntervalSecs = 10;
  healthTimeoutSecs = 5;
};
```

Query health status from the host:

```bash
mvmctl machine logs <name>       # view guest console (includes health check results)
mvmctl machine logs <name> -f    # follow in real time
```

## Users

The guest agent runs as uid **990**. The entrypoint runs as uid **1000** in a
sealed (prod) image and uid **0** in a dev image; override either with the
`uids` argument:

```nix
mvm.lib.${system}.mkGuest {
  name = "my-app";
  entrypoint.command = [ "/usr/local/bin/serve" ];
  uids = { agent = 990; entrypoint = 1000; };
};
```

Secrets at `/mnt/secrets` are owned by `root:<group>` with mode `0440`, so only
members of the service group can read them.

`mkGuest` has no `users` argument — there is no way to declare additional guest
users from the flake today. `serviceGroup` is accepted but not enforced.

## Rootfs Types

By default, `mkGuest` produces an **ext4** rootfs. The build system also supports **squashfs** for smaller, read-only images (~76% smaller with LZ4 compression). When using squashfs, the init system mounts tmpfs overlays on `/etc` and `/var` automatically.

## Composing a workload

`nix/lib` exports exactly three functions: `mkGuest`, `mkFunctionService`,
and `mkFunctionWorkload`. There are no `mkPythonService`, `mkStaticSite`, or
`mkNodeService` helpers — build the service attribute set yourself and pass it
to `mkGuest`, or use `mkFunctionWorkload` to lower an SDK-emitted Workload IR
straight to a rootfs (see
[From Workload IR to MicroVM Image](/guides/ir-to-image/)).
## Build Process

When you run `mvmctl machine build --flake .`:

1. The host CLI reads config and stages the selected flake/profile as a builder job.
2. The builder VM runs Nix evaluation and `nix build` in Linux.
3. The resulting closure is packed into the rootfs.
4. Kernel and rootfs artifacts are copied back to the host cache.
5. Runtime commands boot those already-built artifacts on the selected backend,
   attaching a version-matched runtime overlay when the workload policy
   requires or prefers it.

The same rootfs works on all backends (Firecracker, HVF, microvm.nix).

## Profiles

The `--profile` flag selects which Nix output to build:

```bash
mvmctl machine build --flake . --profile minimal
mvmctl machine build --flake . --profile gateway
```

These map to `packages.${system}.<profile>` in the flake.

## Running an LLM agent inside a microVM

The API key stays on the host. The guest receives an opaque placeholder
(`mvm-secret-…`) in its environment, sends it where the key would go, and the
per-VM network endpoint on the host swaps in the real key on the way out, only
toward the hosts the secret is bound to. What the guest receives, what the host
checks, and what gets audited is covered in
[Agent sandbox](/guides/agent-sandbox/). This section is the flake shape that
path needs. You write it in **your project's** flake; mvm does not ship a
starter image to fork.

Two things make this image different from a plain `entrypoint.command` image:

- **The agent runs per call, not as PID 1.** The placeholder is injected only
  into the entrypoint the guest agent launches for
  `mvmctl machine run --entrypoint`. Nothing injects it into PID 1's
  environment. In a plain `entrypoint.command` image the same file is both
  PID 1's command and the per-call entrypoint, so the agent would also run at
  boot, without a placeholder, and the VM powers off when it exits. Here PID 1
  idles (`bootCommand`), and `/etc/mvm/entrypoint` is a separate script the
  guest agent runs on each call.
- **The per-call entrypoint starts with an empty environment.** It gets
  `HTTP_PROXY`/`HTTPS_PROXY` (and lowercase forms) pointing at the in-guest
  proxy, the placeholder variables, and nothing else. Set `HOME`, `PATH`, and
  anything else your agent needs in the script.

```nix
# my-agent-vm/flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    mvm.url     = "github:tinylabscom/mvm";
  };

  outputs = { self, nixpkgs, mvm, ... }:
    let
      system = "x86_64-linux";
      pkgs   = import nixpkgs { inherit system; };

      idle = [ "/bin/sh" "-c" "while :; do /bin/busybox sleep 2147483647; done" ];

      # One Messages API call; the prompt arrives on stdin.
      agent = pkgs.writeScript "agent" ''
        #!${pkgs.python3}/bin/python3
        import http.client, json, os, sys, urllib.parse

        proxy = urllib.parse.urlsplit(os.environ["HTTPS_PROXY"])
        conn = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=30)
        # Absolute-form request: the in-guest proxy reads the destination from
        # the URL and does not accept CONNECT tunnels.
        conn.request(
            "POST",
            "https://api.anthropic.com/v1/messages",
            body=json.dumps({
                "model": "claude-opus-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": sys.stdin.read()}],
            }),
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],  # the placeholder
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        resp = conn.getresponse()
        sys.stdout.write(resp.read().decode())
        sys.exit(0 if resp.status == 200 else 1)
      '';

      entry = pkgs.writeScript "agent-entrypoint" ''
        #!/bin/sh
        export HOME=/tmp
        exec ${agent}
      '';
    in
    {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "agent";
        # PID 1 only keeps the VM up. `entrypoint.command` classifies the
        # image as sealed; with `bootCommand` set, mkGuest does not write it
        # to /etc/mvm/entrypoint.
        entrypoint.command = idle;
        bootCommand = idle;
        extraFiles."/etc/mvm/entrypoint" = { source = entry; mode = "0755"; };
        packages = [ pkgs.python3 ];
      };
    };
}
```

The secret is declared in Workload IR, not in the flake and not in `mvm.toml`
(which has no secret key). The SDKs write this file for you
(`mvm.secret(...)` compiled by `mvmctl build compile`); for a hand-written
flake, write it yourself next to `flake.nix`:

```json
{
  "schema_version": "0.1",
  "id": "agent",
  "apps": [
    {
      "name": "agent",
      "source": { "kind": "local_path", "path": "." },
      "image": { "kind": "nix_packages", "packages": [] },
      "entrypoints": [],
      "resources": { "cpu_cores": 2, "memory_mb": 2048, "rootfs_size_mb": 4096 },
      "env": {
        "ANTHROPIC_API_KEY": {
          "kind": "secret_ref",
          "ref": {
            "name": "anthropic",
            "mount": { "kind": "env", "var": "ANTHROPIC_API_KEY" },
            "auth_type": "bearer",
            "allowed_hosts": ["api.anthropic.com"]
          }
        }
      }
    }
  ]
}
```

The entrypoint path uses only the secret references from this file: those in
an app's `env`, and those in an entrypoint's own `env`.
`var` names the guest variable; `name` is the host secret it resolves to. The
destination list and auth type the host enforces come from
`mvmctl secret set`, not from `allowed_hosts` and `auth_type` here.

```bash
# Store the key and bind it to api.anthropic.com. Prompts for the value, or
# reads it from a pipe; it never goes on the command line.
mvmctl secret set anthropic --provider anthropic

cd my-agent-vm
echo "Say hello in five words." | mvmctl machine run --flake . --entrypoint \
  --from-workload-ir ./workload.json \
  --allow-host api.anthropic.com \
  --timeout 120
```

`--timeout` bounds the whole entrypoint call and defaults to 30 seconds; a call
that outlives it exits with status 124. Each proxied request also has its own
30-second limits (to the response head, and on any stall), so keep a single
model call short (the example caps `max_tokens`).

`--allow-host` is required: egress is denied by default, and a bound secret
does not open a destination on its own. `--from-workload-ir` is what puts the
secret into the signed plan; without it the entrypoint runs with no placeholder
and no proxy variables.

If a workload needs a credential that is not sent in an HTTP request header
(a database password, a TLS client key), substitution cannot carry it. See
[Secrets and credentials](/guides/secrets-and-credentials/) for file-shaped
secrets, and treat any guest that can read one as holding the real value.

Why a microVM and not a process sandbox: process sandboxes share the host kernel and trust it. A microVM gives the agent its own kernel, so a kernel exploit can't pivot to the host.

Full security composition (per-service uid, seccomp tier, verified boot) is documented in [ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md) and the [Rootless workloads section](/guides/building-microvm-images#rootless-workloads).
