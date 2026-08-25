# mvm

**mvm** is a Rust CLI (`mvmctl`) and a set of language SDKs for running
workloads in fast, hardware-isolated microVMs — from **OCI images**, **Nix
flakes**, or **decorated functions** — on macOS and Linux, with a security
posture that is enforced by CI, not by documentation.

Every machine boots its own Linux kernel under a real hypervisor. There is no
Docker on the runtime path, no SSH in any guest, and **no guest network device
at all** — on any workload backend. Every byte a workload sends crosses
**vsock**, where the host can audit flows, substitute secrets so the workload
never sees raw credentials, detect-and-replace secrets and structured PII on
owned cleartext egress paths, and enforce default-deny egress from a signed
execution plan.

That last point is load-bearing: because the guest has no NIC, the **host
originates every outbound connection**. That is what makes default-deny egress,
"no raw secret reaches the guest", and the audit chain mechanically enforceable
rather than merely intended.

```
macOS 26+ (Apple Silicon)  →  in-house HVF VMM (Hypervisor.framework, zero extra deps)
macOS 13–25                →  libkrun (Homebrew)
Linux + /dev/kvm           →  Firecracker
```

## Highlights

- **One command from image to isolated VM** — `mvmctl machine run --image alpine -- uname -a`
- **Three ways to define a workload** — an OCI image, a Nix flake (`mkGuest`), or
  a decorated function (`@mvm.app`) — all compile to the same signed, auditable
  microVM
- **SDKs for Python, TypeScript, and Rust** — a _decorator_ SDK for authoring
  workloads and a _runtime_ SDK for driving them, both thin wrappers over one
  conformance-pinned surface
- **Security claims, CI-enforced** — 15+ numbered claims (signed execution
  plans, chain-signed audit log, dm-verity boot, default-deny egress, run-shaped
  agent-verb grants, sealed prod images that refuse interactive access, secret
  substitution over vsock)

## Local. A real microVM in milliseconds.

The steady state is deliberately simple: give mvm an image and a command, and
it gives the workload its own Linux kernel, memory boundary, writable root, and
host-brokered I/O. The warm path uses cached VM and image artifacts, so the
microVM starts in milliseconds. Cold mode may download or build those
artifacts; mvm explains that work and caches it for the next run.

```bash
mvmctl machine run --image python:3.12 -- python -c "print(2 + 2)"
```

Network access is off by default. Filesystem sharing, egress, and secrets are
explicit launch decisions recorded in the signed execution plan — there is no
SSH session, daemon to operate, or container fallback hiding behind this
command.

## Install

```bash
# Pre-built release (macOS Apple Silicon, Linux x86_64/aarch64)
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh

# From source
git clone https://github.com/tinylabscom/mvm.git && cd mvm
cargo build --release && cp target/release/mvmctl ~/.local/bin/

# Language SDKs
pip install mvm                 # Python  (or: pip install ./crates/mvm-sdk/sdks/python)
npm install @runmvm/mvm         # TypeScript
```

Host prerequisites: **macOS 26+ Apple Silicon** needs nothing (the in-house HVF
backend and builder are dependency-free); **macOS 13–25** needs the libkrun
runtime (`brew install slp/krun/libkrun slp/krun/libkrunfw`); **Linux** needs
`/dev/kvm` (Firecracker is managed for you). `mvmctl doctor` diagnoses your host
and prints exact install hints for anything missing.

## Quick start

### Transient machines

A transient machine boots, runs one command, and is torn down on exit — nothing
is registered, nothing persists. This is the default shape of `machine run`
(no `--name`):

```bash
# Boot an OCI image, run a command, tear the VM down.
# Networking is OFF by default (default-deny egress).
mvmctl machine run --image alpine -- sh -c "echo hello from a microVM && uname -a"

# Multiple args after `--` are the argv; the VM lives only for this command.
mvmctl machine run --image python:3.12 -- python -c "print(2 + 2)"

# Run a Python file from the host checkout (the mount is read-only).
# Repeat --mount for additional host directories.
mvmctl machine run --image python:3.12 \
  --mount "$PWD:/work:ro" -- python /work/app.py

# Install pandas and run the file in the same transient VM.
# The install disappears when this VM is torn down.
mvmctl machine run --image python:3.12 \
  --allow-host pypi.org:443 \
  --allow-host files.pythonhosted.org:443 \
  --mount "$PWD:/work:ro" \
  -- sh -c 'python -m pip install --no-cache-dir --target /tmp/python-deps pandas && PYTHONPATH=/tmp/python-deps python /work/app.py'

# Interactive dev shell (dev-tier images) — still transient
mvmctl machine run --image alpine -it -- /bin/sh

# Give it resources; admit specific egress only (audited; TCP/22 always refused)
mvmctl machine run --image alpine --cpus 2 --memory 512M \
  --allow-host api.example.com:443 -- ./fetch

# Build a Nix flake and run it transiently in one step
mvmctl machine run --flake . -- ./app

# Share a host directory read-only; use :rw only with --profile dev/permissive
mvmctl machine run --image alpine --mount .:/work -- ls /work

# Increase logging globally; RUST_LOG still overrides the generated filter
mvmctl machine run --image alpine -vvv --allow-host api.example.com -- ps aux
```

# Cap AI API usage with a token budget by adding [network.ai] to mvm.toml:
#   [network]
#   allow_hosts = ["api.openai.com:443"]
#   [network.ai]
#   metering = true
#   [network.ai.budget]
#   max_total_tokens = 1_000_000
mvmctl machine run --flake . -- ./ask-model

### Persistent machines

A persistent machine has a name and an on-disk spec: create once, start/stop/exec
against it, reconfigure it, remove it when done.

```bash
mvmctl machine create web --image nginx --cpus 2 --memory 512M
mvmctl machine start web
mvmctl machine exec  web -- nginx -v
mvmctl machine logs  web
mvmctl machine reconfigure web --memory 1G     # patch + relaunch
mvmctl machine stop  web && mvmctl machine rm web

mvmctl machine ls                              # list (alias: ps)
mvmctl machine inspect web
```

### The builder VM

Nix builds run inside a **headless builder VM** that mvm manages for you — there
is no interactive shell into it. It exists only to run `nix build`, and you debug
it through its logs. It auto-bootstraps on the first `machine build` / `machine
run`; to set up host tooling and pre-acquire all shared launch artifacts ahead
of time:

```bash
mvmctl bootstrap      # host setup + builder VM, kernel, overlay, initramfs, guest shims
mvmctl doctor         # diagnose host deps + the resolved builder/runtime backend
```

`bootstrap` is safe to rerun. It verifies warm artifacts and only rebuilds or
downloads what is missing or invalid. Official release binaries download
published, verified artifacts and never infer a local build merely because the
command runs inside a source checkout. Contributor binaries build source-matched
artifacts when that source is available. If a Stage 0 source build is
interrupted, the incomplete output is never installed; rerunning resumes with
the persistent Nix store still warm.

For an interactive shell you want a _workload_ microVM, not the builder — use a
transient run against a dev-tier image: `mvmctl machine run --image alpine -it -- /bin/sh`.

On the first image-backed run from a contributor build, mvm may prepare and
cache the guest runtime and workload kernel from local sources. The guest
runtime phase is concise by default; pass `-v` to show Cargo's raw compilation
progress. Official binaries download these version-matched artifacts instead.
If the output includes `builder egress endpoint ... exited
with status signal: 15 (SIGTERM)`, that line is normally cleanup: the
host-side builder egress endpoint is terminated after the one-shot Stage 0
build exits. The actionable error is the following one. In particular, a
message saying that the resolved workload kernel has no device-mapper/dm-verity
support means the cached kernel cannot boot a verity-sealed workload. Rebuild
or download the workload kernel explicitly:

```bash
# Use the release's hash-verified kernel
mvmctl build kernel build --which workload --source download

# Or compile the host-architecture kernel from this source checkout
mvmctl build kernel build --which workload --source compile
```

### Examples

Working example workloads live in [`examples/`](examples/) — build any of them
with `mvmctl machine run --flake examples/<name>` (Nix) or `mvmctl build compile`
(SDK):

| Example                                                                              | Kind             | What it shows                                                                           |
| ------------------------------------------------------------------------------------ | ---------------- | --------------------------------------------------------------------------------------- |
| [`examples/python/hello-app`](examples/python/hello-app)                             | Python decorator | Minimal `@mvm.app` function-entrypoint workload                                         |
| [`examples/python/hello-app-with-deps`](examples/python/hello-app-with-deps)         | Python decorator | `@mvm.app` with a locked `python_deps` (uv) dependency → sealed deps volume             |
| [`examples/python/secret-egress`](examples/python/secret-egress)                     | Python decorator | Secret substitution over egress — the workload sees a placeholder, never the raw secret |
| [`examples/typescript/hello-app`](examples/typescript/hello-app)                     | TS decorator     | Minimal `mvm.app({...})(fn)` workload                                                   |
| [`examples/typescript/hello-app-with-deps`](examples/typescript/hello-app-with-deps) | TS decorator     | `mvm.app` with locked `node_deps`                                                       |
| [`examples/exit_code`](examples/exit_code)                                           | Nix flake        | One-shot sealed workload (exits a chosen code)                                          |
| [`examples/sleeper`](examples/sleeper)                                               | Nix flake        | Long-lived sealed workload fixture                                                      |
| [`examples/egress-probe`](examples/egress-probe)                                     | Nix flake        | One-shot workload that TCP-probes targets and exits a verdict — exercises egress policy |
| [`examples/audit-probe`](examples/audit-probe)                                       | Nix flake        | In-guest `host.audit.v1` round-trip fixture                                             |

### From a template

You can also scaffold a new project from a template instead of starting from
an empty directory. A small core set ships with `mvmctl` and works offline;
richer templates are fetched from the [`mvm-templates`](https://github.com/tinylabscom/mvm-templates)
registry on first use and cached under `~/.mvm/templates/remote/`.

```bash
# List bundled + cached templates
mvmctl template list

# Show details for one template
mvmctl template info python

# Scaffold a project from a template
mvmctl generate template python ./my-python-app

# Search the remote registry
mvmctl template search pandas
```

Templates can be Nix flakes or SDK-based. Nix templates ship a `flake.nix`;
SDK templates ship source files (e.g. `app.py`) plus a generated `flake.nix`.
See the [`mvm-templates` README](https://github.com/tinylabscom/mvm-templates/blob/main/README.md)
for how to author one, including the optional `files` list that tells `mvmctl`
which additional files to copy into the generated project.

---

## Defining a workload

A workload can be defined three ways. All three compile to the same artifact —
a signed image plus a launch plan — and boot identically on every backend.

### 1. From an OCI image

The fastest path — no flake, no host Nix:

```bash
mvmctl machine run --image python:3.12 -- python -c "print(2 + 2)"
```

Provenance (registry, repo, resolved digest, layer list, cosign verdict) is
recorded in the chain-signed audit log; `--prod` refuses mutable tags before any
network fetch. A contributor binary built from a source checkout automatically
builds and caches the source-matched guest runtime and dedicated
dm-verity-capable workload kernel on first use. An official binary downloads
the matching verified release artifacts by default and does not implicitly
invoke the local Rust or Nix toolchain.
Use `MVM_KERNEL_SOURCE=download` to prefer the matching hash-verified release
kernel, or `mvmctl kernel build --which workload` when you want to prewarm it.

### 2. From a Nix flake (`mkGuest`)

Reproducible, minimal guests built from a flake — the guest carries only what
you declare. `mkGuest` has three entrypoint forms; the form sets the image's
default accessibility and profile metadata, while the launch profile and run
shape decide the agent-verb grant:

```nix
{
  inputs = {
    mvm.url     = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs   = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        inherit pkgs;
        name = "my-app";

        # Form 1 — command entrypoint  (SEALED, one-shot)
        entrypoint.command = [ "${pkgs.python3}/bin/python3" "-m" "http.server" "8080" ];

        # Form 2 — services  (SEALED, supervised long-running)
        # entrypoint.services.web.exec = "${pkgs.caddy}/bin/caddy run";

        # Form 3 — shell  (DEV, console drops to a shell)
        # entrypoint.shell = "bash";
      };
    };
}
```

```bash
mvmctl machine build --flake .          # build the image inside the builder VM
mvmctl machine run   --flake . -- ./app # build + boot + run
```

Builds run `nix build` inside a builder VM — **host Nix is never used or
required**, so the same `mvmctl` produces byte-identical artifacts on every host.
Sealed images are dm-verity verified and refuse interactive access — no shell,
no `do_exec`, no PTY; the dev form keeps a console. At launch, a
baked-entrypoint run on a non-dev profile gets the restricted ProdSafe
agent-verb grant, while a PTY or ad-hoc argv run requires DevOnly verbs. This
grant is chosen from the run shape and profile, not from whether an OCI rootfs
carries a sealed sidecar bit. See the
[mkGuest guide](public/src/content/docs/guides/nix-flakes.md) and
`nix/lib/default.nix` for the full API.

### 3. From a decorated function (SDK)

Write an ordinary function; the decorator declares the image, resources, deps,
and env around it. `mvmctl build compile` reads the file **statically** (it is never
executed on the host) and emits the flake + launch plan:

```python
# app.py
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    dependencies=mvm.python_deps(lockfile="uv.lock", tool="uv"),
    env={"BANNER": mvm.literal("hi")},
    before_start="export FOO=1",
)
def greet(name: str) -> str:
    return f"hello {name}"
```

```bash
mvmctl build compile app.py --out ./out   # static parse (no execution) → ./out (flake.nix + launch plan)
mvmctl machine build --flake ./out        # build the image inside the builder VM

# Dispatch greet(name="ari"): the entrypoint payload is [args, kwargs] JSON on stdin
# (empty stdin ⇒ the default no-arg payload `[[], {}]`).
echo '[[], {"name": "ari"}]' | mvmctl machine run --entrypoint --flake ./out   # → "hello ari"
```

At build time the `@mvm.app` decorator and the `mvm` import are **stripped** from
the bundled source, so the guest runs your plain function with no SDK dependency
inside the microVM.

---

### From dev loop to attested image

The three routes above are the _start_ of one path: pick a base, iterate until
the workload actually works, then end with a sealed, hashed, recorded artifact.

What that looks like today:

```bash
mvmctl build compile app.py --out ./out   # declared deps; lockfiles must be hash-pinned
mvmctl machine build --flake ./out        # installs deps into a SEALED volume
mvmctl deps install --lockfile uv.lock --language python  # dev install + seal
mvmctl deps capture-live HASH --vm dev-vm \
  --guest-content /mvm/deps/content \
  --guest-sbom /mvm/deps/sbom.cdx.json \
  --guest-fetch-log /mvm/deps/fetch.log \
  --guest-cve /mvm/deps/cve.json              # export + reseal
mvmctl deps inspect                       # SBOM + CVE + hash-chained meta, no VM needed
mvmctl machine run --entrypoint --flake ./out
```

Dependencies land in a sealed volume rather than in the image: hash-locked
content, an SBOM, a CVE scan, and a hash-chained `meta.json`. The supervisor
verifies that volume before launch and refuses a tampered one, and `--prod`
fails closed on high/critical findings or a stub SBOM. A lockfile entry with no
integrity hash is rejected at compile time.

`mvmctl deploy` packages the local attested deployment, while `mvmctl watch`
rebuilds a workload when its local inputs change. Both commands are available
in the CLI; use `mvmctl deploy --help` and `mvmctl watch --help` for their
required inputs and limits. The declared route above remains the supported way
to get a dependency into an attested workload.

Full walkthrough: [From dev loop to attested image](public/src/content/docs/guides/develop-to-attested.md).

## SDKs

Two SDK families, three languages. Both are deliberately **thin**: they drive
the exact surface the CLI does — decorators emit the canonical `Workload` IR;
runtime calls go through the client facade — pinned by shared conformance
fixtures so no SDK can drift from `mvmctl`.

### Decorator SDK — _authoring_

Declare a workload where it lives. `@mvm.app(...)` (Python) / `mvm.app({...})`
(TypeScript) is higher-order: it records the declaration and returns your
function unchanged, so the same file still runs normally under `python` / `tsx`
and is _also_ read statically by `mvmctl build compile`.

<table>
<tr><th>Python</th><th>TypeScript</th></tr>
<tr valign="top"><td>

```python
import mvm

@mvm.app(
    image=mvm.node_image(node="22"),
    resources=mvm.resources(cpu=1, memory_mb=256),
)
def greet(name: str) -> str:
    return f"hello {name}"
```

</td><td>

```ts
import * as mvm from "@runmvm/mvm";

mvm.workload({ id: "hello" });

export const greet = mvm.app({
  image: mvm.node_image({ node: "22" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
})((name: string): string => `hello ${name}`);
```

</td></tr></table>

Shared builder vocabulary across both languages: image builders
(`python_image`, `node_image`, `nix_packages`), `resources`, dependency locks
(`python_deps`, `node_deps`), `env` values (`literal`, `secret`), `network` /
`egress` policy, and lifecycle hooks (`before_build`, `before_start`, …). Emit
the IR directly for inspection or tests with `mvm.emit_json()` /
`mvm.emitJson()`.

**Rust** is the engine behind this path: `mvm-sdk` parses the decorators, holds
the canonical `ir::Workload`, and renders the flake — so adding a language means
emitting that IR, not writing a compiler.

### Runtime SDK — _control plane_

Drive machines imperatively: create, exec, move files, run processes, forward
ports, tear down. The Python/TypeScript `Sandbox` object model and the Rust
`MvmClient` facade are the same operations over different transports.

<table>
<tr><th>Python</th><th>TypeScript</th></tr>
<tr valign="top"><td>

```python
import mvm

with mvm.Sandbox.create(image="python-3.12") as sb:
    sb.files.write("/app/main.py", "print('hi from mvm')")
    sb.commands.start(["python", "/app/main.py"])
    print(sb.exec("uname", "-sr").stdout)
```

</td><td>

```ts
import * as mvm from "@runmvm/mvm";

const sb = await mvm.Sandbox.create({ image: "python-3.12" });
sb.files.write("/app/main.py", "print('hi from mvm')");
sb.commands.start(["python", "/app/main.py"]);
await sb.kill();
```

</td></tr></table>

Run a Sandbox script as an admission-only plan check or against a real VM:

```bash
mvmctl run --mode plan ./script.py     # synthesize + sign + admit, no boot
mvmctl run --mode live ./script.py     # boot a real microVM and execute
```

Interactive surfaces (`exec`, `commands.start`, `console`) are **dev-tier only**;
they refuse with `SandboxDevOnly` when the run needs DevOnly verbs but admission
offers only the restricted ProdSafe grant — no silent fallback (claim 4).
`Machine` is the persistent-handle variant; `Session` drives function-entrypoint
`invoke`.

**Rust** — the runtime SDK is the `MvmClient` facade (`crates/mvm-client`), an
`async` trait with a `LocalBackend` (in-process, drives the host directly) and a
`GatewayBackend` (REST, for remote/hosted control — behind the `remote` feature).
Everything is one import; embed it to run machines from your own Rust service:

```rust
use mvm_client::{MvmClient, MachineSpec, LocalBackend};

let client = LocalBackend::new();

// Fluent builder — name + image are required; cpus/memory/env default + override.
// The image is parsed here, so a declaration that names nothing is refused at
// construction rather than at boot.
let spec = MachineSpec::builder("web", "alpine")?
    .cpus(2)
    .memory_mib(512)
    .env("PORT", "8080")
    .build();

let machine = client.run_machine(spec).await?;
let out = client.exec_machine(&machine.id, vec!["uname".into(), "-sr".into()]).await?;
println!("{}", String::from_utf8_lossy(&out.stdout));
```

The same facade is what the CLI, the desktop **studio** GUI, and the fleet
orchestrator (**mvmd**) all consume — one surface, every frontend.

#### Embedding mvm — studio, mvmd, and custom frontends

There are two integration seams, depending on what you're building.

**Driving machines from a frontend** (the desktop studio, a custom GUI/CLI, a web
service): link `mvm-client` and go through the `MvmClient` trait. `connect(Target)`
picks the transport; the returned `Box<dyn MvmClient>` behaves identically either
way, so the same UI code drives a local host or a remote fleet:

```rust
use mvm_client::{connect, MvmClient, Target};

// In-process — this host's microVMs, auto-selected VMM. No daemon required.
let local = connect(Target::Local)?;              // == mvm_client_local::LocalBackend::new()

// Remote — a hosted fleet or a local sidecar, over REST (needs feature `remote`).
let remote = connect(Target::Gateway {
    base_url: "https://fleet.example.com".into(),
    token: std::env::var("MVM_TOKEN")?,
})?;

// Identical methods on both: create / run / start / stop / remove, exec, logs, reconfigure.
for m in remote.list_machines(Default::default()).await? {
    println!("{}", m.id);
}
```

The **studio** desktop app is exactly this pattern — the in-process
`LocalBackend` (built into `mvm-client`) or the remote `GatewayBackend` (the
`remote` feature), selected at runtime via `MVM_STUDIO_BACKEND`, one
`dyn MvmClient` behind its Tauri commands. Its `Cargo.toml`:

```toml
# LocalBackend ships by default; the `remote` feature adds the REST GatewayBackend.
mvm-client = { path = "../mvm/crates/mvm-client", features = ["remote"] }
```

**Embedding the runtime in a host-side daemon** (the **mvmd** fleet orchestrator,
or your own controller that manages instances directly): link the `mvmctl`
library facade for the runtime types, the host shell seam, and the gated
host↔guest IPC transport. Keep `default-features = false` so no async runtime is
pulled in unless you opt into the transport:

```toml
mvmctl = { path = "../mvm", default-features = false, features = ["hostd-transport"] }
```

```rust
use mvmctl::core::{instance::InstanceStatus, pool::Role, protocol};
use mvmctl::runtime::shell;   // host command-execution seam
```

`mvmd` reconciles pools/instances and reaches each guest agent over the
`hostd-transport` protocol through this seam, while workload-driving frontends
stay on the `MvmClient` facade above. Rule of thumb: **drive sandboxes → `MvmClient`;
run the host that hosts them → the `mvmctl` facade.**

---

## How it works

```
Host (macOS / Linux)
  mvmctl / SDK ──► signed ExecutionPlan ──► admission (validity window, nonce, audit)
                                              │
                                  VM backend (auto-selected)
                     Firecracker (KVM) · in-house HVF · libkrun · QEMU (dev/test)
                                              │
Guest (its own Linux kernel)
  /init (universal initramfs) ──► mvm-guest-agent on vsock :5252
    1. mounts /proc, /sys, /dev
    2. waits fail-closed for a signed ActivateEnvironment
    3. mounts the dm-verity rootfs + runtime overlay, pivots root, drops to uid 901
  no sshd · no SSH keys · setpriv + seccomp service isolation
  rootfs: ext4 (dm-verity sealed in prod) or read-only virtio-fs
```

On boots that attach the universal initramfs, the kernel cmdline carries no
roothash tokens. The guest PID 1 waits fail-closed for a signed
`ActivateEnvironment` over vsock, then mounts the root — dm-verity for a
sealed boot, plain-block for an unverified dev boot, or a virtio-fs tag for a
block-less boot — plus the runtime overlay when one is attached, pivots into
it, and drops to the workload uid before serving operational RPCs. The same
initramfs serves Nix-built and OCI images on every runner backend
(Firecracker, libkrun, HVF). See
[Boot flow](public/src/content/docs/architecture/boot-flow.md) for the
detailed sequence.

Backend selection is automatic per host (`--hypervisor` overrides); all backends
consume the same image artifacts. Egress is default-deny — where policy admits
flows they are enforced and audited host-side. On Linux, an optional host-side
[eBPF](https://ebpf.io/) probe attached to the egress substitution process
observes `tcp_connect` events (destination address and port) via a ring buffer,
with a procfs fallback when BPF loading is unavailable. The probe does not widen
the guest attack surface: the guest still has no NIC, the probe reads no guest
payloads, and policy enforcement remains at the existing admission and vsock
forwarding seams.

### Vsock-only: the invariant the other guarantees rest on

**No production workload microVM has a network device.** Firecracker's config
sequence omits `/network-interfaces`; libkrun pins its direct-vsock mode; and
the in-house HVF device model has no net device. Guest I/O leaves over one
authenticated FlowMux session to a per-VM host endpoint, and the host originates
the real connection or owns the admitted ingress listener. QEMU's explicit
user-mode network is a dev/test facility outside this production claim.

This is enforced mechanically, not by convention:

- **`xtask check-single-network-path`** pins every claim-bearing backend to the
  one endpoint spawner and `NetworkFlow` channel, rejects raw-packet/NIC/L3
  symbols, and inventories every production workload `connect` and listener
  bind so a second socket owner fails CI.
- **`xtask check-one-guest-protocol`** rejects any guest caller of the network
  port that does not construct an authenticated FlowMux client.

The admitted domain cannot represent the removed raw-network mode. Every
network operation instead receives the endpoint's one signed-plan projection:
the same policy, per-VM resource budget, identity, and payload-free audit sink.

**The builder VM is the deliberate exception.** It runs `nix build` and does
have a NIC, because it must reach package mirrors. It carries no untrusted
tenant workload — a different tier with a different contract, and its network
configuration is never consulted by any workload backend.

#### Reaching a store without a network

`--host-service host.kv.v1` binds a per-workload key-value store served on the
host-services broker channel. The workload gets durable storage with no network
path and no credential; the namespace comes from the supervisor's call context
rather than any request field, so one workload cannot address another's by
asking. A workload whose plan did not bind it gets `NotBound` before any
handler runs. A catalog runtime can declare the services it needs, so the
operator does not have to pass the flag every time — declared bindings and
`--host-service` are unioned.

#### Reaching another workload

Peer addressing lets a workload dial `db.mvm.peer:5432` and have the host
resolve and connect, with the name and its resolved address both bound in the
signed plan. Resolution runs in front of the same gate that decides ordinary
egress, so east-west inherits default-deny; a binding authorizes one
`name:port` route; and the reserved `.mvm.peer` suffix keeps the two namespaces
from overlapping. `xtask check-single-network-path` pins the branch to one
place.

**There is no CLI flag to author a peer binding yet.** The decision path is
implemented and gated but not reachable from `mvmctl`, so this is a reserved
namespace and a live enforcement path rather than a feature you can turn on.
Peer dialing is TCP-only and peers are not reachable through the
credential-substituting HTTP proxy.

## Security model

mvm makes **fifteen numbered, CI-enforced security claims** (plus preview
claims), each backed by a named test or workflow gate. In summary:

1. **No host-fs access from a guest beyond explicit shares** — per-service uid,
   seccomp, `setpriv --no-new-privs` bounding set.
2. **No guest binary can elevate to uid 0** — read-only `/etc/{passwd,group}`,
   `no-new-privs` in the launch path.
3. **A tampered rootfs ext4 fails to boot** — dm-verity + universal initramfs
   (roothash delivered over vsock, not the kernel cmdline); live-KVM tamper
   regression panics before userspace. Scoped to the block+ext4 backends
   (Firecracker + Option B); the virtiofs-root dev-tier path carries a weaker
   contract — see the claim catalog.
4. **The guest agent has no `do_exec` in production builds** — symbol-absence
   CI gate on the sealed agent.
5. **Vsock framing + supervisor config are fuzzed** — `cargo-fuzz` targets;
   `#[serde(deny_unknown_fields)]` fails closed on every host↔guest type.
6. **Pre-built dev image is hash-verified** — SHA-256 manifest checked, rejected
   on mismatch.
7. **Cargo deps are audited on every PR** — `deny.toml` + reproducibility
   double-build.
8. **Every workload runs from a signed, audited `ExecutionPlan`** — Ed25519
   host signature, validity window, nonce replay-store; chain-signed
   `plan.admitted`/`launched`/`failed` audit entries.
9. **Every published bundle is content-addressed and re-verified** at fetch and
   admit time (unknown-key, tampered-manifest, pin-drift ladders).
10. **No untrusted workload reaches the network unless admitted by policy** —
    default-deny; `unrestricted` requires an explicit opt-in.
11. **Every app-dependency volume is hash-locked, attestation-checked,
    CVE-scanned, SBOM-enumerated,** and bound to the workload's audit chain.
12. **Every host-side broker service is bound to a signed
    `ExecutionPlan.services` binding,** enforced before dispatch, audited.
13. **No raw secret value crosses to the guest** — destination-bound,
    time-bound signed credentials only; real bytes never leave the supervisor.
    For owned cleartext outbound flows, the host can also detect and replace
    matched secrets and structured PII with request-scoped opaque tokens, then
    restore the original bytes only when the exact token returns on an owned,
    authorized cleartext path.
14. **Every `run --image` admission records OCI image provenance** in the
    chain-signed audit log.
15. **A sealed production microVM has no shell, no `do_exec`, no PTY, and no
    input that can change what runs** — the console is
    `interactive`-feature-gated, the prod rootfs is verity-sealed, console
    capture is write-only, and the host gate refuses `console` on a sealed VM.
    The host→guest input channel carries bytes to an already-running
    entrypoint's stdin and nothing else — it cannot select a program, alter
    argv or env, or spawn anything, and it is refused outright without a grant
    in the signed plan.

Claim 15 used to hold by _absence_: there was no host→guest byte path at all.
The workload input channel built one, so refusing input is now a policy
decision rather than a consequence of there being nothing to refuse. ADR-001
carries that rewording, plus a `Preview` claim 17 for the input channel with
the four limits that keep it a preview — including that it has no operator
surface yet. See
[Workload input](public/src/content/docs/guides/workload-input.md).

    Separately, the restricted ProdSafe grant is issued only to a baked-entrypoint
    run on a non-dev profile; PTY and ad-hoc argv paths require DevOnly verbs.

The guest agent runs as an unprivileged uid under `setpriv`; `~/.mvm` and
`~/.mvm/cache` are mode 0700. **Out of scope** (named in ADR-001): a malicious
_host_ (mvmctl trusts the host with the hypervisor and private keys),
multi-tenant guests (one guest = one workload), and hardware-backed key
attestation.

- The claim ledger (claim → witness, machine-checked): the conformance claim
  catalog embedded in [ADR-001](specs/adrs/001-microvm-security-posture.md)
- The source of truth (threat model, tier matrix): [ADR-001](specs/adrs/001-microvm-security-posture.md)
- Live posture on your host: `mvmctl doctor`
- Audit chain verification: `mvmctl trust audit verify` (exits nonzero on drift)

## Documentation

`just bdd` resolves every `mvmctl` example against the real command tree, checks
every CLI option including hidden internal options, exercises the SDK fixtures,
and rejects new README code blocks without a corresponding test witness. Static
install, Nix, and embedding examples are checked for their required contract
tokens; live boot, egress, and guest-I/O behavior remains covered by tagged
integration scenarios. The merge queue also runs a KVM-backed fast witness for
the persistent-machine path above: create, start, exec, logs, inspect, stop, and
remove all operate one real Firecracker guest before the change can merge.

- [Getting started](public/src/content/docs/getting-started/) ·
  [Python quickstart](public/src/content/docs/getting-started/python-quickstart.md)
- [CLI reference](public/src/content/docs/reference/cli-commands.md)
- [SDK docs](public/src/content/docs/sdk/) ·
  [Python SDK](crates/mvm-sdk/sdks/python/README.md) ·
  [TypeScript SDK](crates/mvm-sdk/sdks/typescript/README.md)
- [Writing Nix flakes for guests (mkGuest)](public/src/content/docs/guides/nix-flakes.md)
- [Secrets and credentials](public/src/content/docs/guides/secrets-and-credentials.mdx) ·
  [Network egress policy](public/src/content/docs/guides/network-egress-policy.mdx) ·
  [Rootless networking](public/src/content/docs/guides/networking.md) ·
  [AI agent integration](public/src/content/docs/guides/ai-agent-integration.md)
- [Security](public/src/content/docs/security/) ·
  [Troubleshooting](public/src/content/docs/guides/troubleshooting.md)
- [Architecture & ADRs](specs/adrs/)

## Contributing

Contributions are welcome. The short version:

### Setup

```bash
git clone https://github.com/tinylabscom/mvm.git && cd mvm
just install-hooks        # pre-commit hook: auto-runs cargo fmt --all

# Recommended: enter the pinned contributor environment.
nix develop

# Or install the source-checkout tools manually:
brew install zig          # or your distro's zig
cargo install cargo-zigbuild cargo-nextest
```

The root [`flake.nix`](flake.nix) is a development environment, not a
workload image. `nix develop` provides the pinned Rust toolchain, Cargo tools,
formatters, linters, Zig, and documentation tooling used by the contributor
workflow. Host Nix remains optional for running `mvmctl`: workload Nix
evaluation and image builds still run inside the managed builder VM. The
microVM library and image-building flake lives separately under [`nix/`](nix/).

When opened interactively, the development shell replaces Nix’s default Bash
with login zsh, so aliases and functions from your normal zsh startup files
remain available. The shell also best-effort installs the
`wasm32-unknown-unknown` target when `rustup` is available.

After building, run `mvmctl doctor` — it reports the resolved builder backend
and emits install hints for anything missing.

### Build, test, lint

```bash
just build           # nightly Cranelift + 8-thread rustc frontend
just test            # cargo nextest run --workspace   (the named test gate)
just lint            # cargo fmt --all -- --check  +  clippy -D warnings
just ci              # lint + tests + doctests — run this before every PR
```

When iterating on `mvmctl` itself, make sure you are running the freshly-built
binary. A manually-copied `bin/mvmctl` or a stale `target/release/mvmctl` can
miss backend fixes — for example, the QEMU session teardown that reaps
`qemu-system-aarch64` and `mvmctl __qemu-vsock-bridge` after a transient run.

The repository pins a dated nightly and installs Cranelift through
`rust-toolchain.toml`. Development recipes route Cargo through
`scripts/cargo-fast.sh`: dev builds use Cranelift and eight frontend threads,
while tests and release builds retain LLVM. The nightly-only settings live in
`.cargo/fast.toml`, separate from the baseline Cargo configuration, so explicit
stable/MSRV and release lanes remain loadable. Lint recipes use the repository's
stable Rust 1.96 toolchain because current nightly Clippy reports a generated
async-trait future as carrying a redundant must-use annotation; no lint is
suppressed. Reproducible embedded-host and runtime-overlay guest binaries remain
on their separately pinned stable Rust toolchain so outer nightly flags cannot
leak into Zig-based artifact builds.

Ground rules (enforced by CI — see [AGENTS.md](AGENTS.md) for the full set):

- **Zero clippy warnings.** `#[allow(clippy::too_many_arguments)]` is banned in
  hand-written code — introduce a builder struct instead.
- **Always `cargo fmt --all`** — without `--all`, other workspace members are
  silently skipped and CI will fail.
- **No task is done without tests.** Types get serde round-trips; wire/protocol
  code gets tampered-input rejection tests; security paths get positive _and_
  negative cases. SDK changes must keep the shared conformance fixtures
  (`tests/machine-fixtures/`) green — that is what keeps the wrappers thin.
- **Reuse first.** Search the workspace before adding a helper — duplicated logic
  is this repo's most common bug source. All `~/.mvm` paths go
  through `mvm-core::config` helpers, never inline `$HOME` joins.
- **Specs discipline.** Design docs live in `specs/` (ADRs in `specs/adrs/`,
  plans in `specs/plans/`). If your change lands a plan workstream, tick the
  matching boxes in the plan and refresh the
  [refactor status dashboard](specs/refactor/README.md) in the same PR. If it
  touches a security claim, keep the conformance claim catalog in
  [ADR-001](specs/adrs/001-microvm-security-posture.md) in sync — the
  claim→witness mapping is machine-checked.

Keep PRs focused (one concern each) and write commit messages that explain
_why_. PRs merge through the GitHub **merge queue** once CI is green. The full
live suite (workspace clippy on x86_64-linux, seccomp probes, longer fuzz runs,
live-KVM smokes) needs real `/dev/kvm`; cloud-init scaffolding for a throwaway
KVM box lives in [`nix/ops/hetzner/`](nix/ops/hetzner/), and the
[contributor guide](public/src/content/docs/contributing/development.md) has the
details.

### Repository layout

14-crate Cargo workspace. The dependency spine runs low → high:
`mvm-contract` (`no_std` + alloc: wire types / Workload IR / policy / audit-log
verify — wasm-capable) → `mvm-core` (std: config / paths / crypto / signed
execution plans — no async by default) → { `mvm-fs` (ext4 / OCI / overlay),
`mvm-net` (vsock + egress tunnel), `mvm-build` (Nix builder pipeline) } →
`mvm-runtime` (the `VmBackend` trait plus the libkrun / HVF / Firecracker / QEMU
impls and VM lifecycle) → `mvm-client` (the local/remote client facade the SDKs
and frontends share) → `mvm-cli` (the `mvmctl` surface). Alongside the spine:
`mvm-hostd` (host daemons — broker, signers, per-VM supervisor binaries),
`mvm-agentd` (in-guest vsock protocol + agent), `mvm-sdk` (decorator parser →
Workload IR → Nix template, plus the runtime SDK), and `deps/libkrun-sys` (the
libkrun FFI + safe wrapper). `xtask` holds the CI lint gates and
`mvm-conformance` runs the BDD security-claim suite. The full module map is in
[CLAUDE.md](CLAUDE.md). Language SDK surfaces live under `crates/mvm-sdk/`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
