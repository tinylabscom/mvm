# mvm

**mvm** is a Rust CLI (`mvmctl`) and a set of language SDKs for running
workloads in fast, hardware-isolated microVMs — from **OCI images**, **Nix
flakes**, or **decorated functions** — on macOS and Linux, with a security
posture that is enforced by CI, not by documentation.

Every machine boots its own Linux kernel under a real hypervisor. There is no
Docker on the runtime path, no SSH in any guest, and (on the in-house macOS
backend) no guest network device at all: guest I/O crosses **vsock**, where the
host can audit flows, substitute secrets so the workload never sees raw
credentials, and enforce default-deny egress from a signed execution plan.

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
- **SDKs for Python, TypeScript, and Rust** — a *decorator* SDK for authoring
  workloads and a *runtime* SDK for driving them, both thin wrappers over one
  conformance-pinned surface
- **Security claims, CI-enforced** — 15+ numbered claims (signed execution
  plans, chain-signed audit log, dm-verity boot, default-deny egress, sealed
  prod images with no interactive access, secret substitution over vsock)

## Install

```bash
# Pre-built release (macOS Apple Silicon, Linux x86_64/aarch64)
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh

# From source
git clone https://github.com/tinylabscom/mvm.git && cd mvm
cargo build --release && cp target/release/mvmctl ~/.local/bin/

# Language SDKs
pip install mvm                 # Python  (or: pip install ./sdks/python)
npm install @runmvm/mvm         # TypeScript
```

Host prerequisites: **macOS 26+ Apple Silicon** needs nothing (the in-house HVF
backend and builder are dependency-free); **macOS 13–25** needs the libkrun trio
(`brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy`); **Linux**
needs `/dev/kvm` (Firecracker is managed for you). `mvmctl doctor` diagnoses your
host and prints exact install hints for anything missing.

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

# Interactive dev shell (dev-tier images) — still transient
mvmctl machine run --image alpine -it -- /bin/sh

# Give it resources; admit specific egress only (audited; TCP/22 always refused)
mvmctl machine run --image alpine --cpus 2 --memory 512M \
  --allow-host api.example.com:443 -- ./fetch

# Build a Nix flake and run it transiently in one step
mvmctl machine run --flake . -- ./app
```

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

### Dev environment

The dev environment is the **builder VM**, not a workload VM:

```bash
mvmctl dev            # boot + drop into a dev shell
mvmctl dev status
mvmctl dev down
```

### Examples

Working example workloads live in [`examples/`](examples/) — build any of them
with `mvmctl machine run --flake examples/<name>` (Nix) or `mvmctl build compile`
(SDK):

| Example | Kind | What it shows |
|---|---|---|
| [`examples/python/hello-app`](examples/python/hello-app) | Python decorator | Minimal `@mvm.app` function-entrypoint workload |
| [`examples/python/hello-app-with-deps`](examples/python/hello-app-with-deps) | Python decorator | `@mvm.app` with a locked `python_deps` (uv) dependency → sealed deps volume |
| [`examples/python/secret-egress`](examples/python/secret-egress) | Python decorator | Secret substitution over egress — the workload sees a placeholder, never the raw secret |
| [`examples/typescript/hello-app`](examples/typescript/hello-app) | TS decorator | Minimal `mvm.app({...})(fn)` workload |
| [`examples/typescript/hello-app-with-deps`](examples/typescript/hello-app-with-deps) | TS decorator | `mvm.app` with locked `node_deps` |
| [`examples/exit_code`](examples/exit_code) | Nix flake | One-shot sealed workload (exits a chosen code) |
| [`examples/sleeper`](examples/sleeper) | Nix flake | Long-lived sealed workload fixture |
| [`examples/egress-probe`](examples/egress-probe) | Nix flake | One-shot workload that TCP-probes targets and exits a verdict — exercises egress policy |
| [`examples/audit-probe`](examples/audit-probe) | Nix flake | In-guest `host.audit.v1` round-trip fixture |

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
network fetch.

### 2. From a Nix flake (`mkGuest`)

Reproducible, minimal guests built from a flake — the guest carries only what
you declare. `mkGuest` has three entrypoint forms; the form decides the security
posture:

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
Sealed images are dm-verity verified and have no interactive access; the dev
form keeps a console. See the
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
mvmctl build compile app.py            # static parse (no execution) → flake.nix + launch plan
mvmctl machine run --flake . --entrypoint  # build + boot + dispatch greet over vsock (RunEntrypoint)
```

At build time the `@mvm.app` decorator and the `mvm` import are **stripped** from
the bundled source, so the guest runs your plain function with no SDK dependency
inside the microVM.

---

## SDKs

Two SDK families, three languages. Both are deliberately **thin**: they drive
the exact surface the CLI does — decorators emit the canonical `Workload` IR;
runtime calls go through the client facade — pinned by shared conformance
fixtures so no SDK can drift from `mvmctl`.

### Decorator SDK — *authoring*

Declare a workload where it lives. `@mvm.app(...)` (Python) / `mvm.app({...})`
(TypeScript) is higher-order: it records the declaration and returns your
function unchanged, so the same file still runs normally under `python` / `tsx`
and is *also* read statically by `mvmctl build compile`.

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

### Runtime SDK — *control plane*

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
against a sealed prod image they refuse with `SandboxDevOnly` — no silent
fallback (claim 4). `Machine` is the persistent-handle variant; `Session` drives
function-entrypoint `invoke`.

**Rust** — the runtime SDK is the `MvmClient` facade (`crates/mvm-client`), an
`async` trait with a `LocalBackend` (in-process, drives the host directly) and a
`GatewayBackend` (REST, for remote/hosted control). Embed it to run machines
from your own Rust service:

```rust
use mvm_client::{MvmClient, MachineSpec};
use mvm_client_local::LocalBackend;

let client = LocalBackend::new();

// Fluent builder — name + image are required; cpus/memory/env default + override.
let spec = MachineSpec::builder("web", "alpine")
    .cpus(2)
    .memory_mib(512)
    .env("PORT", "8080")
    .build();

let machine = client.run_machine(spec).await?;
let out = client.exec_machine(&machine.id, vec!["uname".into(), "-sr".into()]).await?;
println!("{}", String::from_utf8_lossy(&out.stdout));
```

The same facade is what the CLI, the GUI/studio, and the fleet orchestrator all
consume — one surface, every frontend.

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
  /init ──► mvm-guest-agent on vsock :5252  — exec, files, processes, code-run
  no sshd · no SSH keys · setpriv + seccomp service isolation
  rootfs: ext4 (dm-verity sealed in prod) or read-only virtio-fs
```

Backend selection is automatic per host (`--hypervisor` overrides); all backends
consume the same image artifacts. Egress is default-deny — where policy admits
flows they are enforced and audited host-side, and on the in-house backend all
guest I/O rides vsock through a per-VM gating endpoint (there is no guest NIC).

## Security model

mvm makes **fifteen numbered, CI-enforced security claims** (plus preview
claims), each backed by a named test or workflow gate. In summary:

1. **No host-fs access from a guest beyond explicit shares** — per-service uid,
   seccomp, `setpriv --no-new-privs` bounding set.
2. **No guest binary can elevate to uid 0** — read-only `/etc/{passwd,group}`,
   `no-new-privs` in the launch path.
3. **A tampered rootfs ext4 fails to boot** — dm-verity + kernel-cmdline roothash
   + verity initramfs; live-KVM tamper regression panics before userspace.
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
14. **Every `run --image` admission records OCI image provenance** in the
    chain-signed audit log.
15. **No interactive access to a sealed production microVM** — the console is
    `dev-shell`-gated, the prod rootfs is verity-sealed, console capture is
    write-only, and the host gate refuses `console` on a sealed VM.

The guest agent runs as an unprivileged uid under `setpriv`; `~/.mvm` and
`~/.cache/mvm` are mode 0700. **Out of scope** (named in ADR-002): a malicious
*host* (mvmctl trusts the host with the hypervisor and private keys),
multi-tenant guests (one guest = one workload), and hardware-backed key
attestation.

- The claim ledger (claim → witness, machine-checked): [`specs/claims/catalog.md`](specs/claims/catalog.md)
- The source of truth (threat model, tier matrix): [ADR-002](specs/adrs/002-microvm-security-posture.md)
- Live posture on your host: `mvmctl doctor`
- Audit chain verification: `mvmctl trust audit verify` (exits nonzero on drift)

## Documentation

- [Getting started](public/src/content/docs/getting-started/) ·
  [Python quickstart](public/src/content/docs/getting-started/python-quickstart.md)
- [CLI reference](public/src/content/docs/reference/cli-commands.md)
- [SDK docs](public/src/content/docs/sdk/) ·
  [Python SDK](sdks/python/README.md) ·
  [TypeScript SDK](sdks/typescript/README.md)
- [Writing Nix flakes for guests (mkGuest)](public/src/content/docs/guides/nix-flakes.md)
- [Security](public/src/content/docs/security/) ·
  [Troubleshooting](public/src/content/docs/guides/troubleshooting.md)
- [Architecture & ADRs](specs/adrs/)

## Contributing

Contributions are welcome. The short version:

### Setup

```bash
git clone https://github.com/tinylabscom/mvm.git && cd mvm
just install-hooks        # pre-commit hook: auto-runs cargo fmt --all

# Source-checkout builds cross-compile embedded guest binaries; you need:
brew install zig          # or your distro's zig
cargo install cargo-zigbuild cargo-nextest
```

End users of released binaries need none of that — the guest binaries ship
embedded. You do **not** need host Nix: every Nix evaluation runs inside the
builder VM. After building, run `mvmctl doctor` — it reports the resolved builder
backend and emits install hints for anything missing.

### Build, test, lint

```bash
just build           # cargo build
just test            # cargo nextest run --workspace   (the named test gate)
just test-fast       # skips the embedded-binary cross-compile (fast inner loop)
just lint            # cargo fmt --all -- --check  +  clippy -D warnings
just ci              # lint + tests + doctests — run this before every PR
```

Ground rules (enforced by CI — see [AGENTS.md](AGENTS.md) for the full set):

- **Zero clippy warnings.** `#[allow(clippy::too_many_arguments)]` is banned in
  hand-written code — introduce a builder struct instead.
- **Always `cargo fmt --all`** — without `--all`, other workspace members are
  silently skipped and CI will fail.
- **No task is done without tests.** Types get serde round-trips; wire/protocol
  code gets tampered-input rejection tests; security paths get positive *and*
  negative cases. SDK changes must keep the shared conformance fixtures
  (`sdks/machine-fixtures/`) green — that is what keeps the wrappers thin.
- **Reuse first.** Search the workspace before adding a helper — duplicated logic
  is this repo's most common bug source. All `~/.mvm` and `~/.cache/mvm` paths go
  through `mvm-core::config` helpers, never inline `$HOME` joins.
- **Specs discipline.** Design docs live in `specs/` (ADRs in `specs/adrs/`,
  plans in `specs/plans/`). If your change lands a plan workstream, tick the
  matching boxes in the plan and `specs/REFACTOR-STATUS.md` in the same PR. If it
  touches a security claim, keep
  [`specs/claims/catalog.md`](specs/claims/catalog.md) in sync — the
  claim→witness mapping is machine-checked.

Keep PRs focused (one concern each) and write commit messages that explain
*why*. PRs merge through the GitHub **merge queue** once CI is green. The full
live suite (workspace clippy on x86_64-linux, seccomp probes, longer fuzz runs,
live-KVM smokes) needs real `/dev/kvm`; cloud-init scaffolding for a throwaway
KVM box lives in [`ops/hetzner/`](ops/hetzner/), and the
[contributor guide](public/src/content/docs/contributing/development.md) has the
details.

### Repository layout

15-crate Cargo workspace; the full map is in [CLAUDE.md](CLAUDE.md). The short
version: `mvm-core` (types / plans / policy / crypto — no runtime deps) →
`mvm-build` (Nix builder pipeline) → `mvm-backend` (every `VmBackend` impl) →
`mvm` (runtime) → `mvm-cli` (the `mvmctl` surface), plus `mvm-guest` (vsock
protocol + agent), `mvm-hostd` (host daemons: broker / signers / supervisor),
`mvm-vm-host` (per-VM supervisor binaries), `mvm-sdk` (decorator parser + IR +
runtime), `mvm-client*` (the local/remote client facade the SDKs and frontends
share), and `xtask` (lint gates). Language SDKs live under `sdks/`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
