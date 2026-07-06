# mvm

**mvm** is a Rust CLI (`mvmctl`) that runs workloads in fast, hardware-isolated
microVMs — from **OCI images** or **Nix flakes** — on macOS and Linux, with a
security posture that is enforced by CI, not by documentation.

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

- **One command from OCI image to isolated VM** — `mvmctl machine run --image alpine -- uname -a`
- **Nix-native image builds** — reproducible guests via `mkGuest`, built inside a
  builder VM (host Nix is never used, or required)
- **Security claims, CI-enforced** — 15+ numbered claims (signed execution
  plans, chain-signed audit log, dm-verity boot, default-deny egress, sealed
  prod images with no interactive access, secret substitution over vsock); see
  the [security model](#security-model)
- **Persistent or transient machines** — one-shot runs, or named machines with
  `create` / `start` / `exec` / `stop`, plus interactive dev shells
- **SDKs as thin wrappers** — Python and TypeScript SDKs drive the same
  conformance-pinned surface as the CLI; decorator-based workload authoring
  compiles to a typed IR

## Install

```bash
# Pre-built release (macOS Apple Silicon, Linux x86_64/aarch64)
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh

# From source
git clone https://github.com/tinylabscom/mvm.git && cd mvm
cargo build --release
cp target/release/mvmctl ~/.local/bin/
```

Host prerequisites:

- **macOS 26+ Apple Silicon** — none. The in-house HVF backend and builder need
  no Homebrew packages.
- **macOS 13–25** — the libkrun trio:
  `brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy`
- **Linux** — `/dev/kvm` access (Firecracker is fetched and managed for you);
  `passt` from your distro for builder networking.

`mvmctl doctor` diagnoses your host and prints exact install hints for anything
missing.

## Quick start

### Run a command in a microVM

```bash
# One-shot: boot an OCI image, run a command, tear the VM down.
# Networking is OFF by default (default-deny egress).
mvmctl machine run --image alpine -- sh -c "echo hello from a microVM && uname -a"

# Interactive shell (dev-tier images)
mvmctl machine run --image alpine -it -- /bin/sh

# Admit specific egress only (still audited; TCP/22 is always refused)
mvmctl machine run --image alpine --allow-host api.example.com:443 -- ./fetch-thing
```

### Persistent machines

```bash
mvmctl machine create web --image nginx --cpus 2 --memory 512M
mvmctl machine start web
mvmctl machine exec web -- nginx -v
mvmctl machine logs web
mvmctl machine stop web && mvmctl machine rm web

mvmctl machine ls            # list machines (alias: ps)
mvmctl machine inspect web
```

### Build and run from a Nix flake

```bash
mvmctl machine build --flake .          # build a guest image from flake.nix
mvmctl machine run   --flake . -- ./app # build + boot + run
```

Guests are declared with `mkGuest` (see the
[Nix flake guide](public/src/content/docs/guides/nix-flakes.md)); builds run
inside a builder VM, so results are identical on every host regardless of what
the host has installed.

### Dev environment

```bash
mvmctl dev            # boot the builder VM and drop into a dev shell
mvmctl dev status     # show environment info
mvmctl dev down       # stop it
```

The dev environment is the builder VM. Workload microVMs stay headless — the
only interactive path into a guest is the dev-tier console (`machine console`,
claim-15 gated). Sealed production images have **no** interactive access, ever.

### Python SDK

```python
from mvm import Machine

# One-shot run (same semantics as `mvmctl machine run`)
result = Machine.run(image="alpine", command=["sh", "-c", "echo 4"])
print(result.stdout)

# Persistent machine handle
web = Machine.create(name="web", image="nginx", cpus=2, memory="512M")
web.start()
print(web.exec(["nginx", "-v"]).stdout)
web.stop()
```

The SDKs (Python, TypeScript) are deliberately thin: they drive the exact same
argv surface as the CLI, pinned by shared conformance fixtures, so no SDK can
drift from `mvmctl`. Decorator-based workload authoring (functions compiled into
guest images) is documented in the [SDK docs](public/src/content/docs/sdk/).

## How it works

```
Host (macOS / Linux)
  mvmctl ──► signed ExecutionPlan ──► admission (validity window, nonce, audit)
                                          │
                              VM backend (auto-selected)
                 Firecracker (KVM) · in-house HVF · libkrun · QEMU (dev/test)
                                          │
Guest (its own Linux kernel)
  /init ──► mvm-guest-agent on vsock :5252  — exec, files, processes, code-run
  no sshd · no SSH keys · setpriv + seccomp service isolation
  rootfs: ext4 (dm-verity sealed in prod) or read-only virtio-fs
```

- **Backend selection** is automatic per host (`--hypervisor` overrides). All
  backends consume the same image artifacts; switching backends does not change
  the image.
- **Builds** run `nix build` inside a builder VM (in-house HVF on macOS 26+,
  libkrun elsewhere, with automatic fallback). Host Nix is never consulted.
- **Egress** is default-deny. Where policy admits flows they are enforced and
  audited host-side; on the in-house backend all guest I/O rides vsock through a
  per-VM gating endpoint (there is no guest NIC).

## Security model

mvm makes **fifteen numbered, CI-enforced security claims** (plus preview
claims), each backed by a named test or workflow gate — from "a tampered rootfs
fails to boot" (dm-verity) to "no raw secret value ever crosses to the guest"
(vsock substitution: the workload sees placeholders; real credentials are
injected host-side, destination-bound and time-bound) to "no interactive access
to a sealed production microVM."

- The claim ledger: [`specs/claims/catalog.md`](specs/claims/catalog.md)
- The source of truth: [ADR-002](specs/adrs/002-microvm-security-posture.md)
- Live posture on your host: `mvmctl doctor`
- Audit chain verification: `mvmctl trust audit verify` (chain-signed JSONL;
  tampering breaks verification and exits nonzero)

Every workload boots from a **signed ExecutionPlan**; every admission, launch,
and OCI provenance record lands in a **chain-signed audit log**; egress is
**default-deny**; production images are **sealed** (verity rootfs, no console,
no `do_exec`, entrypoint-only); application-dependency volumes are hash-locked,
SBOM-enumerated, and CVE-gated.

Out of scope (named in ADR-002): a malicious *host* (mvmctl trusts the host with
the hypervisor and private keys), multi-tenant guests (one guest = one
workload), and hardware-backed key attestation.

## Documentation

- [Getting started](public/src/content/docs/getting-started/)
- [CLI reference](public/src/content/docs/reference/cli-commands.md)
- [Writing Nix flakes for guests (mkGuest)](public/src/content/docs/guides/nix-flakes.md)
- [Troubleshooting](public/src/content/docs/guides/troubleshooting.md)
- [Architecture & ADRs](specs/adrs/)
- [Security](public/src/content/docs/security/)

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
builder VM. After building, run `mvmctl doctor` — it reports the resolved
builder backend and emits install hints for anything missing.

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
  negative cases.
- **Reuse first.** Search the workspace before adding a helper — duplicated
  logic is this repo's most common bug source. All `~/.mvm` and `~/.cache/mvm`
  paths go through `mvm-core::config` helpers, never inline `$HOME` joins.
- **Specs discipline.** Design docs live in `specs/` (ADRs in `specs/adrs/`,
  plans in `specs/plans/`). If your change lands a plan workstream, tick the
  matching boxes in the plan and `specs/REFACTOR-STATUS.md` in the same PR. If
  it touches a security claim, keep
  [`specs/claims/catalog.md`](specs/claims/catalog.md) in sync — the
  claim→witness mapping is machine-checked.

Keep PRs focused (one concern each) and write commit messages that explain
*why*. PRs merge through the GitHub **merge queue** once CI is green.

Running the full live suite (workspace clippy on x86_64-linux, seccomp probes,
longer fuzz runs, live-KVM smokes) needs real `/dev/kvm`; the cloud-init
scaffolding for a throwaway KVM box lives in [`ops/hetzner/`](ops/hetzner/), and
the contributor guide has the details:
[development.md](public/src/content/docs/contributing/development.md).

### Repository layout

15-crate Cargo workspace; the full map is in [CLAUDE.md](CLAUDE.md). The short
version: `mvm-core` (types / plans / policy / crypto — no runtime deps) →
`mvm-build` (Nix builder pipeline) → `mvm-backend` (every `VmBackend` impl) →
`mvm` (runtime) → `mvm-cli` (the `mvmctl` surface), plus `mvm-guest` (vsock
protocol + agent), `mvm-hostd` (host daemons: broker / signers / supervisor),
`mvm-vm-host` (per-VM supervisor binaries), `mvm-sdk` (authoring + IR),
`mvm-client*` (the local/remote client facade), and `xtask` (lint gates).

## License

Apache 2.0 — see [LICENSE](LICENSE).
