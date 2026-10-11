# mvm

mvm runs workloads in microVMs on macOS and Linux. Each workload gets its own
Linux kernel under a hypervisor: the in-house HVF backend on macOS 26+ Apple
Silicon, Firecracker on Linux with `/dev/kvm`. You can start one from an OCI
image, a Nix flake, or a decorated Python or TypeScript function. The CLI is
`mvmctl`. Python, TypeScript and Rust libraries drive the same operations from
code.

It is built for running code you don't fully trust, such as agent tool calls,
user-submitted scripts or third-party builds, on a laptop or a single host.
Fleet orchestration lives in a separate project,
[mvmd](https://github.com/tinylabscom/mvmd).

Workload VMs have no network device. Everything the guest sends goes over
vsock to a per-VM process on the host, and that process opens any outbound
connection itself. This gives the host one place to enforce default-deny
egress and to swap secret placeholders for real credentials, so the guest
never holds them. Every launch is described by an execution plan that `mvmctl`
signs, checks and records in a hash-chained audit log before the VM boots.
There is no SSH server in any guest.

## Install

```bash
# Release binary: macOS 26+ on Apple Silicon, or Linux x86_64/aarch64 with /dev/kvm
curl -fsSL https://runmvm.com/install.sh | sh

# From source (run ./target/release/mvmctl from the checkout)
git clone https://github.com/tinylabscom/mvm.git && cd mvm
cargo build --release

# Language SDKs
pip install mvm
npm install @runmvm/mvm
```

Nothing else is required: no Docker, no host Nix, no Homebrew packages.
`mvmctl doctor` checks the host and says what is missing. Source builds have a
few extra steps, covered in
[Building from source](public/src/content/docs/guides/building-from-source.md).

## Quick start

```bash
mvmctl doctor
mvmctl bootstrap
mvmctl image pull alpine
export MVM_RESIDENCY=warm
mvmctl pool warm 1 --image alpine
mvmctl machine run --image alpine -- sh -c "echo hello from a microVM && uname -a"
```

`bootstrap` fetches the kernel, guest runtime and builder image. `image pull`
fetches and unpacks an OCI image. `pool warm` boots a standby VM, and
`MVM_RESIDENCY=warm` lets the next matching run claim it. A `machine run
--image` launch reads only the local cache and never downloads anything. A run
that claims a standby must be ready in under 300 ms, or `mvmctl` reports the
launch as failed.

The VM is torn down when the command exits. Networking is off unless you allow
it:

```bash
mvmctl image pull python:3.12

# Share a host directory, read-only. It is copied into a block device at boot.
mvmctl machine run --image python:3.12 \
  --mount "$PWD/examples/python/hello-app:/work:ro" -- python /work/app.py

# Size the VM and admit one destination. The connection is made by the host and audited.
mvmctl machine run --image alpine --cpus 2 --memory 512M \
  --allow-host api.example.com:443 -- ./fetch

# Interactive terminal
mvmctl machine run --image alpine -it -- ls /
```

Runs that mount a directory or allow egress are not served from the warm pool.
They boot cold.

### Persistent machines

A machine with a name keeps its spec on disk until you remove it:

```bash
mvmctl image pull nginx
mvmctl machine create web --image nginx --cpus 2 --memory 512M
mvmctl machine start web
mvmctl machine exec web -- nginx -v
mvmctl machine logs web
mvmctl machine reconfigure web --memory 1G
mvmctl machine ps
mvmctl machine inspect web
mvmctl machine stop web
mvmctl machine rm web
```

## Defining a workload

### Nix flake

`mkGuest` builds a minimal image containing only what you declare:

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
        # Sealed, one-shot. Alternatives: entrypoint.services (supervised,
        # long-running) or entrypoint.shell (dev image with a console).
        entrypoint.command = [ "${pkgs.python3}/bin/python3" "-m" "http.server" "8080" ];
      };
    };
}
```

```bash
mvmctl machine build --flake .
mvmctl machine run --flake . -- ./app
```

`nix build` runs inside a headless builder VM that mvm manages, so the host
never needs Nix. Sealed images boot from a dm-verity-protected root and have no
shell. See the [mkGuest guide](public/src/content/docs/guides/nix-flakes.md).

### Decorated function

```python
# app.py
import mvm

@mvm.app(
    name="greeter",
    source=mvm.local_path("."),
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    env={"BANNER": mvm.literal("hi")},
)
def greet(name: str) -> str:
    return f"hello {name}"
```

```bash
mvmctl build compile app.py --out ./out
mvmctl machine build --flake ./out
echo '[[], {"name": "ari"}]' | mvmctl machine run --entrypoint --flake ./out
```

`build compile` parses the file without running it and writes a flake and a
launch plan. The decorator and the `mvm` import are stripped from the bundled
source, so the guest runs the plain function. The entrypoint reads
`[args, kwargs]` as JSON on stdin. For locked dependencies and sealed
dependency volumes, see
[From dev loop to attested image](public/src/content/docs/guides/develop-to-attested.md).

## Driving VMs from code

The runtime SDK creates sandboxes, runs commands and moves files:

```python
import mvm

with mvm.Sandbox.create(image="python-3.12") as sb:
    sb.files.write("/app/main.py", "print('hi from mvm')")
    sb.commands.start(["python", "/app/main.py"])
    print(sb.exec("uname", "-sr").stdout)
```

```bash
mvmctl run --mode plan ./script.py
```

`--mode plan` signs and admits the script's plan without booting anything.
`exec`, `commands.start` and the console are available only under the dev
profile, and fail with `SandboxDevOnly` otherwise.

From Rust, use the `mvm-client` crate:

```rust
use mvm_client::{LocalBackend, MachineSpec, MvmClient};

let client = LocalBackend::new();
let spec = MachineSpec::builder("web", "alpine")?
    .cpus(2)
    .memory_mib(512)
    .build();
let machine = client.run_machine(spec).await?;
let out = client.exec_machine(&machine.id, vec!["uname".into(), "-sr".into()]).await?;
println!("{}", String::from_utf8_lossy(&out.stdout));
```

The same trait has a REST backend for remote hosts, behind the `remote`
feature. See the [Python](crates/mvm-sdk/sdks/python/README.md) and
[TypeScript](crates/mvm-sdk/sdks/typescript/README.md) SDK READMEs and the
[Rust SDK guide](public/src/content/docs/sdk/rust.md).

## Security model

[ADR-001](specs/adrs/001-microvm-security-posture.md) lists the security claims
and names a test or CI job behind each one. CI fails when a named witness
disappears. The shipped claims:

1. **No host filesystem access from a guest** beyond explicit shares.
2. **No guest binary can gain uid 0.**
3. **A tampered root filesystem fails to boot** (dm-verity, on block-backed roots).
4. **A production-safe run cannot call DevOnly guest-agent verbs.**
5. **The vsock framing, FlowMux decoder and supervisor config are fuzzed.**
6. **The prebuilt dev image is hash-verified** against a signed image-set root.
7. **Cargo dependencies are audited on every PR**, with a reproducibility double build.
8. **Every workload runs from a signed, audited execution plan.**
9. **Every published bundle is content-addressed** and re-verified at fetch and admission.
10. **No untrusted workload reaches the network** unless policy admits it.
11. **Dependency volumes are CVE-scanned and SBOM-enumerated when sealed**, then hash-locked and re-verified at admission.
12. **Every host service a workload calls is bound in its signed plan** and audited.
13. **Secret substitution gives the guest placeholders**, never raw secret values.
14. **OCI image provenance is recorded** in the audit log.
15. **A sealed production VM has no shell, no DevOnly agent verbs and no PTY.**

Claims 16 to 18 (the egress substitution leak gate, workload stdin, and
resource bounds) are previews and are not listed here.

19. **Workload assets and pinned host shares are content-identified** in the signed plan, and a share that changes after admission is refused.
20. **Every release artifact is signed by the release workflow**, and the build, fetch, install and self-update paths refuse a missing or invalid signature.
21. **Base OCI images are inventoried and CVE-scanned at pull**, and production admission refuses a missing scan or a high or critical finding.

Out of scope: a malicious host, several tenants sharing one guest, and
hardware-backed key attestation. `mvmctl doctor` reports the posture of the
current host, and `mvmctl trust audit verify` checks the audit chain.

## Documentation

- [Getting started](public/src/content/docs/getting-started/quickstart.md) and the [Python quickstart](public/src/content/docs/getting-started/python-quickstart.md)
- [CLI reference](public/src/content/docs/reference/cli-commands.md)
- [SDK docs](public/src/content/docs/sdk/index.md)
- [Network egress policy](public/src/content/docs/guides/network-egress-policy.mdx), [secrets](public/src/content/docs/guides/secrets-and-credentials.mdx), and [vsock networking](public/src/content/docs/guides/flowmux-networking.md), including key-value storage and peer routes
- [Builder VM](public/src/content/docs/guides/builder-vm.md) and [kernels](public/src/content/docs/guides/kernels.md)
- [Boot flow](public/src/content/docs/architecture/boot-flow.md) and [architecture](public/src/content/docs/architecture/overview.md)
- [Troubleshooting](public/src/content/docs/guides/troubleshooting.md)
- [Releases](public/src/content/docs/reference/releases.md)

## Contributing

Work is tracked in GitHub issues. Start with the
[development guide](public/src/content/docs/contributing/development.md) and
[AGENTS.md](AGENTS.md), which holds the rules CI enforces.

```bash
git clone https://github.com/tinylabscom/mvm.git && cd mvm
just maint::hooks   # pre-commit hook that runs cargo fmt --all
nix develop         # optional: pinned toolchain
just ci             # lint, tests and doctests; run before opening a PR
```

Every `mvmctl` command in this README is checked against the real CLI, and
each one is mapped either to a conformance scenario that runs it or to a
recorded reason it cannot run
([readme_examples.toml](features/suites/s8_readme_contract/readme_examples.toml)).
PRs merge through the merge queue.

## License

Apache 2.0. See [LICENSE](LICENSE).
