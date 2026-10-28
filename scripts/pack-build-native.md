# Native SDK pack-build witness

`pack-build-native.py` is a tracked test driver, not a VM/cloud runner. It uses
the existing `just lab::gcp-kvm` lifecycle. Do not run it or start that lifecycle
until the operator authorizes this particular billable host, tracked-source
transfer, and source-compilation/bootstrap setup exception. Permission for an
earlier lab run is not permission for this one.

## Execution scope and preparation

The target is native `x86_64` Linux with writable `/dev/kvm` and the existing
runner's pinned Firecracker. The driver rejects other hosts. Every workload Nix
operation remains inside the project builder VM; there is no host Nix command,
alternate cloud runner, paid API, Claude credential, public publisher enrollment,
publication, or signing-identity change.

Prepare the binary using the existing live-test recipe's compilation commands
(`just/bdd/mod.just`, `live-ci`), under the separately authorized setup exception:

```sh
cargo build --bin mvmctl --features user,embed-host-bins
cargo build -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper --bin mvm-network-endpoint
```

The binary is `${CARGO_TARGET_DIR:-target}/debug/mvmctl`. The generic remote
runner restores the public source commit, installs its Ubuntu build dependencies
and pinned Rust/Zig/cargo-zigbuild/Firecracker toolchains, and exposes
`$MVM_GCP_KVM_RESULTS_DIR`. Python 3 must also be present for this driver and the
real Python SDK. These steps involve downloads and compilation; they are not
performed by the driver or by its offline tests.

The authorized run plan produces **SourceCLI** evidence: a locally compiled debug client exercising the
real SDK/CLI/build/health/sign/verify/admit/run path. It is not evidence that a
released client consumes a public pack registry.

## Final run plan, only after new authorization

Set `PACK_LOCKED_MVM_REVISION` to a reviewed, public, full 40-character mvm
commit **A**, deliberately different from the executing checkout commit **B**.
The driver checks both spellings and verifies B against the checkout's actual
Git HEAD. A matching lock declaration alone is not proof Nix consumed A.

The following uses the existing lifecycle and existing binary-preparation recipe
without adding a second runner. It has not been executed:

```sh
: "${PACK_LOCKED_MVM_REVISION:?Set the reviewed full locked mvm revision A}"
just lab::gcp-kvm bash -lc '
  set -euo pipefail
  {
    set -x
    git rev-parse HEAD
    cargo build --bin mvmctl --features user,embed-host-bins
    cargo build -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper --bin mvm-network-endpoint
    sha256sum "${CARGO_TARGET_DIR:-target}/debug/mvmctl"
    set +x
  } 2>&1 | tee "$MVM_GCP_KVM_RESULTS_DIR/authorized-build.log"
  python3 scripts/pack-build-native.py \
    --mvmctl "${CARGO_TARGET_DIR:-target}/debug/mvmctl" \
    --mvm-revision "$1" \
    --source-revision "$(git rev-parse HEAD)" \
    --build-transcript "$MVM_GCP_KVM_RESULTS_DIR/authorized-build.log" \
    --evidence-dir "$MVM_GCP_KVM_RESULTS_DIR"
' pack-build-native "$PACK_LOCKED_MVM_REVISION"
```

The runner owns outer-host creation, result download and deletion on success or
failure. Never substitute manual GCP provisioning. The runner uploads only
Git-tracked files: these new files must be tracked through the normal reviewed
change before a real invocation. No commit, push or publication is part of this
code-only task.

## What the driver observes

The fixture imports the real checkout-local `mvm.packs` SDK. It authors a tiny
sealed pack with a declared runtime `busybox` package, a copied hello file and
`cat /app/hello.txt` entrypoint. The producer locks and builds with the existing
CLI, which health-boots and signs using its isolated test host key.

Producer, prepared consumer and no-runtime consumer have distinct temporary
`HOME`, `MVM_HOME` and cache locations. Credentials and ambient runtime/build
selectors are not forwarded. The consumer receives only the archive and test
public key; authored application source is removed before the consumer run.
The prepared consumer explicitly bootstraps its runtime and enrolls only that
publisher. Full `bootstrap` also prepares builder dependencies; the consumer is
not claimed to be runtime-only or fully cache-empty. `machine check-artifact`
must return the actual archive digest, `x86_64`, verified/runnable flags,
`sealed-prod`, dm-verity protection, deny-all egress and no volumes. This is a
verified structural preview, not proof of a backend boot or kernel enforcement.
Unknown-key refusal, payload-tamper refusal, sealed ad-hoc-command
refusal and expected entrypoint output are required. The third home receives no
bootstrap: it must refuse with a runtime-preparation diagnostic without changing
its runtime/cache artifact inventory. `PreparedRuntime` and `NoPreparedRuntime`
remain separate observations. All homes run `trust audit verify` to verify their
audit chain.

The initial inventory is asserted before any acquisition in the no-runtime home.
Inventories include explicit cache, XDG cache, OCI, runtime, guest-runtime,
images and user cache roots, including symlink metadata. A separate pre-launch
inventory follows archive verification: verification may cache embedded image
material. This fixture contains no embedded runtime; that is not a guarantee
about arbitrary archives and this state is not called fully empty.

Each command records exact argv, executable, source/digest identity, isolated
home, start/end times, exit code, stdout and stderr. Failures and timeouts are
retained. The archive, lock, spec, test public key and verification outputs are
retained. No private key or signed claimed execution verdict is exported.

Actual retained builder input disks are raw tar archives. The driver reads only
bounded regular `work/flake.nix` and `job/cmd.sh` members without extraction,
and retains nearby bounded config/result/log observations. It never selects the
"newest" disk or treats path existence as an invocation binding. These are
candidate observations with `association: unobserved`, not positive proof.

The driver explicitly requests `build PACK.json --input-observation PATH`, retaining
the product diagnostic separately from raw transport observations, with a
1 MiB report limit. It does not treat a success-shaped report as proof.
Raw input/config/job/result/output-staging association has not been established.
Therefore `locked_revision_consumption` remains
`unobserved`, and even a completed functional workflow exits **2**, not success.
The missing binding is reported in `report.json`. A future positive observation
requires independently recomputed submitted-work and command hashes from the
raw input, actual job/config/result/store-path association, the exact root and
inherited workspace mvm lock graph, and actual output staging/cache hash checks.
Builder pre-sealing kernel/rootfs hashes are distinct from final signed archive
hashes. No observation is a signed consumer credential.

Commands start in invocation-owned process sessions. Timeout handling signals
only a still-live owned command's process group and waits at most ten seconds.
Each stdout/stderr stream is drained independently and retains at most 16 MiB;
overflow fails and cannot support a positive observation. Candidate collection
accepts raw tar only, at most 4096 headers, 2 MiB per selected member, 32 disks
and 64 MiB retained evidence, with 60-second collection/read/hash deadlines.
Candidate and adjacent evidence readers reject links at every path component.

Payload tampering accepts only raw tar, with at most 4096 regular/directory
headers. A 512-byte header pre-scan rejects compression, PAX, GNU long-name,
sparse and special entries before any extended metadata parsing. Source bytes,
expanded member bytes and output bytes each have an independent 16 GiB limit;
these image-bundle limits intentionally exceed the 64 MiB candidate-evidence
limit. A single 60-second monotonic deadline covers scanning and rewriting,
using at most 1 MiB payload chunks. Source and destination parents are opened
without following links; output is exclusively created with mode 0600, never
clobbered. Failure removes only a partial output whose inode is still owned.
The raw copy changes one rootfs byte and preserves manifest/signature bytes.

Cache inventories record `exists` and `type` consistently for all roots and
nested entries, including empty directories, regular-root hashes and symlink
targets without following them. FIFOs, sockets and devices fail closed without
being opened. Inventories are bounded to 4096 entries and 60 seconds, including
regular-file hashing with no-follow reads.

The driver requests stop separately in each private home. Exit zero is only
best-effort inventory cleanup, not proof. An independent Linux process inventory
checks private-home provenance and PID starttime identity. Any live scoped
process, unreadable inventory, identity change or unavailable verification
retains homes, reports `teardown-unverified` and exits **1**. It never kills
unrelated processes. Outer-host deletion is the ultimate boundary, not an
inner teardown proof.
The census and identities must remain stable across final verification; even
unrelated process churn can conservatively make teardown unverified.

The required authorized build transcript is retained alongside its digest,
observed source commit and observed executable digest. The driver labels an
arbitrary supplied executable `ExplicitBinary`: these observations do not
infer compilation linkage or certify that an old debug client is the newly
built one, and they are not released-client evidence.
Evidence may contain local paths, flake URLs and console output. Keep it
local/restricted and review it before sharing; it is not ordinary telemetry.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_pack_build_native.py
```

These tests use in-process command doubles solely to check sequencing, refusal
handling, cleanup, environment isolation and safe archive handling. The fixture
still uses the real SDK. No test starts a subprocess, `mvmctl`, Nix, a signer,
VM or cloud resource. Passing them is not native workflow evidence.
