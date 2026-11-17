# Native actor acceptance witness

This is an explicit native Apple Silicon HVF test, not a mock, ignored-test
marker, performance benchmark, or production-security claim. It uses the
ordinary signed admission gates, the real `ActorBootstrap::provision` path,
and the same controller subprocess bootstrap as `mvmctl actor launch`.

## Build and run

Prerequisites:

- Native Apple Silicon macOS with Hypervisor.framework support.
- The repository's pinned Rust, Zig and cargo-zigbuild toolchain, including
  `aarch64-unknown-linux-musl`. The existing `just payload::toolchain` recipe
  documents installation; this witness does not install system tooling.
- An already acquired, verified AArch64 workload kernel. Supply its absolute
  path in `MVM_ACTOR_KERNEL`; the witness pins its bytes in each synthesized plan
  and the ordinary kernel admission gate remains in force.

From the repository root, with `MVM_ACTOR_KERNEL` set:

```bash
bash scripts/actor-live-hvf.sh
```

The script executes these artifact builds:

```bash
source scripts/dev-env.sh
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
scripts/cargo.sh zigbuild --release --target aarch64-unknown-linux-musl \
  -p mvm-agentd --example actor_live_parent --example actor_live_worker
scripts/cargo.sh build --release -p mvm-hostd --features hvf-live-validation \
  --bins --example actor_live_hvf
```

The host example then uses the existing source-runtime resolver and
`build_runtime_overlay_from_guest_runtime` / `build_initramfs_from_guest_runtime`
assemblers. The two minimal read-only ext4 workload images are built with the
existing `mvm_fs::ext4` writer. Their root-owned mode-0555 native executables
are pinned as `/usr/lib/mvm/wrappers/actor` by `/etc/mvm/entrypoint`.
No Nix command, arbitrary guest Exec, guest NIC, or security-bypass flag is used.
The guest programs use native transport directly (`sdk_uses_sidecar=false`).

Each role has its own artifact directory: `evidence/parent/rootfs.ext4` and
`evidence/worker/rootfs.ext4`, each beside its own `mvm-meta.json`. The canonical
`GuestSidecar` writer records `overlayAware: true` and `runtimeLean: true`:
the images contain `/mvm/runtime` and `/mvm/sdk` mount directories and no baked
agent/netinit fallback. Metadata declares the immutable command argv,
`initSystem: "initramfs-agent"`, `hypervisor: "hvf"`, and a rootless entrypoint.
The `dev` variant remains accessible and unsealed; this is not a production
profile. `agentBinary: "real"` describes the separately bound runtime, not an
agent embedded in the workload image. Source is `built-local`, with assembly
time recorded; image tag and generator revision are empty, protocol version
and expected boot time are zero (unrecorded), and libc is unknown because no
dynamic loader is included. None of these fields bypasses admission or attests
kernel security.

The fixture-only test builds and reads ext4 images and exercises the ordinary
sidecar gate, without building guest payloads or starting a VM:

```bash
just tests::scoped mvm-hostd rootfs_artifacts_match_sidecar \
  --example actor_live_hvf --features hvf-live-validation
```

The controller must dispatch the authenticated immutable `RunEntrypoint` only
after the launcher's commit acknowledgement. Merely booting an agent or setting
`entrypoint_present` does not run an application and cannot pass this witness.

## Assertions and evidence

The parent guest:

1. Checks that a template absent from its grant is refused.
2. Launches the exact `worker` template once.
3. Checks refusal of a 1025-byte call under a 1024-byte signed payload ceiling.
4. Makes one correlated call with stable message IDs.
5. Performs one bounded blocking result receive, validates the response, and
   submits the exact signed-delivery-lease acknowledgement through the guest reader.
6. Releases the child and requires a terminal lifecycle response before exiting 0.

The worker receives once, validates the request, replies, acknowledges its
request lease, and waits for release. It fails if it survives that bounded wait.

The host waits on the **original controller child**, verifies its exit status,
verifies the audit chain, requires exactly two admitted launches and successful
root application completion, checks terminal root/child reservations, and checks
that used VM state did not survive or enter warm capacity. The request and reply
payloads must be absent from the audit.

An isolated new `/tmp/actor-hvf.*/evidence` directory retains the authored
`bootstrap.json`, both workload images, the isolated `MVM_HOME`, audit,
reservation/terminal records and `result.json`. Its explicit host budget and
mailbox retention are test configuration, not modifications to the user's home.
The finite FD/socket/helper figures are configured reservations with the runtime's
known-owner lower-bound check, not a measured OS-wide resource census or density
qualification.

A timeout is a failure, not evidence of teardown. The harness does not kill
unknown native PIDs or erase retained state; a cleanup-only controller remains
responsible for its original resources.

## Separate process-crash witness

`cargo test -p mvm-hostd --test mailbox_process_bin` includes
`actor_response_survives_helper_process_crash_before_signed_ack`. It runs real
parent and child mailbox helpers, receives the durable reply without acknowledging
it, kills and reaps the original parent helper through its retained `Child`,
and restarts the helper with the exact original serialized configuration.
The test requires the same reply and lease to replay, followed by signed ACK
and settlement. Its isolated test process owns all helper handles and state.

This witnesses mailbox response durability across a helper-process crash. It
does not demonstrate automatic actor-runtime supervision or a crash during the
two-VM run.

## Deliberately unclaimed

This witness does not currently inject a mailbox-helper crash between durable
acceptance and application ACK. No public process-level fault-injection seam was
found in the mailbox launcher. The report records
`helper_crash_recovery_exercised: false`; unit journal/crash tests are not relabeled
as a live crash witness. It also makes no host-blindness, production authority,
latency, or density claim.

The fixture has not passed until the script actually completes and writes a
successful evidence report. Compilation alone is not a live result.
