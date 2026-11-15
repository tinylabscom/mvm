# Lifecycle and unsafe review: reviewed to date (umbrella #4839)

Backing: preview
Validation: none — this records what was read and what was fixed, as stated in the fixing PRs; it is not a claim that the review is exhaustive and enforces nothing beyond the `undocumented_unsafe_blocks` lint it cites.

The umbrella issue owns status. This file records the "reviewed to date" half of the box
"Review ownership, allocation, errors, state transitions, cancellation, lock/task ownership,
cleanup/rollback, unsafe/FFI boundaries, and panic paths affected by changes" in
[#4839](https://github.com/tinylabscom/mvm/issues/4839). The ongoing half is the PR checklist item in
`AGENTS.md` ("Definition of Done", item 7).

**The review is not exhaustive.** The tables list the areas read, the defects they produced, and,
separately, the files that were not read. Absence from the "read" column is not evidence of
soundness. "Read" is taken from the fixing PR descriptions and the review notes for the lane; the
line ranges are as recorded there and were not re-derived when this file was written.

## Compile-time AES-GCM boundary

Reviewed `crates/mvm-crypto/src/aead.rs`,
`crates/mvm-core/src/crypto/aead.rs`, and the seal/open paths and independent
cipher tests in `crates/mvm-core/src/net/session.rs`. The shared crypto crate
only instantiates the existing `aes-gcm` implementation in its own optimized
compilation unit. It borrows fixed-size keys and nonces for one operation and
returns owned ciphertext/plaintext; it owns no persistent keys, process, task,
lock, or lifecycle state.

The public `aead::Aead` trait lets implementations define their key, nonce,
and error types. `Aes256Gcm` remains the concrete selection at both production
call sites; no algorithm negotiation, protocol switch, or new cipher is added.
Integration tests cover trait-object dispatch and a downstream refusal-only
implementation with different associated types.

The callers retain key zeroization, nonce generation, associated-data selection,
framing, signature verification before session decryption, sequence advancement,
replay checks, and existing error mapping. The at-rest encryption `expect`
retains its existing message and failure condition. The leaf adds a known AES-256-GCM
vector and wrong-key/nonce/AAD, truncated-tag, and byte-tampering tests; the
independent direct-cipher tests in `mvm-core` remain. This is not a review of
the upstream cipher implementation or of the broader snapshot/session lifecycle.

## Mechanical gate

`clippy::undocumented_unsafe_blocks` is `deny` workspace-wide ([#5438](https://github.com/tinylabscom/mvm/pull/5438);
about 200 `SAFETY` comments were written after reading each site, and three packages that had skipped
the lint table now inherit it). The earlier unsafe documentation pass for `mvm-setpriv` and
`mvm-host-services` is [#4993](https://github.com/tinylabscom/mvm/pull/4993). The lint checks that a
comment exists, not that its claim is true; the sites were read, but a comment is not a proof.

## Reviewed areas and defects fixed

| Area reviewed | Defect class | Fixed in | Files read and found sound or fixed |
| --- | --- | --- | --- |
| Silent `let _ =` on teardown and rollback paths | cleanup failure discarded | [#4989](https://github.com/tinylabscom/mvm/pull/4989) | builder pipeline teardown, transient-run Ctrl-C handler, Firecracker `teardown_paused` restore branches, idle-pool claim rollback (`crates/mvm-backends/src/fc/idle_pool.rs`) |
| Production `unwrap` on guaranteed values | panic path encoded in types | [#4992](https://github.com/tinylabscom/mvm/pull/4992) | `embed_toolchain::strip_glibc`, stage0 nix-seed lift, `vm artifact` prefix resolution, TypeScript decorator site scan, manifest image validation |
| Panics and truncation on hostile sizes | arithmetic overflow, narrowing casts, lock poisoning | [#5168](https://github.com/tinylabscom/mvm/pull/5168) | `mvm-fs` ext4 writer and `elf.rs`; cpio writer in `mvm-builder-guest`; `mvm-agentd/src/process_rpc.rs` and `mvm-core` instance metrics locks. Census is heuristic (script, not a parser) |
| Unproven `expect`/`unwrap` in six crates | panic path | [#5352](https://github.com/tinylabscom/mvm/pull/5352) | `mvm-fs`, `mvm-net`, `mvm-client`, `mvm-bundler`, `mvm-http`, `mvm-hostd`; poisoned-mutex expects and static schema parses left alone on purpose |
| Other typed-error conversions | panic path | [#5075](https://github.com/tinylabscom/mvm/pull/5075), [#5083](https://github.com/tinylabscom/mvm/pull/5083), [#5139](https://github.com/tinylabscom/mvm/pull/5139) | empty workloads, bare image refs, unnamed persistent requests; agentd, vmm and hostd reachable panics; registry `block_on` bridge inside a tokio runtime |
| Persistent builder pid and kernel cache | signalling pid 0 (own process group); racy fixed staging name | [#5385](https://github.com/tinylabscom/mvm/pull/5385) | persistent-builder stop path, `extract_bundled_kernel` |
| Pid-file readers | corrupt pid file reaching `kill(2)` | [#5388](https://github.com/tinylabscom/mvm/pull/5388), [#5395](https://github.com/tinylabscom/mvm/pull/5395) | `EndpointPid::parse`, broker, audit-signer, network-endpoint, QEMU and GPU endpoint pid readers; one `signalable_pid` rule in `crates/mvm-vmm/src/host/process_liveness.rs` |
| Stale pid file at boot | boot proceeding past an unremovable pid file | [#4991](https://github.com/tinylabscom/mvm/pull/4991) | libkrun and QEMU boot paths |
| Killed boot-timeout child never reaped | kill without `wait()` leaves a zombie in a long-lived parent | [#5489](https://github.com/tinylabscom/mvm/issues/5489) | libkrun driver boot and vsock-timeout paths now kill and reap through `driver::kill_and_reap`, with a waitpid-based no-zombie test; the `hvf_restore.rs` sites are owned by #5490 and the `hvf/stop_state.rs` and `fc/idle_pool.rs` sites listed with the gap were test-only and already reaped |
| FlowMux registry and UDP relay | peer-chosen stream id overflow; unsolicited datagrams holding an association; UDP slot leak on open failure | [#5390](https://github.com/tinylabscom/mvm/pull/5390) | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs`, `udp_relay.rs`. The slot-leak fix has no test (needs fd or thread exhaustion) |
| HVF guest PC, SMP unwind, HTTP flow cancellation | guest-chosen PC overflow; panic wedging `thread::scope`; cancellation unwatched after response head | [#5402](https://github.com/tinylabscom/mvm/pull/5402) | `crates/mvm-runtime/src/backends/hvf/smp.rs` (non-test code), `http_flow.rs`, `open_flow.rs` lines 1-352 |
| HVF snapshot and cancellation lifecycle | pause/capture races, completion notification | [#4994](https://github.com/tinylabscom/mvm/pull/4994), [#5064](https://github.com/tinylabscom/mvm/pull/5064), [#4983](https://github.com/tinylabscom/mvm/pull/4983) | fixed under the HVF owner work; not re-read for this table |
| Volume, checkpoint and peer-EOF custody | custody, removal guard, EOF after timeout refusal | [#4880](https://github.com/tinylabscom/mvm/pull/4880), [#4957](https://github.com/tinylabscom/mvm/pull/4957), [#4864](https://github.com/tinylabscom/mvm/pull/4864), [#4879](https://github.com/tinylabscom/mvm/pull/4879) | fixed under the volume and vmm owner work; not re-read for this table |
| Unsafe/FFI documentation | missing `SAFETY` claims | [#4993](https://github.com/tinylabscom/mvm/pull/4993), [#5438](https://github.com/tinylabscom/mvm/pull/5438) | every `unsafe` block in the workspace has a comment; see the gate above |
| Restore readiness teardown | failed restore leaving its supervisor running | [#5490](https://github.com/tinylabscom/mvm/issues/5490) (fix on `fix/5490-hvf-restore-teardown`, PR pending) | `crates/mvm-backends/src/driver/hvf_restore.rs` (`await_restored`): both error returns after the ready marker now stop and reap the spawned supervisor through the owned child handle, with the outcome logged; the published record is validated by `restored_identity` and the pid read stays on the guarded `process_liveness` helper |

## Files NOT read

None of the following was read for lifecycle, ownership or cancellation defects. Treat them as
unreviewed.

- `crates/mvm-backends/src/driver/hvf_restore.rs` lines 1-380 and 620 to the end (the part between was read).
- Snapshot codecs: `crates/mvm-runtime/src/backends/hvf/snapshot.rs` and `crates/mvm-vmm/src/snapshot.rs`.
- `crates/mvm-runtime/src/backends/hvf/kernel_boot.rs`: most of `run_primary` and the device wiring.
- Tests in `crates/mvm-runtime/src/backends/hvf/smp.rs`.
- `crates/mvm-hostd/src/supervisor/endpoint/flowmux/`: `ingress.rs`, `tcp_relay.rs`, `open_flow.rs` beyond line 352, `socket.rs`, `wire.rs`, `resources.rs`.
- `crates/mvm-backends/src/driver/libkrun.rs` configuration building.
- Async cancellation safety outside FlowMux.
- The volume bridge beyond its wire codec (`crates/mvm-agentd/src/volume.rs`, `crates/mvm-client/src/volume/`).

## Known and unfixed

Found during the #5390 review and left alone. No item has a fix in flight; the owner is the
maintainer of the named area until an issue is opened, and the next step is a failing-before test
at the cited site, then the fix.

| Item | Site | Owner | Next step |
| --- | --- | --- | --- |
| `hvf/standby.rs` leaves the VM running when its pid is negative | `crates/mvm-backends/src/driver/hvf/standby.rs` | HVF owner | refuse and stop through the owned-stop path; test with a negative pid (tracked in #5491) |
| `HvfVm::create` did not destroy the VM or release the GIC config when GIC creation fails — fixed by an RAII guard (`PendingHvfVm`) over the setup seam (`VmSetup`), so every early return after `hv_vm_create` drops into cleanup, and by `commit` releasing the config on the success path too; cleanup order is unit-tested with a fake seam, the real-FFI check on a live HVF host is still owed (tracked in #5492, fix on branch `fix/5492-hvf-gic-guard`) | `crates/mvm-runtime/src/backends/hvf/hv_impl.rs` (`HvfVm::create`) | HVF owner | merge the fix, then confirm `mvmctl` launch/teardown on a real macOS HVF host (the failure itself is not injectable through the real framework) |
| FlowMux registry keeps `Closed` entries for the session lifetime (memory only, rate-limited) | `crates/mvm-hostd/src/supervisor/endpoint/flowmux/registry.rs` | hostd maintainer | evict closed entries on a bound; test that a long session does not grow without limit (tracked in #5493) |
