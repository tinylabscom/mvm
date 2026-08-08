# Plan 303 — Runtime hardening for production

**Status: IN PROGRESS**
**Owner:** host runtime
**Related:** ADR-001 (claims 5, 8, 9, 10, 12, 13, 14), ADR-014, ADR-020

## Why

Six gaps between what CI witnesses and what actually ships, found by auditing
the tree against a runtime-hardening review of production Rust services. Each
one is a place where the shipped binary behaves differently from the binary the
test suite exercises, or where an untrusted input reaches an unbounded
resource.

These are not hypothetical. The fuzz corpus already drives the ext4 writer, the
OCI unpacker, the vsock frame parser and the datapath ingress — all of it in a
profile that checks integer overflow, against a release binary that does not.

## Workstreams

### WS1 — Release-profile arithmetic and a witness lane

`[profile.release]` sets `opt-level`/`lto`/`strip`/`codegen-units` and nothing
else, so every shipped binary wraps silently on integer overflow: `mvmctl`, the
per-VM supervisors, the guest agent, the ext4 writer, the OCI unpacker, the
vsock frame parser, the IPv6 extension-header walk. The only mention of the
setting in the workspace is `crates/mvm-hostd/ebpf/Cargo.toml:17`, which
disables it deliberately (eBPF verifier constraints — leave it).

Turning it on converts silent wraparound into a panic. In the host daemons that
is fail-closed and correct. In the guest agent it is a crash, which is why WS4
lands the panic hook.

- [ ] `overflow-checks = true` in `[profile.release]`
- [ ] Add a `release-witness` profile inheriting `release` with `lto = false`
      and `codegen-units = 16`, so the lane pays for overflow checks and
      `debug_assertions = false` without paying LTO on a ~4,350-test suite
- [ ] CI lane running the claim-witness tests under that profile
- [ ] Triage every overflow the lane surfaces; fix, don't suppress

### WS2 — Audit-chain appends are neither atomic nor durable

`crates/mvm-hostd/src/supervisor/audit_file.rs` appends with
`writeln!(file, "{line}")` and drops the flock without an fsync.
`Write::write_fmt` issues at least two `write` syscalls (payload, then `\n`), so
a crash between them leaves a newline-less final line. The next append
concatenates onto it and `verify_audit_chain` reports drift that is
indistinguishable from tampering.

This is the substrate for claims 8, 12 and 14. A crash must not be able to
forge the signature of an attack.

- [ ] Build `line + '\n'` into one buffer and `write_all` it
- [ ] `sync_data()` before releasing the flock
- [ ] Test: a torn final line (no trailing newline) is rejected as truncation,
      not silently concatenated into the next entry

Note: PR #2239 (`fix/audit-chain-fork-races`) touches this file to widen
`flock_exclusive` visibility. Different function; expect a clean merge.

### WS3 — Unbounded reads on the OCI path

Two separate holes:

`crates/mvm-fs/src/oci/manifest.rs` reads the manifest body with `.bytes()`,
uncapped, and computes the SHA-256 *afterwards*. A hostile or MITM'd registry
streams a multi-GB body and mvmctl buffers all of it before any integrity check
runs. Allocation failure aborts the process — it cannot be caught.

`crates/mvm-fs/src/oci/layer.rs` caps the layer via `CacheWriterReader`, but
that cap counts *compressed* bytes. `UnpackOptions`
(`crates/mvm-fs/src/oci/unpack/mod.rs`) bounds path length and xattrs and
nothing else, so a gzip bomb passes the cap and writes unbounded bytes to disk.

- [ ] Cap the manifest body before it is buffered (OCI manifests are KBs;
      a few MB is generous) and reject over-cap before hashing
- [ ] Add decompressed-byte and entry-count caps to `UnpackOptions`
- [ ] Tests: over-cap manifest rejected before hashing; gzip bomb rejected at
      the decompressed cap; entry-count bomb rejected

### WS4 — Panic hygiene in the host daemons

No `set_hook` anywhere in the workspace. The supervisor is the one process that
holds secrets in the clear, and `xtask check-no-display-on-secret-types` cannot
reach a panic payload: it guards `Debug`/`Display` impls, not
`.expect(&format!("... {token}"))` or an `unwrap()` on an error type that
transitively carries a value.

`strip = true` also means release panics carry no symbolized backtrace, so the
`location()` field is the only signal.

- [x] Panic hook for the host daemon bins that sanitizes the payload through
      the existing `SecretsScanner`
      (`crates/mvm-hostd/src/supervisor/secrets_scanner.rs`) — reuse, do not
      write a second scanner
- [x] Hook is installed once and chains to the previous hook
- [x] Test: a panic carrying a known secret value produces a redacted record,
      and an ordinary message survives intact

Two items from the original draft were **dropped as actively unsafe**, found
while implementing:

- ~~Hook exits nonzero.~~ A panic hook runs for *every* panic, including ones
  about to be caught. Three sites depend on `catch_unwind` to contain a fault
  without losing the process — the observer pipeline, the gateway-bridge
  signer fan-out, and the host-services FFI boundary. A hook that exited would
  silently convert all three into crashes. Panic policy belongs at those call
  sites, which can tell a contained fault from a fatal one.
- ~~Hook emits a chain-signed `plan.panicked` entry.~~ The audit signer takes a
  mutex and a file lock, and the most likely way to reach this hook holding
  secret material is that something in that path just failed. Signing from the
  hook would deadlock on a lock already held, or hit a poisoned mutex and panic
  again — and a panic inside a panic hook aborts. Crash reporting that can kill
  the process it reports on is worse than none.

The hook therefore observes and redacts only, which is all a panic hook can
soundly do.

### WS5 — Observer panic must not vote Forward

`crates/mvm-hostd/src/supervisor/network/pipeline.rs` catches an `on_packet`
panic, logs, and `continue`s — which is Forward. The same function fails
*closed* twenty lines earlier when a rebuild is unparseable.

Severity today is low and the original write-up of this workstream overstated
it. Correcting the record:

- The fail-open is deliberate and was tested
  (`panicking_observer_is_isolated_and_forwards`, "panic must be isolated ->
  Forward"), not an oversight.
- The pipeline is reached only from `passt.rs` and `native_gateway.rs`, which
  are builder-VM / Stage 0 paths. No workload guest has a NIC, so this was
  never a live claim-10 hole.
- The only production `Observer` impl is `FlowCountMetrics`, a counter with
  `payload_tap: false` that does not override `on_packet`. Every `Verdict::Drop`
  in the tree is in a test module, and the observer list is host-allowlisted
  and empty by default.

So there is nothing on this path today that a panic could disarm, and blanket
fail-closed would mean a panicking metrics counter takes down builder-VM
networking — an availability regression bought with no security.

Resolution: split on the capability the observer already declares.
`payload_tap: true` is an observer saying it inspects contents, which is the
class that can return `Drop`; its panic fails closed. A telemetry observer
keeps today's isolate-and-forward, because it was never in a position to
withhold approval.

- [ ] Panic in a `payload_tap` observer maps to `PacketDecision::Kill` with an
      `ObserverPanic` reason
- [ ] Panic in a telemetry observer stays isolated (existing behaviour, kept
      deliberately rather than by omission)
- [ ] Tests for both halves, so neither can regress into the other

### WS6 — Landlock self-sandboxing for the process moat (Linux)

The `mvm-hostd` roles are separate processes precisely so that compromising one
does not yield the others. Today that containment is convention. Landlock makes
it kernel-enforced: `mvm-host-signer` needs only `~/.mvm/keys/`,
`mvm-audit-signer` only `~/.mvm/audit/`, `mvm-broker` needs no filesystem at
all.

Linux-only, kernel 5.13+, and it must be applied after the role knows which
paths it needs but before it accepts any input. Degrade to a warning where the
kernel lacks support — never fail a launch over a missing LSM.

- [ ] Per-role path allowlists derived from `mvm-core::config` helpers, not
      inline `$HOME` joins
- [ ] Applied early in each role's `main`, before threads or sockets
- [ ] Absent/unsupported kernel degrades with a `doctor`-visible warning
- [ ] `mvmctl doctor` reports the resolved sandbox state per role
- [ ] Tests: allowlisted path opens; non-allowlisted path is denied

### WS7 — Miri over the pure-Rust crates

~750 unsafe blocks, concentrated in FFI and the VMM device models, which Miri
cannot cross. The tractable targets are the pure-Rust ones on the untrusted
input path.

- [ ] Miri lane over `mvm-contract`, `mvm-core` crypto, and the `mvm-fs` ext4
      writer
- [ ] Nightly + manual dispatch, pinned toolchain, `continue-on-error` until a
      clean baseline holds

## Sequencing

WS1 and WS2 first — both are small and both close a witnessed-versus-shipped
gap. WS3 next as one PR (shared test surface, `unpack_layer` already fuzzed).
WS4 and WS5 together (both `mvm-hostd`). WS6 and WS7 last; they are additive
and platform-gated.
