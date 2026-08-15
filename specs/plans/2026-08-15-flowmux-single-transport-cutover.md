# One transport: finish the FlowMux cutover and restore guest egress

**Issue:** [#2543](https://github.com/tinylabscom/mvm/issues/2543).
**Supersedes the production-path decisions in** `specs/plans/316-single-flow-vsock-networking.md`
Phases 2–4. Plan 316's phase issues (#2368, #2371, #2372, #2373) are all closed while the
work is demonstrably incomplete on `main`; this plan is where the remaining work is tracked.

## Status

**WS0–WS7 not started.** Guest egress is dead on `main`.

## Why

`2821e2dd4` ("Feat/316 guest flowmux adapter", #2480) made the in-guest `mvm-egress-client`
FlowMux-only: it loads a per-boot guest signing key and a host-signer anchor before binding
its loopback listener (`crates/mvm-agentd/src/bin/mvm-egress-client.rs:52-90`). Nothing writes
`/run/mvm/flowmux-guest-signing-key`, so the client exits 1, nothing listens on
`127.0.0.1:1080`, and every proxied fetch gets an instant `ECONNREFUSED`.

The mismatch is symmetric: no host spawn site selects FlowMux either. All five production
constructions of `SubstitutionSpawnParams` hard-code `flowmux_identity: None`, and Stage 0
hand-builds its config with `"egress_mode": "raw"` (`crates/mvm-build/src/libkrun_builder.rs:317`).
The host serves Raw/Wire; the guest speaks only FlowMux. This breaks all guest egress —
workload microVMs (`nix/lib/mk-guest.nix:786`) and the resident builder VM
(`crates/mvm-build/src/bin/mvm-host-vm-init.rs:1451`) use the same binary.

Plan 316's status header predicted this and said the two halves must land together with a
live witness.

## The decision: one transport

**Every byte between guest and host goes through one authenticated FlowMux session on
`GuestService::NetworkFlow` (port 5253). Nothing else.**

A dispatch-on-first-frame design was considered and rejected: it would leave three protocols
and a sniffing step on the guest→host channel permanently, and the sniff is itself the shape
of the bug that caused this outage — a mode chosen in one place and assumed in another.

| Guest dialer | Today on 5253 | After |
| --- | --- | --- |
| `mvm-egress-client` | FlowMux | FlowMux (unchanged) |
| `mvm-addon-dns` | FlowMux (2nd session) | FlowMux (unchanged) |
| `forward_proxy` (`substitution_client.rs:30-33`) | framed `WireRequest`, one conn/request | `OpenHttp` + `Http*` frames |
| `icmp_client` (`icmp_client.rs:85,101`) | `MVM_ICMP/1` line prelude, one conn/echo | new `Icmp*` opcodes |

Rationale:

- **One authenticated boundary.** `Wire`, raw and `MVM_ICMP/1` connections are
  per-connection and unauthenticated; only FlowMux carries the Ed25519-pinned,
  sequence-numbered session. Folding them in makes every guest→host byte authenticated,
  replay-checked and attributable to one pinned identity.
- **One policy gate and one audit point** instead of three paths that each have to remember
  to call `EgressGate` and emit payload-free audit.
- **The bug class disappears.** No `EgressMode`, no `raw_egress`, no mode selection to get
  wrong, no sniff. That is Plan 316 Phase 3's last checkbox, finally executable.
- **The expensive part is already built.** `OpenHttp`/`HttpRequestHead`/`HttpRequestBody`/
  `HttpResponseHead`/`HttpResponseBody`/`HttpComplete` (`0x50`–`0x55`) exist in
  `crates/mvm-contract/src/protocol/network_flow/opcode.rs:65-77` with `FlowClass::Http`,
  state-machine coverage and fuzz targets. The substitution *logic* — placeholder → real
  credential, host-originated TLS, claims 12/13 — stays in
  `network_endpoint_proxy::SubstitutionService`. Only its framing moves.

**Cost, stated plainly.** This touches the secret-bearing path. Two mitigations are
non-negotiable: `SubstitutionService` is not rewritten, and a hard gate refuses to inject
`mvm-secret-<hex>` placeholders into a guest unless the substituting flow is live. Today
placeholders are minted and injected regardless, because `can_skip_substitution_assembly` is
Raw-only (`mvm-network-endpoint.rs:330-336`) — that is how a half-finished cutover could
silently ship a placeholder to a real upstream.

**One transport, several sessions.** `forward_proxy` and `icmp_client` live in
`mvm-guest-agent`, a different process from `mvm-egress-client`, so they cannot share one
socket without an in-guest session broker. The host accepts N concurrent FlowMux sessions per
VM, all the same protocol, all pinned to the same guest key. That is still one transport —
one wire contract, one auth boundary, one gate. A broker collapsing them to a single session
is a later simplification, not a prerequisite.

## Workstreams

### WS0 — Stage 0 fails fast with the true cause

- [ ] `wait_for_vsock_egress_proxy_if_requested` (`crates/mvm-build/src/bin/stage0-init.rs:355-398`)
      returns a `Result` and aborts before `nix build` when the egress client exits or never
      binds, naming `mvm-egress-client` and its exit status; `dump_vsock_egress_diagnostics()`
      still runs
- [ ] Decision extracted as a pure `egress_readiness_outcome(...) -> Result<(), String>`,
      unit-tested without a VM, matching the `egress_child_exit_message` shape (`:341`)
- [ ] Mirrored in `crates/mvm-build/src/bin/mvm-host-vm-init.rs`
- [ ] The CLI surfaces the `stage0-init:` line instead of the downstream nix noise
- [ ] `cmdline_overflow` (`crates/mvm-vmm/src/host/cmdline.rs:30-52`) enforced on both
      builder paths — `libkrun_builder.rs:204` and `qemu_builder.rs:231` validate nothing today

### WS1 — Host accepts sessions properly — **complete**

- [x] `serve_flowmux` is an accept loop; the listener is adopted once and re-armed per
      connection rather than consumed by the first accept
- [x] Concurrent sessions per VM, each via `FlowMuxSession::accept_with_recorder`; a session
      that ends is logged and the loop continues, and a run of consecutive accept failures
      (16) fails the endpoint rather than spinning
- [x] `RegistryLimits::default()` recorded explicitly: still defaults, still because the
      spawner does not thread the admitted plan's `NetworkLimits` through. Built per session
      so one session's accounting cannot be spent by another

**FlowMux mode had never worked at all.** `bind_transport` sets the UDS listener
non-blocking so the Wire and raw loops can adopt it into tokio; the FlowMux path accepted it
on a blocking thread, where it returns `EAGAIN` immediately and forever. The first
connection failed with `Broken pipe` before any handshake. So the missing guest identity was
not the only thing standing between `main` and a working cutover — this was too, and it was
invisible because nothing exercised the path. The listener is now adopted per transport:
tokio for UDS, `spawn_blocking` for the blocking vsock listener, with each accepted
connection handed on as a blocking `UnixStream` for the session thread.

Witness: `a_flowmux_endpoint_keeps_serving_sessions_after_one_ends`
(`crates/mvm-hostd/tests/network_endpoint_bin.rs`) drives three real authenticated handshakes
against the real binary — one, then one after it ends, then one concurrent with that.
Confirmed red on the pre-fix binary (`Broken pipe` on the first handshake) and green after.
It deliberately asserts a *completed handshake* rather than a successful `connect()`: a unix
socket accepts into its backlog while the listener is open, so a connect-only assertion
passes against the broken version and proves nothing. The first draft of this test did
exactly that and had to be rewritten.

### WS2 — Per-boot identity, delivered off the cmdline — **complete**

- [ ] `mint_flowmux_identity(session_id) -> (FlowMuxIdentity, [u8; 32])` — one helper, so the
      private half and the published `guest_verifying_key_base64` cannot drift. Host key is
      the existing signer at `~/.mvm/keys/host-signer.ed25519`, so no second trust root
- [ ] Per-boot read-only ext4 identity drive built with the pure-Rust writer (`mvm-fs`, no
      `mkfs`, no subprocess), mounted **by label** not device order, carrying the 32-byte key
      (mode 0400) and the anchor. Reuses the already-hardened `/mnt/config` mount
      (`nix/lib/mk-guest.nix:432-437`, `ro,noexec,nosuid,nodev`) whose host-side producer was
      deleted (`crates/mvm-runtime/src/microvm/boot_config.rs:37-47` is a `bail!`)
- [ ] Attached on all three tiers; provisioned through the shared choke point
      `guest_bootstrap::provision_guest_environment()`
      (`crates/mvm-agentd/src/guest_bootstrap.rs:25-35`), plus `stage0-init` and
      `mvm-host-vm-init` before their `fork_vsock_egress_client_if_requested` sites
- [ ] `nix/lib/mk-guest.nix:595-612` — the host-signer anchor block is lifted out of
      `if [ -n "$MVM_VERB_GRANT_B64" ]`, matching the host's deliberate ungating
      ("identity is not authority", `crates/mvm-vmm/src/host/egress_bridge.rs:28-41`)

**The signing key must not ride the kernel cmdline.** It is world-readable at `/proc/cmdline`
by the workload's own uid 901, logged verbatim by
`crates/mvm-runtime/src/workload_runner/runner/backend.rs:146`, echoed to the captured console
log under `loglevel=8` on the builder paths, and visible in host `ps` as `-append` on every
QEMU path. `crates/mvm-vmm/src/host/network_endpoint_spawn.rs:123-137` states the invariant:
"the intermediate key never enters the guest secrets drive — the same claim-13 'no key on the
guest' invariant".

**As built.** Two modules. `mvm_agentd::flowmux_drive` is the reading side, deliberately
*not* behind the `addons` feature — `flowmux_keys` is, because it pulls tokio, and the guest
inits must reach the drive without putting tokio in the sealed agent's closure. It owns the
label, the filenames, the ext4 superblock probe and the Linux mount/copy, using raw
`libc::mount` to match `guest_mount.rs` rather than enabling `nix`'s `mount` feature.
`mvm_vmm::host::flowmux_identity` is the writing side: it mints the keypair, assembles the
image **in memory** so the signing key never lands in a host temp file, writes it 0600, and
carries a hand-written redacted `Debug`. Both sides reference one set of constants, declared
on the reading side.

`stage0-init`'s duplicate superblock-label helpers were deleted in favour of the shared ones,
with their eight tests moved to where the code now lives.

The guest-side scan lives in `mvm-egress-client` itself rather than in each init: the
Nix-built `/init` is shell, and putting it there would mean a second copy of the label probe
written against busybox applets (`blkid`) this image does not otherwise use. Stage 0 and the
builder VM *also* provision early so they can refuse with a named cause rather than surfacing
a proxy that never bound; the helper is idempotent. `mk-guest.nix` keeps only the fix it
genuinely needed: the host-signer anchor is provisioned unconditionally instead of nested
inside the verb-grant check, which had left a grant-less run with no anchor.

The drive costs **373µs to build and 32KiB on disk** (measured, 20 runs, release), so putting
it on every boot does not weigh on the launch path — worth checking, since warm-start work
targets a p50 in the tens of milliseconds.

The device scan enumerates `/sys/class/block` rather than probing a fixed candidate list. A
fixed list is not safe: `mvm_vmm::host::spec_map::workload_blocks` assigns slots dynamically
after the fixed rootfs/verity/overlay four, so user volumes can push the identity drive past
the end of any list short enough to write down. Enumerating is independent of both position
and count — the same reasoning that puts a label on the drive at all.

Verified: 17 `flowmux_drive` + 9 `flowmux_identity` tests, `mvm-agentd` 668, `mvm-vmm` 532,
`mvm-build` 791 lib tests, and a clean `--workspace --all-targets --all-features` cross-check
for `x86_64-unknown-linux-gnu`.

### WS3 — Thread the identity to every spawn site

- [ ] `NetworkEndpointSpawnRequest` (`crates/mvm-runtime/src/workload_runner/runner/spawner.rs:10-19`)
      carries the identity; `RealNetworkEndpointSpawner::spawn` (`:32-55`) sets it
- [ ] Five test doubles updated (`runner.rs:1498`, `runner.rs:3288`, `claim.rs:343`,
      `crates/mvm-hostd/tests/workload_stream_plane.rs:52`,
      `crates/mvm-conformance/tests/steps/warm_claim.rs:168`)
- [ ] `raw_egress: bool` dropped from `SubstitutionSpawnParams`; the identity is mandatory, so
      `build_endpoint_config_json` (`crates/mvm-vmm/src/host/network_endpoint_spawn.rs:542`)
      stops selecting a mode at all
- [ ] `ClaimGuards::spawn_endpoint` (`crates/mvm-runtime/src/workload_runner/claim.rs:236-262`)
      loses `let raw_egress = inputs.secrets.is_empty()`
- [ ] `BuilderVsockEgressEndpoint::spawn_with_transport`
      (`crates/mvm-build/src/libkrun_builder.rs:306-390`) uses the shared config builder
      instead of hand-rolling JSON at `:311-318`

**At the end of WS3 the reported command works again.**

### WS4 — Fold substitution onto `OpenHttp`

- [ ] Guest `forward_proxy` keeps its loopback listener and `parse_proxied_request` but relays
      over FlowMux as `OpenHttp` → `HttpRequestHead` → `HttpRequestBody`*;
      `substitution_client` deleted
- [ ] Host `FlowMuxSession` dispatch (`crates/mvm-hostd/src/supervisor/flowmux.rs:346-415`)
      gains the `Http` arm; `flowmux/registry.rs:398` gains
      `Opcode::OpenHttp => FlowClass::Http`. The arm adapts onto the existing
      `SubstitutionService` — substitution, redaction, the claim-10 gate and payload-free
      audit are called, not reimplemented
- [ ] Bodies stream as bounded chunks instead of whole-body base64 JSON (the Phase 4 win)
- [ ] Hard gate: `can_skip_substitution_assembly` (`mvm-network-endpoint.rs:330-336`) keys on
      the substituting flow being available, and the failure is a launch failure

### WS5 — Fold ICMP in

- [ ] `IcmpEcho`/`IcmpReply`/`IcmpRefused` (`0x60`–`0x62`) with `FlowClass::Icmp` added to
      `crates/mvm-contract/src/protocol/network_flow/opcode.rs`, wired through the state
      machine and `Sender` tables
- [ ] Golden byte fixtures + fuzz seeds alongside the existing ones
- [ ] Guest `icmp_client` (`crates/mvm-agentd/src/icmp_client.rs:85,101`) drops the
      `MVM_ICMP/1` prelude; host dispatch arm reuses the existing handler and gate

### WS6 — Delete the alternatives

- [ ] `EgressMode`, `serve_wire`, `serve_raw` (`mvm-network-endpoint.rs:344-378`),
      `raw_egress.rs`'s guest-facing dispatcher, `WireRequest`/`WireResponse`, and every line
      marker (`MVM_ICMP/1`, `MVM_DNS/1`, `MVM_SOCKS5_UDP/1`, `MVM_HTTP_FORWARD/1`) removed.
      **Keep** `resolve_hostname_ips_pure` and the helpers
      `crates/mvm-hostd/src/supervisor/dns_handler.rs:41` and `socks5_udp.rs:46` still use
- [ ] `crates/mvm-hostd/fuzz/fuzz_targets/fuzz_datapath_ingress.rs` and
      `xtask/src/check_build_egress_callers.rs` checked for references
- [ ] An xtask gate asserts the guest→host channel has exactly one protocol — no
      `connect_host_vsock` caller that is not a FlowMux client, no line-marker constants.
      This is Plan 316 Phase 8's "one path, mechanically enforceable", and it is what would
      have caught #2480

### WS7 — Readiness fails closed

- [ ] `EndpointHandshake` (or a second line) reports the first authenticated session
      (`crates/mvm-hostd/src/bin/mvm-network-endpoint.rs:88-121`)
- [ ] The spawner treats endpoint-exit-before-session as a launch failure rather than
      detaching and forgetting (`network_endpoint_spawn.rs:707-709`)
- [ ] A session that fails to authenticate fails the launch — Plan 316 invariant 4, and
      Phase 2's remaining unchecked box. Nothing asserts this today

## Tests

### BDD — `features/suites/s2_egress_vsock/one_transport.feature`

Hermetic (gate every PR; these are what would have caught #2480):

- [ ] The guest and the host agree on one transport — compares what the guest adapters
      require against what the production spawner emits, via library calls, no VM
- [ ] There is exactly one guest→host protocol (drives the WS6 gate)
- [ ] A launch without a FlowMux identity is refused, not booted
- [ ] A secret-bearing workload boots only when substitution is live (the WS4 hard gate)
- [ ] `machine run --image alpine --dry-run` reports the transport, as a
      `hvf | libkrun | firecracker` Scenario Outline

`@live` (opt-in via `MVM_BDD_LIVE`; does not gate PRs):

- [ ] `machine run --image python:3.12 -- python -c "print(2 + 2)"` exits 0 and prints `4`
- [ ] `kernel build --which workload` succeeds from a cold cache and the console log contains
      `local vsock egress proxy ready at 127.0.0.1:1080`
- [ ] With the identity drive suppressed, the Stage 0 build fails in seconds naming
      `mvm-egress-client`, not a nix download error (WS0)
- [ ] `ping` works over FlowMux (WS5); a secret-bearing run substitutes over `OpenHttp` (WS4)

`mvm-conformance` gains `mvm-agentd` + `mvm-vmm` dev-deps; `cucumber` stays dev-only. Steps in
`crates/mvm-conformance/tests/steps/flowmux.rs`. No `@MVM-SEC-*` tags — behavioural scenarios,
not claim rows, so `tests/meta.rs` and `model/claims.toml` are untouched.

### Unit

- [ ] `mint_flowmux_identity`: minted private key ↔ published verifying key match
- [ ] Identity drive: build → mount-by-label → parse round-trip; length and mode assertions
- [ ] `build_endpoint_config_json`: identity present and mandatory (replaces
      `endpoint_config_json_carries_policy_and_raw_when_set`,
      `crates/mvm-vmm/src/host/network_endpoint_spawn.rs:1436`)
- [ ] Accept loop: a second connection after a dropped session is accepted; two guest
      processes both authenticate concurrently
- [ ] `OpenHttp` adapter: a placeholder-bearing request round-trips through
      `SubstitutionService`, the real credential never appears in a frame the guest could
      see, and a chunked body streams rather than buffering
- [ ] New ICMP opcodes: golden bytes, state-machine acceptance/refusal, fuzz seeds
- [ ] `egress_readiness_outcome`: exit-before-ready, timeout, ready
- [ ] A session that fails to authenticate fails the launch
- [ ] `cmdline_overflow` enforced on both builder paths

## Sequencing

WS0 → WS1 → WS2 → WS3 → (WS4 ∥ WS5) → WS6 → WS7. Each is independently green and shippable.

The guest client is already FlowMux-only, so **workload and builder egress stay broken exactly
as they are on `main` today until WS3 lands.** Nothing here makes anything worse; WS3 is the
step that unbreaks the reported command; WS4/WS5 are what let WS6 delete the alternatives. If
WS3 slips, say so in the PR rather than letting it be discovered.
