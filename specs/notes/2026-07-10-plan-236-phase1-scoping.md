# Plan 236 Phase 1 scoping — host-authority boundary, runway into Phase 2A

**Date:** 2026-07-10
**Base:** `origin/main` @ `dd5924664`
**Companion to:** `specs/plans/236-host-authority-runtime-roadmap.md`
**Purpose:** turn Phase 1's five checkboxes into concrete, sequenced work, and
establish the dependency chain into Phase 2A (workload data plane honestly
vsock-only). Analysis only — no code changed by this pass.

## Bottom line

The go-checker (`scripts/check-plan-236-go.sh`) is GO: two prerequisites are
merged on `main`, three refresh lanes are aligned. The remaining Phase 1 work is
not the port-handler registry (that landed as Plan 240, complete) — it is the
**authority wiring on the vsock-only backends (libkrun, HVF)**. Firecracker is
complete and live-proven; libkrun and HVF are the gap, and they are exactly the
backends Phase 2A rides on.

Three findings gate Phase 2A, in order:

1. **Verb-grant enforcement is not wired on the vsock-only path.** HVF appends
   no grant tokens; the OCI `/init` never delivers the host-signer trust anchor.
   A grant boot today denies everything (libkrun) or enforces nothing (HVF).
2. **`no_guest_nic` is dishonest on libkrun.** The capability contract is
   device-level ("no virtio-net device") but libkrun attaches a drained
   virtio-net device. Phase 2A's "honestly vsock-only" claim rests on this
   field.
3. **HVF spawns the egress endpoint universally.** libkrun already gates it on
   admitted policy; HVF must adopt the same admitted-runtime decision. This is
   the one net-new Phase 2A code delta.

Everything else in Phase 1 is classification and negative-path tests, below.

## Phase 1 checkbox status

| # | Checkbox | State | Owner section |
|---|----------|-------|---------------|
| 1 | Land remaining Plan 219 grant enforcement on the real boot path | **FC done; libkrun/HVF unwired** | §1 |
| 2 | Audit + classify guest protocol verbs | **ledger complete; 6 decisions open** | §2 |
| 3 | Remove/quarantine guest-defined mutable runtime state in prod | **candidates identified** | §2.2 |
| 4 | Make backend capability descriptors honest | **only libkrun dishonest** | §3 |
| 5 | Negative-path tests (no verb regain via reconnect/resume/fallback) | **matrix drafted** | §4 |

---

## §1 — Plan 219 grant enforcement on the vsock-only boot path (checkbox 1)

### Enforcement chain today

Host mint → config drive → guest `/init` → agent pin → audit:

- Host mints `verb-grant.json` when `plan.agent_verbs.is_some()`
  (`mvm-hostd/src/plan_admission.rs`).
- Host attaches the 32-byte host-signer pubkey to the config drive
  (`mvm-cli/src/commands/vm/up.rs:678`) — **block backends only**.
- Kernel cmdline carries `mvm.verb_grant=<hex>` + `mvm.require_grant=1`
  (`mvm-backend/src/microvm.rs:3048/3063`), appended by Firecracker
  (`microvm.rs:2392/2396`), qemu (`qemu.rs:148/152`), libkrun
  (`libkrun.rs:308/314`). **HVF appends neither** (`hvf_bootargs.rs`,
  `hvf/kernel_boot.rs`).
- Sealed mkGuest `/init` stages `host-signer.pub` + `verb-grant.json` into
  `/run/mvm/` (`nix/lib/mk-guest.nix:583-600`). The OCI injected `/init`
  (`mvm-guest/src/bin/mvm-oci-init.rs:147`) writes `verb-grant.json` but
  **never provisions `host-signer.pub`** — there is no config drive on the
  vsock path.
- Agent pins + enforces: `load_pinned_verb_grant` returns `None` when
  `host-signer.pub` is absent (`vsock.rs:1652`); `trust_decision` then yields
  `FailClosed` under `require_grant` (`vsock.rs:1735`), refusing every
  non-baseline verb.

### Per-backend coverage

| Backend | grant token | require_grant | signer pubkey reaches guest | can pin (selective enforce) | live-proven |
|---|---|---|---|---|---|
| Firecracker | yes | yes | yes (config drive) | **yes** | **yes** |
| qemu | yes | yes | yes (same image) | yes | no witness |
| **libkrun** | yes | yes | **no** (OCI init) | **no → deny-all** | no |
| **HVF** | **no** | **no** | **no** | **no → enforces nothing** | no |

### Root gap + work

The trust anchor ships only via the config drive, which exists only on block
backends. The vsock-only path needs an out-of-band channel.

1. Carry the host-signer pubkey on the kernel cmdline for the vsock/OCI path
   (`mvm.host_signer_pub=<hex>`), minted alongside the grant sidecar. Emit from
   `libkrun.rs` (~`:308`) and the HVF cmdline builder. Safe on `/proc/cmdline` —
   it is a public key.
2. Extend `mvm-oci-init.rs::provision_verb_grant` (`:147`) to decode that token
   and write `/run/mvm/host-signer.pub` (0644), mirroring
   `mk-guest.nix:583-599`.
3. Wire HVF cmdline (`hvf_bootargs.rs` + `hvf/kernel_boot.rs`) to append
   `verb_grant_cmdline_token` + `require_grant_cmdline_token`, matching
   `libkrun.rs:308/314`; add the parity unit test alongside
   `microvm.rs:4337/4402`.
4. Confirm the sealed libkrun/HVF workload `/init` is `mvm-oci-init` and that
   `mvm.require_grant=1` alone drives fail-closed on OCI (it does, via
   `trust_decision:1735`), or bake `/etc/mvm/verb-trust.json` into the OCI image
   as mkGuest does (`mk-guest.nix:1025`).
5. Add a unit test that a *pinned* grant on the OCI path serves listed verbs
   (not just deny-all) — closes the "libkrun can only deny everything" behavior.
6. Live end-to-end proof on libkrun + HVF (macOS 26): listed `RunEntrypoint`
   succeeds, unlisted `ProdSafe` → `VerbNotAuthorized`, `DevOnly` →
   `UnsupportedInProfile`, grant-less regression, `verb_denied` audit entry that
   `trust audit verify` accepts. Blocked today by the missing published
   workload-kernel checksum manifest for the OCI download path (Plan 219 open
   items 5c/5d).

Items 1–3 are missing wiring, 4–5 lock in selective enforcement, 6 is the
macOS proof that Phase 2A's admitted-policy signal depends on.

---

## §2 — Guest protocol verb authority ledger (checkboxes 2, 3)

### 2.1 Boundary shape

The naming misleads: **`GuestRequest` is host→guest** — the host requests, the
guest enforces (VerbGrant + `AgentProfile`). Genuinely guest-originated surfaces
are `HostBoundRequest`, broker `ServiceCall`, substitution, and egress.

Two independent gates, not to be conflated:

- **VerbGrant** (family 1, `GuestRequest`): signed cmdline envelope, Ed25519 vs
  host-signer + session_id + plan nonce, per-call intersected
  (`vsock.rs:1447/1543`), plus compile-time `AgentProfile` class gate
  (`vsock.rs:854/920`).
- **Service binding** (family 3, claim 12/ADR-059):
  `RegisterVm.services_bindings` → `Registry::dispatch` → `NotBound`
  (`registry.rs:41-58`).

Classification (full table in the appendix ledger, kept in the source audit):

- **host-authority-request** (prod, gated): `WorkerStatus`, `SleepPrep`, `Wake`,
  `Ping`, `IntegrationStatus`, `CheckpointIntegrations`, `ProbeStatus`,
  `PrimedStatus`, `RunEntrypoint`, `PostRestore`, `EntrypointStatus`,
  `ReadinessStatus`, `MountVolume`, `UnmountVolume`, `UpdateIdleTimeout`;
  broker `host.time.v1`, `host.cost.v1`, `host.secrets.v1`, `host.audit.v1`;
  substitution + `EgressRequest` (guest-chosen within signed allowlist).
- **host-only-control-socket** (no guest path): `ControlRequest`,
  `HostdRequest`, `AgentRequest`, `HostVmRequest`.
- **prod-disallowed** (`dev-shell`-gated, absent in sealed prod): `Exec`,
  `ExecBatch`, `RunDetached`, `RunCode`, `FsDiff`, `StartPortForward`,
  `StartUnixSocketForward`, `Console*`, `Fs*` RPC (v1), `Proc*` RPC,
  `host.dev.echo.v1`.

### 2.2 Quarantine candidates (checkbox 3), ranked

1. **`UpdateIdleTimeout` (`vsock.rs:550`) — highest.** `ProdSafe`, mutates the
   warm-pool idle-recycle timeout at runtime. Host-originated under VerbGrant
   today, but it is the exact "guest sets timeouts" shape the checkbox targets.
   Decision: confirm host-authority-only and unreachable guest→host; consider
   sourcing the value from the signed session record, not an ad-hoc frame.
2. **`host.audit.v1::emit` / `emit_batch` — binding-gate bypass.** "Implicitly
   available, need not be listed" (`broker_control.rs:67`) — the one guest→host
   broker verb that bypasses ADR-059 binding dispatch. Bounded (append-only
   chain, dedup, rate-limited) but a documented bypass; make it an explicit
   Phase-1 decision.
3. **`StartPortForward` / `StartUnixSocketForward` — already quarantined**
   (`DevOnly`, `vsock.rs:890-891`). Confirm no prod re-enable path.
4. **`MountVolume` / `UnmountVolume`** — `ProdSafe` FS-topology mutation, bounded
   by `MountPathPolicy`. Record as host-authority-gated; lower risk.
5. **`RunEntrypoint { env }`** — `ProdSafe`, injects env after `env_clear()`.
   Confirm env is host/plan-sourced, never guest-influenced in prod.

### 2.3 Open gating decisions (checkbox 2 outputs)

1. **`HostBoundRequest::WakeInstance` / `QueryInstanceStatus`
   (`vsock.rs:2388/2394`) — clearest unguarded guest→host path.** Carries
   guest-supplied tenant/pool/instance IDs with no visible signed-plan binding
   or VerbGrant check. Decide: authorize caller identity against admission, or
   keep trusting guest-supplied IDs (and bound the blast radius).
2. **`host.audit.v1` binding bypass** — accept "implicit" long-term, or require
   an auto-granted binding for uniform dispatch gating.
3. **`UpdateIdleTimeout` classification** — host-authority-only vs quarantine.
4. **Fs RPC graduation** — which `Fs*` verbs (currently blanket `DevOnly` "in
   v1") become host-authority-request, under what path policy.
5. **`RunEntrypoint.env` provenance** — confirm plan-sourced.
6. **`AgentRequest::Reconcile` (unsigned) vs `ReconcileSigned`** — confirm the
   unsigned path is unreachable in prod, mirroring the `dev-shell` symbol strip.

---

## §3 — Capability descriptor honesty (checkbox 4)

Contract: `VmCapabilities` (`mvm-core/src/protocol/vm_backend.rs:519-569`).
`no_guest_nic` is defined device-level: "no virtio-net device." Selection
matches via `shortfall()` fail-closed — a dishonest `true` silently seals a
workload onto a backend that does not meet the requirement.

| Backend | vsock | no_guest_nic | host_vsock_proxy | honest? |
|---|---|---|---|---|
| **libkrun** | ✅ | **❌** | ✅ | **no** — `Disconnected` mode attaches a drained virtio-net device (`libkrun-sys/src/lib.rs:751`); supervisor comments say the NIC is intentionally retained pending an unshipped "Phase B" (`mvm-libkrun-supervisor.rs:185-186`) |
| **HVF** | ✅ | `proxy_path_ready` | `proxy_path_ready` | behaviorally honest (VMM has no `add_net` at all), but overloads `false` = "not launchable," not "has a NIC" |
| Firecracker | ✅ | `false` | `false` | ✅ (real TAP + passt + nft `:80/:443` redirect; sole claim-10 egress-enforced backend) |
| qemu | ✅ | `false` | `false` | ✅ (slirp NIC, dev/test) |
| mock | `false` | `false` | `false` | ✅ |

Work:

1. **[blocker] libkrun `no_guest_nic`.** Either redefine the field to "no
   usable/routed guest NIC" and update the doc-comment + every consumer's
   assumption, or land the "Phase B" device removal so it is truly absent. Until
   one lands, selection can seal a workload believing there is no NIC when a
   drained one is present.
2. **[HVF] decouple capability (always NIC-free) from availability**
   (`is_available`). Phase 2A must not read HVF `no_guest_nic=false` as "NIC
   attached."
3. **[libkrun builder, confirm]** `stage0-init.rs:220` still sets a slirp
   gateway inert under `Disconnected` — verify vestigial, not relied on.
4. Doc tidy: `libkrun.rs:56-57` describes a NativeGateway `:80/:443` path the
   vsock-only libkrun path never spins — misleading comment, not a runtime bug.

---

## §4 — Negative-path test matrix (checkbox 5)

Prove production guests cannot regain forbidden verbs or widen authority through
reconnect, resume, or fallback. Existing coverage is largely unit-level; the
gaps below are the checkbox-5 deliverable.

| Threat | Vector | Assertion | Backend(s) | Exists? |
|---|---|---|---|---|
| Verb regain via reconnect | drop + re-open vsock control, replay pre-grant `ProtocolHello`, then a `DevOnly` verb | still `FailClosed`/`VerbNotAuthorized` | libkrun, HVF, FC | **missing** (FC has grant-less regression only) |
| Verb regain via resume | `PostRestore` re-pin with a stale/absent grant envelope | refuses to widen; keeps prior fail-closed | all warm-path | **missing** |
| Verb regain via fallback | auto-fallback backend (ADR-093) lands on a backend that never wired grants | fail-closed, not enforce-nothing | HVF→libkrun | **missing** (depends on §1) |
| Grant-less deny-all | boot with `require_grant=1`, no pinned grant | every non-baseline verb refused | libkrun, HVF | **missing on vsock-only** |
| Pinned-grant selective serve | boot with a valid pinned grant | listed verbs served, unlisted refused | libkrun, HVF | **missing** (§1 item 5) |
| Binding-gate bypass | unbound `ServiceCall` to `host.time.v1` | `NotBound`; `host.audit.v1` bypass is the only intended exception | all | partial (claim-12 tests) |
| Unguarded HostBound | `WakeInstance` with a forged tenant/instance ID | host authorizes vs admission (post §2.3 decision) | gateway path | **missing** |
| Capability dishonesty | select a sealed no-NIC workload onto libkrun | no routed NIC reachable from guest | libkrun | **missing** (§3 item 1) |

---

## §5 — Runway into Phase 2A

Phase 2A ("workload data plane honestly vsock-only") consumes three Phase 1
outputs. Sequencing:

- **Registry (2A checkbox 1): done.** Plan 240 folded the vsock port-handler
  registry into `mvm-backend/src/vmm/vsock_handlers/`; readiness-driven host I/O
  (`poll_fds`) replaced the 5 ms backstop; no code residual.
- **No workload spawns gvproxy/passt/native-gateway today** on libkrun or HVF.
  The only NIC artifact is libkrun's drained virtio-net device (§3).
- **Endpoint spawning — the one net-new 2A delta.** libkrun already gates the
  egress/substitution endpoint on admitted policy (deny-all no-secret → no
  endpoint, `EGRESS_PORT` unbound, fail-closed via `ECONNREFUSED` —
  `libkrun.rs:58-88`, `egress_server.rs:128-134`). **HVF spawns it
  unconditionally per VM** (`hvf_backend.rs:140-185`, call site `:347-355`).
  Make `spawn_hvf_gating_endpoint` conditional on
  `network_policy.allows_egress() || state_has_bound_secrets`; skip + leave the
  relay socket unbound for deny-all no-secret; harden the HVF supervisor relay
  (`mvm-hvf-supervisor.rs:211-224`) for an absent socket.
- **Dependency gates:** the HVF endpoint-gating change must not land ahead of
  §1 (macOS verb-grant enforcement) and §3 item 1 (honest `no_guest_nic`),
  because both feed the "admitted policy is authoritative" premise the gating
  decision relies on.

Missing 2A witnesses (Phase 2C-adjacent, but they guard the 2A regression
surface): automated no-gvproxy/no-passt process-absence; workload "no routed
NIC" assertion; deny-all-skips-endpoint (post HVF change); live macOS+Linux
host-mediated-egress-under-admitted-policy workload witness; CI/lint gate
against new guest-NIC attach points and legacy helper spawn sites.

---

## §6 — Ordered execution plan

1. **§1 items 1–3** — wire the host-signer pubkey channel for the OCI path +
   HVF grant tokens. Unblocks selective enforcement on both vsock-only backends.
2. **§1 items 4–5** — tests locking selective-serve (not deny-all) on OCI.
3. **§3 item 1** — resolve libkrun `no_guest_nic` honesty (redefine or remove).
4. **§2.3 decisions** — settle the six open gating questions; quarantine per
   §2.2 outcomes.
5. **§4 matrix** — land the negative-path tests, especially the vsock-only and
   fallback rows.
6. **§1 item 6** — macOS live proof (gated on the workload-kernel checksum
   manifest).
7. **Enter Phase 2A** — HVF endpoint gating (§5), then witnesses.

Steps 1–3 are the true critical path into Phase 2A. The rest can proceed in
parallel once the vsock-only authority wiring lands.

## Decisions (resolved 2026-07-10)

- **§3.1 — `no_guest_nic`: redefine, do not remove the device.** The field means
  "no host-routable guest NIC," set honestly: libkrun `true` (drained sink
  device, no route), HVF `true` (no device), FC/qemu `false`. Rename to make the
  semantic self-evident (e.g. `no_routable_guest_nic`). Rationale: the
  security-relevant property is reachability (satisfied by the drained sink +
  `Disconnected`-only supervisor enforcement), not device presence; libkrun is
  transitional (HVF is the device-free destination) so device surgery on a sunset
  dep is low-ROI; a hard `false` would wrongly exclude libkrun from sealed
  selection. Record the residual: libkrun's drained virtio-net device is still an
  untrusted-input surface HVF does not have.
  **Scope confirmed:** contained in-process hard-rename — `VmCapabilities` /
  `RequiredCapabilities` carry no serde, so no wire/on-disk contract and no mvmd
  coordination. ~15 sites across `mvm-core`/`mvm-backend`/`mvm`+`mvm-cli`
  (producers `hvf_backend.rs:277`, `libkrun.rs:483`; consumers `machine/mod.rs:174`,
  `exec.rs:320`, `commands/vm/exec.rs:1269`). Change the shortfall diagnostic
  literal `"no_guest_nic"` (`vm_backend.rs:620`) and its assertion
  (`exec.rs:1560`) together.
- **§1.4 — OCI verb-trust anchor: bake `/etc/mvm/verb-trust.json` into the
  sealed image.** The require-grant *policy* lives in the dm-verity-sealed rootfs
  (intrinsic, tamper-evident, fail-closed regardless of launch args); the kernel
  cmdline carries only the *grant envelope + signer key*. Bake for `--prod`/
  sealed OCI images only, mirroring `mk-guest.nix:1025`. Rationale: cmdline-only
  `require_grant` is fail-OPEN at the image level (a launch that omits the token
  enforces nothing); a sealed artifact must assert its own posture.
- **§2.3.1 — `HostBoundRequest`: dead surface, LOW priority — prefer deletion.**
  Reachability check: the enum is entirely unwired — no host listener on
  `HOST_BOUND_PORT=53`, no guest dialer, no dispatch anywhere (only serde
  round-trip tests reference it). Port 53 is never added to any VM's vsock
  allowlist. Not reachable by an untrusted workload — not reachable by anyone. It
  is gateway-VM-only by design intent and on a deprecation path (superseded by
  the signed broker on `:5300`). So there is no live authority hole to close now;
  the cleaner move is to delete the `WakeInstance`/`QueryInstanceStatus` variants
  rather than harden them. If the reverse channel is ever wired, it must derive
  caller identity from admission, never trust guest-supplied IDs.

## Still open

- §2.3.2 — keep `host.audit.v1` binding bypass, or require an auto-granted
  binding for uniform dispatch gating.
- §2.3.4 — which `Fs*` RPC verbs graduate to host-authority-request, under what
  path policy.
- §2.3.6 — confirm `AgentRequest::Reconcile` (unsigned) is unreachable in prod.
