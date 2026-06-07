# Plan 74: Claim-safe sandbox parity

**Status:** In progress
**Date:** 2026-05-14 (last status refresh: 2026-05-15)
**ADR:** [`../adrs/048-claim-safe-sandbox-parity.md`](../adrs/048-claim-safe-sandbox-parity.md)
**Goal:** make the seven target sandbox claims defensible for `mvm` without weakening the existing signed-plan, audit, verified-boot, and Nix-first security posture.

## Status at 2026-05-15

| Workstream | Status | Notes |
|---|---|---|
| **W0 — Claims hygiene + docs guardrails** | **Shipped** | xtask `check-doc-claims` lint + feature-status page + mvmforge cleanup all landed. |
| **W1 — OCI image ingest** | **Mostly shipped** | mvm-oci crate, OCI unpack with R10 mitigations, ext4 materialization, verity sealing, *and* the full runtime overlay disk sub-arc (ADR-051) all shipped. **Remaining:** `mvmctl image pull/ls/rm` CLI, `mvmctl up --image`, mutable-tag policy hook, per-step OCI audit records. |
| **W1.4b — Runtime overlay (sub-arc)** | **Shipped (Firecracker)** | 7-PR end-to-end stack landed: flake → resolver → orchestrator → install → verity-init mount → backend wiring → mkGuest target → release pipeline → host download → `mvmctl overlay` CLI → auto-fetch on `up`. libkrun + Apple Container overlay attachment **deferred** (both need their own verity story; tracked on mvm side under "drop baked-in agent"). |
| **W2 — Programmable network policy** | **mvm side mostly shipped; mvmd side rolled out via Plan 51** | Layer 1 (guest-side defense via `mvm-guest-netinit` + audit emission), Layer 2 (host iptables mandatory-deny), audit-kind vocabulary, DnsPin types, and vsock-RPC inbound audit infrastructure (helper + ~18 call sites migrated) all shipped on mvm. **Remaining on mvm:** IPv6 mandatory-deny, iptables-LOG → nflog consumer for per-flow events, `overlayAware` admission gate, OCI overlay copy of netinit. **Layer 3 (DNS resolver) + Layer 4 (L7 proxy) + Layer 5 (VPC firewall):** owned by mvmd Plan 51, not mvm. |
| **W3 — Secret placeholders** | **Not started** | Architecture exists in ADR-049 (TLS substitution mechanism). Implementation work hasn't begun. |
| **W4 — SDK-owned lifecycle** | **Not started** | |
| **W5 — Cold-start measurement** | **Not started** | |
| **W6 — Extensible filesystem backends** | **Not started** | |

## Sequencing recommendation for what's next

The unblock-the-most-downstream-work order:

1. **W1 remainder (`mvmctl image` CLI surface)** — small slice; OCI ingest is already shipped at the primitive level; missing only the user-facing verbs. Closes the `oci-ingest` claim per ADR-048.
2. **W2 deferreds in any order** — IPv6 mandatory-deny, nflog consumer, `overlayAware` admission gate, OCI overlay netinit copy. Each is independent and small.
3. **W5 (cold-start measurement)** — orthogonal to security work; unlocks the latency claims in ADR-048 once measurement methodology + CI gates land.
4. **W3 (secret placeholders)** — large; depends on mvmd Plan 51 L7 proxy for the substitution path.
5. **W4 (SDK lifecycle)** — depends on the lifecycle contract design being settled.
6. **W6 (filesystem backends)** — substantial; lowest priority among the security claims.

Cross-repo: mvmd Plan 51 W1-W7 owns the fleet-side enforcement (DNS resolver, L7 proxy, audit aggregation, inbound flow audit, VPC bridges). mvm's W2 deferreds are *additional* defense-in-depth that lands independently.

## Workstreams

### W0 — Claims hygiene and docs guardrails — **Shipped**

**Goal:** stop overclaiming before runtime work lands.

- [x] Add a public feature-status table: Shipped, Preview, Planned, Not claimed.
- [x] Update Python SDK docs that still reference `mvmforge` instead of the current `mvm`/`mvmctl` surface.
- [x] Add a docs check that blocks phrases like "any OCI image", "secrets cannot leak", and "<100ms" unless the corresponding claim gate file is marked Shipped.
- [x] Update the external-sandbox gap-analysis note to include current SDK directories and mvmd ADR-0020 (external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`).

**Verification:**

- Documentation-only test or xtask grep fails on gated claim phrases outside approved files.

### W1 — OCI image ingest — **Mostly shipped**

**Goal:** `mvmctl image pull <ref>` materializes OCI images into microVM artifacts.

- [x] Add `mvm-oci` or `mvm-build::oci` module for registry resolution, auth, manifest fetch, layer fetch, and digest verification. *(W1.1 + W1.2)*
- [x] Implement OCI layer unpack with whiteout, symlink, hardlink, ownership, permissions, xattr policy, env, entrypoint, workdir, and exposed-port extraction. *(W1.3a with R10 attack-surface mitigations)*
- [x] Materialize to ext4/rootfs artifact compatible with existing backend launch. *(W1.3b deterministic ext4)*
- [ ] Register pulled artifacts as templates with requested ref, resolved digest, source registry, and cache scope metadata.
- [ ] Add `mvmctl image pull`, `mvmctl image ls`, `mvmctl image rm`, and `mvmctl up --image`.
- [ ] Add policy hooks for mutable-tag rejection in production profile.
- [ ] Emit audit records for resolve, fetch, cache hit, materialize, verify, launch, and delete.

**Sub-arc — W1.4b runtime overlay (ADR-051):** Shipped end-to-end on Firecracker. Flake → resolver → orchestrator → install_overlay_into_cache → mvm-verity-init runtime extension → Firecracker backend drive attachment → mkGuest overlay-aware rootfs → release pipeline artifact → host download_runtime_overlay → `mvmctl overlay {fetch,status}` → auto-fetch on `mvmctl up` cache miss. libkrun + Apple Container overlay attachment deferred to a follow-up (both need verity wiring on those backends first).

**Tests:**

- Unit fixtures for whiteouts, symlinks, hardlinks, file modes, invalid manifests, digest mismatch, and max-size rejection.
- Integration test running `alpine` or a hermetic local registry fixture through `mvmctl up --image`.
- Negative tests for mutable tag rejection under production policy and private cache isolation.

### W2 — Programmable network policy — **mvm side mostly shipped; fleet side in mvmd Plan 51**

**Goal:** ship the L7 path currently represented as plan/stub work.

- [~] Implement supervisor-owned DNS resolver with admission-time pinning. *(DnsPin + DnsPinRegistry types shipped — `mvm-core::policy::dns_pin`. The resolver implementation moves to mvmd Plan 51 W3 — supervisor lives there.)*
- [ ] Wire all guest egress through the trusted proxy for restricted policies. *(L7 proxy is mvmd Plan 51 W4.)*
- [ ] Enforce HTTP Host and HTTPS CONNECT/SNI policy. *(Part of mvmd Plan 51 W4.)*
- [x] Block metadata endpoints and local control-plane ranges by default. *(`MANDATORY_DENY_RANGES` data + Linux-host iptables wiring on Layer 2 + `mvm-guest-netinit` kernel blackhole routes on Layer 1, with `NetworkMandatoryDeny` audit emission.)*
- [x] Add per-plan network policy objects with explicit defaults. *(`NetworkPolicy`/`EgressMode`/`HostPort`/`NetworkPreset` types in `mvm-core::policy::network_policy`; default is deny-all.)*
- [x] Emit audit entries for every allow/deny and DNS pin/reject event. *(5 `LocalAuditKind::Network*` + `DnsPin*` variants reserved; `NetworkMandatoryDeny` emission live for the netinit Layer 1 install; `NetworkPolicyAllow scope=rpc,direction=in,kind=vsock,verb=…` emission live across ~18 host→guest vsock call sites. `DnsPinSet` / `DnsPinReject` emission lands with the mvmd resolver + L7 proxy.)*

**mvm-side W2 deferreds (small, independent):**

- IPv6 mandatory-deny (when the guest bridge gains v6).
- iptables `-j LOG` → nflog consumer for per-flow `NetworkMandatoryDeny` events (today's audit emit covers rule-install only, not per-flow drops).
- `overlayAware` admission gate — refuse cached pre-W1.4b templates whose rootfs is missing the `/mvm/runtime` bind-mount target.
- OCI overlay copy of `mvm-guest-netinit` so OCI-imported workloads also get Layer 1 defense (stacks on the W1.4b runtime overlay landing, which is shipped on Firecracker).

**Tests:**

- DNS rebinding denied.
- Raw IP bypass denied.
- Wrong SNI denied.
- HTTP Host mismatch denied.
- `169.254.169.254` and local control-plane ranges denied.
- Allowed destination succeeds and records audit.

### W3 — Secret placeholders and host-side substitution

**Goal:** default secret flow prevents real secret values from entering guests.

- [ ] Add `SecretPlaceholder` type with opaque token, plan id, secret name, allowed destinations, expiry, and grant id.
- [ ] Update SDK/IR secret references to request placeholder mode by default.
- [ ] Implement supervisor grant registry with revoke-on-stop/crash/timeout/parent-death.
- [ ] Integrate substitution with the L7 egress proxy after destination policy passes.
- [x] Define SDK credential-loading substitution handlers for SigV4-shaped auth: Python, TypeScript, and Rust expose `register_substitution_handler(name, fn)` plus built-in AWS credential helpers that resolve placeholders before request signing.
- [ ] Add redaction wrappers for plan JSON, logs, audit, errors, route labels, and cache keys.
- [ ] Keep legacy env/file injection behind an explicit `unsafe_guest_secret_materialization` flag.

**Tests:**

- Guest receives no real secret in env, files, argv, logs, plan JSON, or audit.
- Placeholder only substitutes for approved destination.
- Redirect to unapproved destination fails closed.
- Wrong SNI and plaintext HTTP do not receive substitution.
- Grant revokes after stop, crash, and parent death.
- AWS S3 `ListBuckets`-shaped SigV4 signing computes the signature from resolved credentials, not placeholder strings.

### W4 — SDK-owned lifecycle

**Goal:** Python, TypeScript, and Rust SDKs can own local sandbox lifecycle without shelling out through an undocumented path.

- [ ] Define shared lifecycle contract: `create`, `exec`, `files.read/write/list/remove`, `logs`, `snapshot`, `fork`, `stop`, `destroy`.
- [ ] Add a stable local control API in Rust and bind it to Python/TypeScript.
- [ ] Implement parent-process lease and cleanup semantics.
- [ ] Add explicit detach mode for long-running sandboxes.
- [ ] Keep static decorator compilation separate from lifecycle execution; no importing user code to inspect it.

**Tests:**

- Same fixture suite runs against Rust, Python, and TypeScript SDKs.
- Parent process death cleans up non-detached sandboxes.
- Detached sandboxes survive and are discoverable by CLI.
- Error paths redact secrets.

### W5 — Cold-start measurement and budgets

**Goal:** publish measured latency claims with reproducible methodology.

- [ ] Extend `runtime_boot_bench` and `cargo xtask perf boot` into one canonical harness.
- [ ] Record backend, host, CPU, memory, vCPU, kernel digest, rootfs digest, storage mode, readiness signal, and run count.
- [ ] Report fresh start-return, guest-agent-ready, snapshot restore, warm-pool claim, and SDK create-to-exec separately.
- [ ] Store benchmark reports under `specs/perf/` or public docs with exact command lines.
- [ ] Add CI budget gates for representative artifacts.

**Initial claim target:**

- Do not claim `<100ms` cold boot until p95 fresh guest-agent-ready supports it.
- It is acceptable to claim faster warm-pool or snapshot numbers if those are measured and labeled.

### W6 — Extensible filesystem backends

**Goal:** make filesystem backend extensibility a tested contract, not just a trait.

- [ ] Split the current storage contract into mountable and API-only capability flags.
- [ ] Add conformance tests for local, encrypted, object store, and memory backends.
- [ ] Define consistency and rename semantics for object stores.
- [ ] Add path traversal, symlink escape, concurrent write, and large-file tests.
- [ ] Add audit records for attach, detach, read, write, delete, rename, snapshot, and backend health failure.
- [ ] Expose mountable backends through VM volume operations; expose API-only backends through guest agent or host-side file API.

## Cross-repo handoff to mvmd

`mvmd` may expose a capability only after the owning `mvm` primitive has a stable API and tests. The handoff contract for each workstream is:

| mvm workstream | mvmd consumes |
|---|---|
| W1 OCI ingest | Tenant image policy, Sandboxfile image fields, API/CLI `--image` |
| W2 network policy | Tenant egress/DNS policy and fleet audit aggregation |
| W3 placeholders | Tenant secret providers and cross-node grant revocation |
| W4 SDK lifecycle | Generated API SDKs and MCP sandbox server behavior |
| W5 benchmarks | Fleet-facing latency claims and warm-pool SLOs |
| W6 filesystem | Managed storage, buckets, encrypted/object-store backends |

## Risks

The workstreams above are sized to be independently shippable, but a
handful of cross-cutting risks can force architectural change late if
they go unnoticed. Each risk names the workstream(s) it threatens, the
current evidence, the failure mode if ignored, and the assigned
mitigation owner.

### R1 — Supervisor as concentrated trust surface (W2, W3)

**Current state.** `crates/mvm-supervisor/src/l7_proxy.rs:21,357`
implements L4 policy (proto/CIDR/port) only and emits one audit entry
per request (`flow.egress.allowed` / `flow.egress.denied`). The
keystore releaser (`crates/mvm-supervisor/src/keystore.rs:23-81`) is a
`Noop` today — attestation-gated secret release is pending. The
supervisor runs in host userspace (ADR-002 L2, "host-side proxy
socket 0700") and is single-host trusted.

**Failure mode.** W2 wires body inspection (`SecretsScanner`,
`PiiRedactor`, `SsrfGuard`) and W3 makes the supervisor the single
mint-and-revoke point for `SecretPlaceholder` substitution. A
supervisor compromise or crash now exposes every active grant and
plaintext request body on the wire. The trust footprint grows from
"audit + admission" to "audit + admission + secret substitution +
egress content".

**Mitigation owner.** W2 must add per-request audit quotas and
backpressure to the inspector chain (no quota trait exists today —
`crates/mvm-supervisor/src/audit_recorder.rs:36`). W3 must split the
grant registry from the substitution code so a single bug doesn't
cross-contaminate both — they share a process but should not share a
crash boundary. Document the trust footprint expansion in the
status-page entry for both claims so users opt in knowingly.

### R2 — Panic-output secret redaction is new infrastructure (W3)

**Current state.** No `panic::set_hook` exists anywhere in the
workspace. The `check-no-display-on-secret-types` lint
(`xtask/src/check_no_display_on_secret_types.rs`) is a name-based
compile-time check — it rejects `Debug`/`Display` derives on types
matching `*Secret*` / `*Password*` / `*Token*` / `*Key*` patterns. It
does NOT prevent panics from leaking secrets carried in generic
containers (`String`, `Vec<u8>`, `HashMap<String, String>`).

**Failure mode.** A `format!("{e:?}")` of an error type containing a
`String` field whose value happens to be a secret writes plaintext to
stderr. The ADR-048 gate "real secret values never appear in ...
panic output" then fails the moment any `unwrap()`-on-secret-bearing
result fires. Extending the existing lint cannot solve this — it's a
runtime concern, not a typing concern.

**Mitigation owner.** W3 must build a custom `panic::set_hook` in the
supervisor init path (likely `crates/mvm-supervisor/src/lib.rs`) that
runs the panic message through a redaction filter keyed on the active
grant registry. The filter sees the message after Rust formats it,
substitutes any known plaintext secret with `<redacted:grant-id>`,
and emits the redacted form. Add a hostile-guest test that triggers a
panic from a guest-controlled path (e.g. malformed request body) and
asserts the secret does not appear on the supervisor's stderr. This
is mandatory new code, not a refactor of the lint.

### R3 — Per-pull verity generation decision is unresolved (W1)

**Current state.** Claim 3 of the security model
(`CLAUDE.md` "Security model" §3) is "a tampered rootfs ext4 fails to
boot," backed by `mvm-verity-init`
(`crates/mvm-guest/src/bin/mvm-verity-init.rs`), the
`probe_verity_sidecar` plumbing
(`crates/mvm-backend/src/microvm.rs:1525-1547`), and the deterministic
`verityArtifacts` Nix derivation. The initramfs is a static binary
that's reused for every rootfs — only the sidecar + roothash are
per-image. `probe_verity_sidecar` already returns `(None, None)` when
artifacts are missing, so an "unverified" lane exists technically
even though no production code path uses it.

**Failure mode.** OCI input is arbitrary, not Nix-built. Every pull
needs either (a) a verity sidecar generated at pull time (extra
`veritysetup format` step, requires the binary on the pull path,
slows first pull by seconds-to-tens-of-seconds for typical image
sizes) or (b) a documented carve-out that pulled images run without
dm-verity. Today plan 74 W1 does not pick. Shipping W1 without
deciding leaks the decision into ad-hoc PR review and risks weakening
claim 3 silently.

**Two clean options, pick before W1 starts:**

- **Option A (strict claim 3):** Pull-time verity generation for
  every image. Adds `veritysetup` to the pull path (or to the builder
  VM that runs the pull), regenerates the sidecar whenever the rootfs
  blob changes, keeps claim 3 unchanged.
- **Option B (documented carve-out):** Pulled images live in an
  "unverified" template lane gated by a profile flag. Claim 3 becomes
  "Nix-built and prebuilt images" with an explicit exclusion for
  `image pull`-sourced templates. Audit chain (claim 8) still covers
  provenance.

**Mitigation owner.** Resolved by [ADR-050](../adrs/050-oci-image-verity-posture.md):
pull-time verity generation by default; `--no-verity` is
dev-profile-only; production-profile admission rejects pulled
templates without a verity sidecar. ADR-050 §Implementation Plan
adds the concrete task list onto W1.

### R13 — Guest agent and SDK runtime placement for pulled images (W1, W3, W4)

**Current state.** `nix/lib/mk-guest.nix` bakes
`mvm-guest-agent`, `mvm-seccomp-apply`, and `mvm-runner` into
every Nix-built image's closure. Per-language SDK runtime
libraries (ADR-049 vsock substitution hooks) are also expected to
sit inside the rootfs. An OCI-pulled rootfs (W1) is **user
content** with none of those binaries — left alone, the agent
has nowhere to live, ADR-049's hooks have nothing to bind to,
and W3 substitution silently breaks for OCI workloads.

**Failure mode.** Two bad options if left unaddressed: (a)
inject the agent + SDK runtime into the OCI rootfs at unpack
time, mutating the image and breaking digest pinning; or (b)
ship OCI ingest with no agent inside pulled images, making them
second-class citizens that can't be `mvmctl exec`'d, can't
participate in W3 secret substitution, and can't use the W4
lifecycle surface. Either way the unified-runtime promise of
ADR-048 collapses.

**Mitigation owner.** Resolved by [ADR-051](../adrs/051-mvm-runtime-overlay-disk.md):
ship a separate verity-sealed `mvm-runtime` overlay disk
attached to every microVM (Nix-built and OCI-pulled alike),
mounted read-only at `/mvm/runtime/`. The OCI rootfs stays
byte-for-byte identical to the registry content. ADR-051
§Implementation Plan folds the overlay build, `mkGuest`
refactor, and `/mvm` path-collision check into W1.3 and W1.4.

### R4 — Audit volume without backpressure (W2)

**Current state.** Today's L3 allow-list emits per-event audit (the
audit category exists at
`crates/mvm-supervisor/src/audit_recorder.rs:36` — `flow.egress.*`).
No batching, no sampling, no per-tenant quota.
`~/.mvm/audit/<tenant>.jsonl` is append-only.

**Failure mode.** W2 wires per-request audit on the L7 proxy. A
malicious or buggy workload that emits thousands of requests per
second turns the audit log into a DoS — disk fills, audit signer
falls behind, the chain-signed log loses real-time integrity.

**Mitigation owner.** W2 adds an audit-sink trait with per-tenant
rate limits and lossy-but-counted overflow (one chain entry recording
"N events dropped" so the chain stays intact). The trait also belongs
in front of every new audit kind W3/W6 introduces. Add to plan 74 W2
task list explicitly.

### R5 — Snapshot/fork interaction with placeholders (W3)

**Current state.** Snapshots are HMAC-sealed with monotonic-epoch
replay protection (`mvm-core/src/instance.rs` snapshot path). Grants
live in supervisor memory (W3 design), not in the snapshot.

**Failure mode.** A workload snapshotted with active grants gets
restored on a different host or after a long delay. The original
grant has been revoked (parent-process death, timeout); the restored
workload sees the placeholder env var but cannot complete the
substitution because the grant is gone. Worse: if grants are
inadvertently included in the snapshot, restoring on a second host
revives an already-revoked grant.

**Mitigation owner.** W3 spec must state that snapshots NEVER carry
grant state — restore re-runs admission and produces fresh grants.
Add a snapshot-restore-with-placeholder test to W3's test list.

### R6 — Cross-platform supervisor parity (W2, W3, W4)

**Current state.** ADR-031 names cross-platform strategy but the L3
allow-list today uses `nftables` on Linux; no macOS equivalent ships
in `crates/mvm-supervisor`. The supervisor process binary is built
for the host OS; libkrun runs on macOS, Firecracker on Linux.

**Failure mode.** W2 builds a kernel-netfilter-shaped policy
enforcement layer. If the implementation reaches for `nftables` /
`iptables` directly, the macOS supervisor cannot enforce. W4's
parent-process lease (`PR_SET_PDEATHSIG` on Linux, kqueue `NOTE_EXIT`
on macOS) has the same shape — both platforms must land in lock-step
or the SDK lifecycle claim is false on one of them.

**Mitigation owner.** W2 lead picks an L7 proxy implementation that's
a user-space process (not a kernel netfilter rule); the proxy is the
policy point on both platforms. W4 lead implements the macOS kqueue
path in the same PR as the Linux `prctl` path — neither lands alone.
Document the platform matrix on the status page rows for both claims.

### R7 — Cold-start measurement transparency (W5)

**Current state.** `runtime_boot_bench` (`crates/mvm/tests/`) covers
serial-and-parallel boots on Apple Container; no Firecracker
fresh-boot number is published. ADR-048 §"Non-goals" explicitly
forbids claiming `<100ms` before measured data supports it.

**Failure mode.** First measurements may show fresh Firecracker boot
in the 200-500ms range with audit append, plan signing, and verity
attach in the path. The earlier external sandbox runtime's `<100ms` claim is warm-pool
restore, not fresh boot — but their public docs do not always label
this. If we publish only a fresh-boot number, we look slower than we
are; if we publish only a warm-pool number, we overclaim. Either is a
defensible-claim failure.

**Mitigation owner.** W5 lead publishes p50/p95/p99 numbers for
*every* readiness boundary (start-return / guest-agent-ready /
snapshot-restore / warm-pool-claim / SDK-create-to-exec) in the same
table, with backend + host context on every row. The status-page row
for cold-start cites the table directly. The `check-doc-claims` lint
W0 builds will block any unqualified `<100ms` until the cold-start
row is Shipped *and* the page that quotes the number is on the
allow-list. Don't fight the lint — let it force discipline.

### R8 — mvmd cross-repo handoff discipline (all workstreams)

**Current state.** "If a primitive is missing in mvm, mvmd must not
implement a parallel runtime path" (ADR-048 §"Runtime Ownership").
The handoff contract per workstream is listed above in "Cross-repo
handoff to mvmd". No enforcement mechanism today — it's a convention.

**Failure mode.** mvmd reaches for an unstable or slow mvm primitive,
decides to fork its own path "temporarily," and the fork persists.
The plan-74 promise that mvmd consumes mvm primitives unmodified
collapses.

**Mitigation owner.** Each workstream's Shipped gate includes the
sentence "primitive is consumable by mvmd as a library with a
documented API surface." A workstream is not Shipped until the
mvmd-side issue exists referencing the mvm API by file:line. This
keeps the cross-repo contract from being implicit.

### R9 — TLS substitution mechanism is undecided (W2, W3)

**Current state.** ADR-048 §"Secret non-leakage" says "substitution
is bound to destination policy and transport identity" and plan 74
W3 says "integrate substitution with the L7 egress proxy after
destination policy passes." Neither names *how* the proxy reaches
into a TLS-encrypted body to swap a placeholder for a real value.
Three architectural shapes are compatible with the words; they have
very different attack surfaces.

**Three options:**

- **(a) Proxy-with-CA.** Install an mvm CA in the guest's trust
  store, terminate TLS at the proxy, substitute in plaintext,
  re-encrypt to upstream. We then own a CA in every guest — any
  guest TLS library bug becomes a supervisor-host compromise. Most
  invasive. Equivalent to a corporate-MITM proxy.
- **(b) Vsock side-channel.** Guest receives a
  `mvm-secret://<grant-id>` token, calls a host-side library over
  vsock at egress time to mint a per-request signed header; the
  host signs/substitutes and the guest emits the request as-is. No
  CA needed; the proxy stays SNI-only. Requires guest cooperation —
  a Python/Node SDK helper that hooks into `requests`/`fetch`.
- **(c) Host-side request reconstruction.** Guest issues plaintext
  HTTP through the proxy; proxy does TLS to upstream. Substitution
  happens in plaintext on the host. Breaks any SaaS that forbids
  unencrypted client-to-proxy.

**Failure mode.** Shipping W3 without picking turns the substitution
code into ad-hoc PR-review architecture. Worse: an (a)-style CA
installation can land "temporarily" and never get reverted, expanding
the trust footprint of every guest without an explicit decision.

**Mitigation owner.** Resolved by [ADR-049](../adrs/049-secret-substitution-mechanism.md):
default substitution is the vsock side-channel (b); (a)
proxy-with-CA lands later behind `unsafe_guest_tls_inspection`
for legacy workloads only; (c) host-side reconstruction is
rejected. ADR-049 §Implementation Plan extends W3's task list
with the vsock substitution service, per-language SDK runtime
hooks, and hostile-guest tests.

### R10 — OCI layer unpack attack surface (W1)

**Current state.** Plan 74 W1 names "whitelists, symlinks, hardlinks,
ownership, permissions" once. Industry has shipped multiple CVEs in
this space: Docker CVE-2019-14271 (path traversal via `tarSum`),
CVE-2024-21626 (runc `WORKDIR` cwd escape), and a long tail of
gzip-bomb / tar-slip variants.

**Failure mode.** Any of the following unpack bugs gives a hostile
image author host-side code execution at pull time:

- **Path traversal**: tar entries with `../../etc/passwd`.
- **Decompression bomb**: nested gzip plus a small manifest pointing
  at TB-scale layer bodies — fills disk or OOM-kills the unpacker.
- **Symlink-then-overwrite race**: layer 1 creates
  `/etc/passwd → /target`; layer 2 writes `/target` as
  attacker-controlled content.
- **Hardlink escape**: a hardlink in the OCI layer pointing at a
  host file mounted via `--add-dir`.
- **Setuid/setgid bits**: pulled rootfs may carry setuid binaries.
  Claim 2 (`setpriv --no-new-privs`) drops capabilities at service
  launch, but `find /sandbox -perm -4000` still reports them. The
  layered defense holds; the discoverable surface is wider than
  Nix-built images.
- **Registry MITM**: a non-HTTPS registry URL or a manifest without
  a content digest lets a network attacker substitute the body.

**Mitigation owner.** W1 lead enumerates each of the above as an
explicit test case in the W1 tasks list (not a generic "whitelist /
symlink coverage" bullet). Pull path enforces `https://` + digest
on every fetch. Layer unpack runs inside the builder VM, not on the
host, so a layer-unpack RCE is bounded by VM isolation rather than
hitting the host filesystem directly — this is a strong reason to
keep the unpack path inside libkrun and not "optimize" it onto the
host later.

### R11 — Non-HTTP egress posture is unspecified (W2)

**Current state.** Plan 74 W2 specs "HTTP Host and HTTPS CONNECT/SNI."
It is silent on every other egress protocol.

**Failure mode.** The supervisor-owned L7 proxy enforces policy for
exactly the protocols it parses. Without an explicit decision the
following are de facto allowed (or worse, ambiguous):

- **HTTP/2 connection reuse.** A single TCP+TLS connection carries
  multiple streams; each stream has its own `:authority`
  pseudo-header. SNI-only inspection sees the first stream's
  host; subsequent streams to other hosts bypass policy.
- **HTTP/3 / QUIC.** UDP-based, no TCP CONNECT to intercept. SNI
  is in the QUIC initial packet but the path is foreign to a
  TCP proxy.
- **WebSockets.** HTTP upgrade then bidirectional binary frames;
  per-request inspection breaks once the upgrade completes.
- **gRPC.** HTTP/2 + protobuf. Body inspection requires schema.
- **Raw TCP, SSH, mTLS APIs, DB protocols (PG/MySQL).** No Host
  header at all. The L7 proxy is irrelevant; only L3/L4
  allow-list applies.

This is also a W3 risk: secrets cannot be substituted into a
channel the proxy doesn't parse.

**Mitigation owner.** W2 spec must pick an explicit posture per
protocol class. Recommended default: **deny by default; allow
HTTP/1.1 + HTTP/2 + HTTPS CONNECT explicitly; block HTTP/3/QUIC
egress at the L4 layer until a QUIC-aware proxy ships; document
WebSockets/gRPC/raw-TCP as "destination-policy-only, no body
inspection".** W3's default flow restricts secrets to HTTP
destinations until non-HTTP substitution has a design.

### R12 — DNS bypass via DoH/DoT (W2)

**Current state.** Plan 74 W2 builds a supervisor-owned pinning
resolver. Guest libc honours `/etc/resolv.conf`, which our network
controls. But a guest can trivially bypass this by using DNS over
HTTPS (DoH, `https://1.1.1.1/dns-query`) or DNS over TLS (DoT,
TCP/853 to known providers).

**Failure mode.** Pinning is a marketing claim, not a security
boundary. A workload that bundles `cloudflare-dns` or uses Go's
`http.Transport{DialTLS}` to talk directly to a DoH endpoint
resolves arbitrary names without our pinning ever seeing the query.
The W2 audit log shows "no DNS activity" while the workload
exfiltrates via `attacker.example.com`.

**Mitigation owner.** W2 implements at least one of the following:

- **L4 blocklist of known DoH/DoT providers** (Cloudflare, Google,
  Quad9, NextDNS, Mullvad, etc.) — pragmatic, cat-and-mouse with
  new providers, easy to maintain.
- **Transparent intercept of :443 to known DoH endpoints** — bend
  the request through the L7 proxy and either rewrite or block —
  heavier, requires R9-style TLS handling.
- **Block all egress to A/AAAA/HTTPS records the pinning resolver
  did not resolve** — strongest, requires keeping a per-connection
  table of "this destination IP was resolved via the pinning path"
  and dropping anything else. This is the technically correct
  default; document it.

W2 ships option 3 as default; option 1 is the fallback for cases
where the resolver path is incomplete (e.g. statically-linked Go
binaries that ignore `/etc/resolv.conf`).

## Risks resolved since plan was written

- **Builder-VM transition (was blocking).** Plan 72 W0-W6 shipped
  2026-05-13; the libkrun builder VM is the default backend and
  `mvmctl dev up` is reliably green on contributor laptops and CI.
  In-microVM integration tests gate behind `#[ignore]` +
  `MVM_LIBKRUN_E2E=1` for local runs; CI runs them on the
  ubuntu-latest `/dev/kvm` lane. Apple Silicon CI builds and
  unit-tests but does not boot. No blocker to W1, W2, W3, or W4
  starting now.

## Definition of Done

- Every target claim has a status table entry.
- Every Shipped claim has tests and docs.
- `cargo test --workspace` passes on host where applicable.
- Linux-only/network/microVM tests are gated and run in the builder VM before merge.
- `cargo clippy --workspace --all-targets -- -D warnings` passes in the builder environment before merge.
- `specs/SPRINT.md` is updated as workstreams move from Proposed to active.
