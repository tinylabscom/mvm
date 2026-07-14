# ADR 005: Sealed, Signed Builder Image

## Status

Proposed — 2026-04-30

## Context

Sprint 42's commit `688b7de` made the dev/builder VM the *only* build
environment for everything `mvmctl build` produces. The host no longer
runs `nix` or any Linux build tooling. The commit message is explicit:
*"any code path that runs on the host is outside the sandbox, and any
'we'll just bypass the VM here' shortcut chips away at the contract one
PR at a time."*

That promotion makes the dev/builder image **load-bearing** for the
security model: if a tampered image is silently swapped or modified,
every artifact mvmctl builds — including the production-bound
rootfs/kernel images that user flakes ship via `mvm-build`, and the
pool images mvmd will rebuild via plan 23 — inherits whatever the
tampered image injects.

Sprint 42's W5.1 closed part of this gap by SHA-256-verifying downloads
against a per-arch checksum manifest (`apple_container.rs:918-1048`),
with `MVM_SKIP_HASH_VERIFY=1` as the documented escape. The W5.1 code
itself flags the remaining gap at line 952: *"who can swap the artifact
can also swap the checksum file, so the checksum manifest is TLS-only
trust today, on the checksum file itself in a future iteration."*

This ADR records the architectural decisions for that future iteration.

## Decisions

### 1. The image is a signed release artifact

The dev/builder image (`nix/images/builder/flake.nix` outputs) becomes
a **signed release artifact** alongside the `mvmctl` CLI binary.
Cosign keyless signs a per-release manifest that records SHA-256 of
each artifact, the Nix store hash, the source git SHA, and the SHA-256
of every flake lockfile. Mvmctl verifies the signature on download and
on every cache reuse.

The manifest — not the artifacts individually — is the trust anchor.
One cosign verification step covers everything inside.

### 2. Two outputs from one flake — sibling `default` and `builder`

The single `nix/images/builder/flake.nix#default` output splits into:

- **`default`** — current behavior. Dev guest agent (Exec vsock handler
  compiled in for `mvmctl exec`/`console`). Writable `/dev/vdb`
  overlay. `verifiedBoot = false`. Used by `mvmctl dev up`. **No
  behavior change.**
- **`builder`** — new sibling output. Same package list. Prod guest
  agent (no Exec handler). No writable overlay (squashfs root +
  tmpfs overlay for `/tmp`, `/var/log`, `/nix/var`). `verifiedBoot
  = true`. Used by mvmd's pool-build pipeline (mvmd plan 23).

Plumbed through `mkGuest` as a `variant ∈ {"dev", "builder"}`
parameter, visible as `passthru.variant`. Reuses the prod/dev guest
agent split from commit `4e6c5fa` and the existing sibling flake at
`nix/dev/flake.nix`.

### 3. Cosign keyless via GitHub OIDC, identity-bound to release tags

The expected signing identity is
`https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v*`.
The release pipeline is the only entity that can produce verifiable
artifacts; an unsigned-or-untagged build cannot accidentally claim
project authority.

Reuses the existing cosign keyless flow already used for the `mvmctl`
binary (Sprint 21 binary signing) and the SBOM (W5.4). One signing
infrastructure, three artifact families.

### 4. Verify on every startup, fail closed

Mvmctl runs the full verification pipeline on every `dev up`, including
cache hits (re-hash cached files against the cached manifest, no
network). Verification failure is a hard fail with no auto-retry,
pointing at the troubleshooting docs. Tampering must be loud.

`MVM_SKIP_HASH_VERIFY=1` keeps its W5.1 escape semantics — but only for
the SHA-256 check. A separate `MVM_SKIP_COSIGN_VERIFY=1` exists for
emergency cosign rotation. Both print non-suppressible warnings.

### 5. Reusable verification primitive in `mvm-security::image_verify`

The verification logic lives in `mvm-security::image_verify` as a
reusable primitive with a typed `VerifyError` enum (not `anyhow`).
mvmctl consumes it for the dev variant on `dev up`. mvmd (cross-repo,
plan 23) consumes the same functions for the builder variant on pool
rebuild and for pool images of its own. Same primitive, different
artifacts.

The typed-error contract lets mvmd's reconciliation loop pattern-match
outcomes — Revoked, Expired, DigestMismatch, etc. — and decide whether
to skip the bad image, alert, hold rollout, instead of crash-looping on
`anyhow::Error`.

### 6. Lifecycle: revocation list + manifest `not_after`

A signed image can be recalled. The release pipeline maintains a
cosign-signed `revoked-versions.json` published as the `revocations`
release tag's only asset. Mvmctl checks it at most once per 24h
(cached, fresh-window 7d). Manifests carry `not_after` (default 90d
post-release): mvmctl warns and proceeds; mvmd refuses (different risk
tolerances).

### 7. Air-gapped operators stay on the trusted path

A new `mvmctl dev import-image` (and `mvmd image import`) subcommand
runs the *same* verification logic against local files. Without this,
regulated/gov/air-gapped operators are pushed onto
`MVM_SKIP_HASH_VERIFY=1` — the unsafe escape becomes their default,
which is exactly the failure mode this ADR exists to prevent.

## Alternatives considered

- **Single image used for both mvmctl `dev up` and mvmd pool builds.**
  Reject: the dev variant bundles the dev guest agent's vsock Exec
  handler (RCE-by-design — that's how `mvmctl exec` and `console`
  work). Acceptable in mvmctl's local sandbox, unacceptable inside
  an mvmd coordinator's production builder VM. Two outputs from one
  flake gives single source of truth without shipping the Exec
  handler to production.
- **Distinct flakes for dev and builder.** Reject: lets the build
  sandbox tooling drift silently between dev and production —
  the "works on my machine" trap. One flake, two outputs.
- **Sign artifacts individually instead of a per-release manifest.**
  Reject: requires N verification steps per boot; no place to record
  cross-artifact metadata (Nix store hash, lockfile hashes, advisory
  list); manifest schema versioning is harder.
- **Project-internal Ed25519 signing root instead of cosign keyless.**
  Reject: requires key management + rotation infrastructure the
  project doesn't otherwise need. Cosign keyless reuses Sigstore's
  transparency log + GitHub OIDC, which the project is already
  publishing under for the CLI binary.
- **TLS-only trust on the checksum file (status quo post-W5).**
  Reject: the W5.1 code itself flags this as the gap to close. An
  attacker who can swap the artifact can swap the checksum.
- **Seal the dev image (current `default` output) instead of adding a
  builder sibling.** Reject: would break `mvmctl dev` for everyone.
  Users running `nix build` inside the dev VM expect outputs to
  persist in `/nix/store` across the session. The split preserves
  ergonomics for dev users while enabling production sealing.
- **Sign the user's microVM image (what `mvmctl build --flake ./myapp`
  produces).** Out of scope. Users have their own release identities
  and may not want their builds attached to mvm's. The signed builder
  produces *their* artifacts; what they do with them is theirs.

## Consequences

**Positive:**
- Trust chain bottoms out at a cryptographic identity bound to the
  source tree, not at "GitHub's TLS cert + release infrastructure."
- Production builders (mvmd plan 23) never carry the dev RCE primitive.
- One verification primitive serves both mvmctl users and mvmd's
  fleet pipeline. Single audit surface.
- Air-gapped operators have a sanctioned trusted path. The unsafe
  escape (`MVM_SKIP_HASH_VERIFY=1`) is no longer the *only* offline
  option.
- Builder image inherits sprint 42's W3 dm-verity protection. Tampering
  the on-disk rootfs panics the kernel before userspace.
- Verifiable answer to "which dev/builder image built this artifact?"
  via manifest digest recording (mvmd plan 23 records this in pool
  manifests).

**Negative:**
- mvmd takes a hard dependency on `mvm-security::image_verify` (git-dep
  until crates.io publish). Cross-repo coordination required.
- Hotfixes require cutting new tags. No re-signing existing tags in
  place. Same constraint that already applies to mvmctl binaries.
- `sigstore` Rust crate is heavy (TUF + transparency log + x509).
  Binary size impact may force a default-on Cargo feature gate.
- Reversal cost is medium: once a tag ships with the cosign-signed
  manifest, downgrading would require either impossible post-hoc
  re-signing or a period of unverified downloads.

**Neutral:**
- Manifest schema versioning needed from day one so older mvmctl/mvmd
  binaries fail closed on unknown versions.
- The dev variant continues to be verity-exempt per ADR-002 §W3.4.
  Only the builder variant gets verity protection.

## References

- Sprint 42 commit `688b7de` — "make dev VM the only build environment;
  delete HostBuildEnv"
- `specs/adrs/002-microvm-security-posture.md` — the seven-claim
  threat model that drove sprint 42
- `specs/plans/29-w5-supply-chain.md` — W5.1 SHA-256 verification this
  plan extends
- `specs/plans/36-sealed-signed-builder-image.md` — implementation plan
  derived from this ADR
- mvmd plan 23 + mvmd ADR 0001 (cross-repo) — rolling microVM rebuild
  pipeline that consumes the verification primitive


## Consolidated from ADR-013 — Pivot to libkrun + libkrun + microvm.nix; drop Lima

## Status

Proposed. Implementation tracked in `specs/plans/60-mvm-libkrun-migration.md`. Phase 0 + Phase 1 deliver the build/exec pivot; subsequent phases compose on top.

## Invariant — host does not need Nix

**`mvmctl` runs on a stock host. Nix is not a prerequisite.** On first
build, mvm bootstraps a small Linux builder microVM (libkrun-backed,
OCI image as the acceptable shape for the *builder* trust zone), runs
`nix build` inside it, and extracts the resulting rootfs back to the
host. The runtime path stays Nix-free; the builder path keeps Nix
inside the sandbox where it belongs.

Host-side Nix remains an **opt-in power-user path**:
- contributors hacking on mvm itself who want a shared `/nix/store`,
- users with `nix-darwin`'s `linux-builder` already configured (mvm
  detects and uses it),
- users with a remote `nix-daemon` URL.

The full design is in §"Linux builder via libkrun (no Lima)" below.
The user-facing docs (install/*, getting-started/*, guides/*) reflect
this invariant — host Nix is documented as optional, not required.

> **Status (2026-05-08):** the bootstrap is in flight on `feat/micro`
> as part of W6.x. Until it lands, contributors building rootfs images
> still need host-side Nix (or `nix-darwin`'s `linux-builder` on macOS).
> Docs describe the target user-facing shape; the contributor guide
> notes the current gap.

## Context

The previous iteration of `mvm` (at `../mvm`) used Lima as the macOS dev-VM hop and Firecracker as the production hypervisor on Linux. Two pain points motivated the pivot:

1. **macOS dev experience was indirect**: every guest action traversed `host → Lima Ubuntu → Firecracker microVM`. Boot times were dominated by Lima warm-up; first-launch UX was brittle.
2. **Build pipeline lacked portability**: Nix builds ran inside ephemeral Firecracker builder VMs, gated by KVM availability. macOS and Windows hosts had no clean path.

The new direction:

- **libkrun** (Apache-2.0, libkrun-backed) becomes the **builder** and the macOS/Windows execution path. libkrun gives us native Hypervisor.framework on macOS and KVM on Linux without a wrapping Lima VM.
- **Firecracker** stays as the preferred Linux production execution path because of its smaller attack surface, faster cold boot, and existing security work (jailer, dm-verity, seccomp tier).
- **microvm.nix** (MIT) becomes the Nix-flake foundation for microVM image generation. It abstracts Firecracker / Cloud Hypervisor / QEMU / crosvm / kvmtool / stratovirt as a NixOS module — adding a new backend later is a config change, not a kernel rewrite. **Fallback path**: if the per-bump audit (`xtask audit-flake`) of microvm.nix surfaces a security regression we can't accept, we fall back to the previous iteration's hand-rolled NixOS modules in `../mvm/nix/`. The fallback is a **named, ready-to-execute escape hatch**, not just an ADR sentence.
- **Lima is dropped entirely.** The macOS path is libkrun-direct; no intermediate Linux VM.

## Decision

1. **Builder**: libkrun-backed Nix builds (`mvm-build/src/pipeline/libkrun.rs`); persistent warm-pool per tenant (ADR-015).
2. **Execution backend selection** at runtime:
   - Linux + `/dev/kvm` available → Firecracker
   - macOS / Windows / Linux without KVM → libkrun (libkrun)
3. **Image generation**: extend microvm.nix's NixOS module with our security overlay (W2.1 per-service uids, W2.4 seccomp tiers, W3 dm-verity, W2.2 read-only `/etc`).
4. **Drop Lima** from the codebase; no fallback path.

## Consequences

**Positive**:
- Single fewer hop on macOS (host → libkrun → guest) — faster boot, cleaner UX.
- microvm.nix gives multi-hypervisor portability for free.
- Builder pipeline runs on every host class.
- Reduced surface: no more Lima-specific code paths.

**Negative**:
- Adds a third-party dep (microvm.nix) to the build trust boundary — pinned by hash and CI-audited (`xtask audit-flake`).
- Some Linux-specific guarantees (dm-verity at boot, seccomp tier "strict") only hold on the Firecracker path. The libkrun path uses image-hash-on-load + HMAC chain instead. Documented in the per-backend tier matrix in ADR-002.
- Loss of the Lima dev-VM means macOS users without libkrun installed get a clearer error instead of a working but slow path.

**Neutral**:
- mvmd's facade contract (`mvmctl::core`, `mvmctl::runtime::shell`, etc.) is unaffected — this is a backend swap, not a contract change.

## Boot-time budget — busybox-as-PID-1, NOT NixOS+systemd

The project's value prop includes "as fast as possible" boot — concretely **sub-200ms to userspace on Firecracker / libkrun**, sub-1s on Apple Virtualization framework. Neither NixOS+systemd nor Alpine+OpenRC reaches that:

| init system | Firecracker p50 | Why |
|---|---|---|
| NixOS + systemd | 1–3 s | systemd unit graph, generators, dbus, locale-loader |
| Alpine + OpenRC | 300–500 ms | OpenRC runlevel + service supervision |
| **busybox-as-PID-1** (custom init) | **~50–150 ms** | One static binary, one script, exec the entrypoint |

microvm.nix's NixOS module is a convenient way to *describe* a microVM, but it produces a NixOS-systemd rootfs that's structurally too heavy for our boot budget. We therefore:

1. **Use microvm.nix only for the hypervisor abstractions** it exposes (runner-script generation, hypervisor-specific config knobs). Pinning microvm.nix as a flake input is still an ADR-013 commitment.
2. **Build the rootfs ourselves** as busybox-as-PID-1, the way the previous iteration did. The mkGuest implementation (`nix/lib/mk-guest.nix`) emits an ext4 image whose `/init` is a tiny script that mounts `/proc`, `/sys`, `/dev`, sets up vsock, and execs the user's entrypoint.
3. **No initrd in the default path** — kernel modules required at root mount (virtio-blk, virtio-vsock, ext4) are built into the kernel image, so `init=/init` runs without a stage-1 initramfs detour. Saves ~30-50ms vs the microvm.nix initramfs path.
4. **NixOS+systemd remains available as an opt-in** for users who explicitly want it (`init = "nixos"` parameter on mkGuest). Boot will be ~1-3s; we surface that warning in mkGuest's module docs.

The previous iteration shipped this exact strategy and was approaching the upstream Firecracker reference (~125ms). We replicate that, then tighten further per Phase 9's perf gate (`tests/perf.rs::cold_boot_p50_within_budget`).

### Per-backend boot budgets (CI gate, Phase 9)

**Floor: every backend must boot in ≤ 300 ms cold p50.** The number is intentionally aggressive — busybox-as-PID-1 + a trimmed kernel + direct-`vmlinux` boot all exist precisely so we can hit it. A backend that can't reach the floor is a backend we don't ship.

| Backend | Cold p50 | Snapshot-cloned p50 | Notes |
|---|---|---|---|
| Firecracker (Linux/KVM) | ≤ 300 ms | ≤ 30 ms | Default for typical mvm workloads. Smallest attack surface; the security work (jailer, dm-verity, seccomp tier) targets it. |
| **Cloud Hypervisor (Linux/KVM)** | ≤ 300 ms | ≤ 50 ms | Tier-1 peer of Firecracker; rust-vmm-based; passes the §"fork test." Picks up where FC stops: VFIO passthrough, virtio-gpu, virtio-fs, larger guests. Opt-in via `--hypervisor cloud-hypervisor`. |
| libkrun / libkrun (Linux/KVM) | ≤ 300 ms | ≤ 30 ms | libkrunfw bundles kernel; matches Firecracker on Linux. |
| libkrun / libkrun (macOS HVF) | ≤ 300 ms | ≤ 60 ms | HVF init overhead is real; reaching the floor needs the kernel + initramfs trim from §"Boot-time budget" to be tight. |
| Apple Virtualization framework | ≤ 300 ms | ≤ 200 ms | Apple's hypervisor overhead. If we can't hit 300 ms here we drop the backend (see ADR-031 — macOS path is libkrun-direct anyway). |

CI perf gate: `xtask perf --backend <name> --p50-ms 300 --runs 100` (Phase 9). The smoke at `tests/smoke_e2e_boot.rs` (Phase 1 W6) runs a single boot and asserts the floor on every PR that touches the boot path.

## Guest agent supervision

`/init` (PID 1) forks **two** processes after staging the filesystem:

1. The **guest agent** in the background, under `setpriv` to uid 990. The agent listens on vsock for host-mediated tool RPCs (web_search, code_eval, file transfer, etc.), reports system metrics, and handles lifecycle events (sleep/wake, stop). Without it the host can boot the VM but can't talk to it for anything beyond hypervisor-level control.

2. The **entrypoint** in the foreground, under `setpriv` to the resolved entrypoint uid (root in dev, 1000 in prod by default).

PID 1 stays uid 0 (kernel mandate) but exec's nothing as root after the supervision fork.

**Implementation status (Phase 1 W6.1.1 — partial):**
- The supervision pattern is in place: `/init` forks the agent in the background under uid 990 before setpriv-exec'ing the entrypoint.
- The agent **binary** at `/usr/local/bin/mvm-guest-agent` is currently a **placeholder stub** — a sh script that logs its startup uid to `/dev/console` and sleeps in a loop. It demonstrates the supervision shape but doesn't implement the vsock RPC surface.
- Every `mkGuest`-built derivation surfaces `passthru.mvm.agentBinary = "stub"` so consumers can detect this. Production deployments will refuse to boot a `"stub"` image once the policy lint lands.
- W6.1.2 swaps in the real Rust binary (`crates/mvm-guest/src/bin/mvm-guest-agent.rs` — ~2400 LOC of vsock RPC). That swap needs cross-compile infrastructure (a Linux builder) and is its own focused wave.

The supervision wiring matters even with the stub because: (a) the dev/prod uid split is real today, (b) `/etc/passwd` + `/etc/group` are baked correctly today, (c) the host-side `mvmctl status` cross-check against `/proc/<pid>/status` works today, and (d) swapping the binary path in the rootfs population step is a one-line change.

## Cloud Hypervisor as a Tier 1 peer of Firecracker

Firecracker is the default for typical mvm workloads — smallest attack surface, fastest boot, and the existing security overlay (jailer, dm-verity, seccomp tier) targets it. But Firecracker is intentionally minimal: it deliberately excludes VFIO passthrough, virtio-gpu, virtio-fs (in any rich form), and tops out at modest guest sizes. **Cloud Hypervisor (CH)** picks up where Firecracker stops:

- **VFIO passthrough** — pass a PCI device (NVIDIA GPU, NIC, custom accelerator) directly into the guest. Required for compute-GPU workloads (CUDA, ROCm). FC will not implement this; CH does today.
- **virtio-gpu** — accelerated graphics for in-VM rendering. Required for `computer-use`-style templates that need a real display.
- **virtio-fs** — high-throughput shared filesystem between host and guest. FC supports a more limited path; CH's is closer to native.
- **Larger guests** — CH's device model handles more vCPUs and devices than FC's deliberately minimal one.

**Tier classification:** CH is rust-vmm-based and passes the plan-53 §"fork test" (rust-vmm origin, ~80K LOC core, no Firecracker-excluded features in the boot path; the richer device set is opt-in per VM, not always-on). Same Tier 1 posture as Firecracker; the choice between them is workload-shape, not security-shape.

**Selection model:**
- `auto_select()` keeps Firecracker as the KVM default (no behavioral change for typical workloads).
- CH is opt-in via `mvmctl run --hypervisor cloud-hypervisor` or the `mkGuest { hypervisor = "cloud-hypervisor"; }` argument.
- Aliases: `cloud-hypervisor`, `cloud_hypervisor`, `ch`, `clh` (matching upstream's own docs).

**Status:** Phase 1 ships the stub backend (final `VmBackend` shape; lifecycle returns "not yet wired"). Same shape as the `LibkrunBackend` stub before plan-57's libkrun spike landed real lifecycle. CH bring-up is a focused near-term wave (no longer post-Phase-10 — moved up because users want backend flexibility for GPU + larger-guest workloads). The lifecycle implementation needs:

- `cloud-hypervisor` binary detected on PATH (`Platform::has_cloud_hypervisor()` already shipped)
- A small JSON-API client (CH exposes a REST API on a Unix socket)
- Drives, vsock, network device assembly per `VmStartConfig`
- Process supervision (PID file in `~/.mvm/vms/<name>/ch.pid`)

Once shipped, the per-backend boot budget table holds for CH the same way it does for FC; the smoke + perf gates apply uniformly.

**Why move CH up the schedule:** the user explicitly asked for backend flexibility — the same flake should be runnable across FC, CH, libkrun depending on what the workload needs. CH was scheduled post-Phase-10 because the original justification was GPU passthrough; the broader argument ("flexibility on what runs and where") makes it a near-term concern.

## Linux builder via libkrun (no Lima)

macOS hosts can't `nix build` Linux derivations natively — `nix build` emits a "no Linux builder available" error and stops. The previous iteration solved this by running a Lima VM as a Linux builder; this iteration drops Lima entirely (per the body of this ADR), so the question becomes: how does a macOS user `mvmctl build .` without configuring host-side Nix infrastructure?

**Design: bootstrap a Linux builder inside libkrun itself.**

Libkrun supports OCI images, and Nix-bearing OCI images are widely available (`nixos/nix`, `nixpkgs/nix-flakes`, our own pinned image). On a macOS host without a Linux builder configured, `mvmctl build` can:

1. Detect the gap — `Platform::has_host_nix()` returns true but the Nix instance can't build Linux derivations (`nix-store --eval` against a Linux derivation fails, or `nix.conf` lacks a configured builder).
2. Pull a small, pinned Nix-bearing OCI image — once, cached in `~/.cache/mvm/builder-image/`.
3. Spawn a libkrun sandbox from that image with the user's flake source bind-mounted as `/work`, the host's Nix store mount-shared as `/nix`, and a sane PATH.
4. Run `nix build .#default` inside the sandbox.
5. Extract the resulting rootfs (the runtime artifact) back to the host.
6. Hand the rootfs off to the runtime path (which uses libkrun + `RootfsSource::DiskImage` per the OCI non-goal — the runtime never pulls OCI).

**Why this is consistent with the OCI non-goal.** The non-goal banned OCI from the **runtime/boot path** — the place where user workloads run, where reproducibility + offline-by-default + no-registry-trust matter. The **builder** lives in a different trust zone: it has to fetch from caches, talk to the network, run arbitrary `nix build` derivations. Builder VMs and runtime VMs are governed by different policies; using OCI for the builder doesn't compromise the runtime's invariants.

**Cache reuse.** The Nix store on the macOS host is bind-mounted into the builder sandbox as `/nix`. Builds populate the host store; subsequent builds (Linux or otherwise) reuse the same cached derivations. This is the same trick `nix-darwin`'s `linux-builder` uses — the difference is mvm doesn't require the user to have configured `nix-darwin`.

**Fallbacks.** If the user has already configured a host-side Linux builder (`nix-darwin`'s `linux-builder`, or a remote `nix-daemon` URL), mvm uses that — the libkrun-builder path is the *zero-config* default, not a forced override. Detection: probe `nix-store --add-fixed sha256 /dev/null --realize` against a Linux derivation; success → the host can build; failure → fall through to the libkrun builder.

**Implementation status.** Phase 1 W6.x ships the design as documented; the actual builder bootstrap is its own focused wave (needs the OCI image pinned + cached, the bind-mount semantics worked through, the artifact extraction path written). Tracked in Sprint 50 as a follow-up.

**This replaces every previous reference to "configure `nix-darwin`'s `linux-builder`" in the docs.** Users with an existing builder keep using it; everyone else gets the libkrun-bootstrapped path with no host-side configuration.

## Privilege model — rootless workloads on busybox PID 1

PID 1 must be uid 0 (Linux kernel requirement; user-namespace tricks bring their own risk surface and are out of scope). `setpriv` drops privileges before exec'ing the workload, so the user-visible process tree is non-root by default in production.

| Process | Uid | Why |
|---|---|---|
| `/init` (PID 1) | 0 | Kernel mandates. Mounts `/proc`/`/sys`/`/dev`, sets up the world, then exec's the entrypoint via `setpriv`. |
| `mvm-guest-agent` | 990 | Vsock RPC handler. Never needs root. Always non-root regardless of mode. |
| Entrypoint (workload) | 0 (dev) / 1000 (prod) | Root by default in dev for debug ergonomics (`apt`, `mount`, etc.); non-root by default in prod for defense in depth. Override via `uids = { entrypoint = … }`. |

`setpriv` invocation uses `--reuid + --regid + --clear-groups + --no-new-privs` (matches ADR-002 W2.3). `--no-new-privs` blocks `setuid` re-elevation in the workload — a compromise of the entrypoint can't reach uid 0 even if it finds a SUID binary.

**Why dev defaults to root:** dev shells are interactive debug surfaces. `apt install`, `mount /dev/sdX`, `tcpdump -i any` — all expect root. Defaulting dev to non-root would break those flows on first try and push users to flip the override, which is friction without payoff. Dev is *already* a less-secure mode (the `accessible` distinction in ADR-013 §"Sealed vs accessible"); rootful entrypoint is consistent with that posture.

**Why prod defaults to non-root:** the ADR-002 W2.1 commitment — "no guest binary can elevate to uid 0." Defending against this requires the workload not *being* uid 0 to begin with. The rootless default lands a meaningful slice of W2.1 ahead of Phase 6's full security overlay; the rest of W2 (per-service uids, read-only `/etc`, dm-verity) layers on top without breaking the surface.

**Override knob:** `uids = { agent = N; entrypoint = M; }` on the `mkGuest` call. Valid permutations:
- `{ entrypoint = 1000 }` — rootless dev shell (forces non-root in dev mode)
- `{ entrypoint = 0 }` — rootful prod workload (rare; usually a misconfiguration; blocked at policy level once the lint lands)
- `{ agent = 5000 }` — non-default agent uid (e.g. to avoid collisions with a host-side range)

Values surface on the resulting derivation as `passthru.mvm.uids = { agent; entrypoint; }` and `passthru.mvm.rootlessEntrypoint :: bool`. `mvmctl status` reads them and cross-checks against `/proc/<pid>/status` in the guest at runtime.

## Non-goal: OCI / container images

**mvm is microVMs, not containers.** Even though libkrun's API
exposes both — `RootfsSource::Oci(reference)` for OCI image pulls and
`RootfsSource::DiskImage { path, format, fstype }` for raw disk
images — we deliberately use **only the `DiskImage` path**.

Why this is a stated invariant, not a default:

1. **Architectural commitment.** The project's value prop is microVM
   isolation backed by Nix-built rootfs images. OCI brings registry
   pulls, layered images, image index resolution, and a different
   trust model — none of which we want in the trust boundary.
2. **Reproducibility.** Nix-built rootfs images are byte-reproducible
   given the same flake inputs (we gate this in CI). OCI images
   resolve through a registry, can be re-tagged, and don't carry the
   same guarantees by construction.
3. **Trust boundary minimalism.** Pulling from an OCI registry adds
   an external network dependency to the boot path. The microVM
   path is offline-by-default once the rootfs is built.
4. **Runtime path consistency.** The bridge between our `.ext4`
   rootfs files and libkrun's `.disk()` builder (a sibling
   `.raw` hard-link with explicit `fstype("ext4")`) keeps the disk
   path entirely host-local. No registry, no auth, no pull cache.

**What this means for code review:** any PR that introduces
`RootfsSource::Oci`, `libkrun::RegistryAuth`, OCI image
references, or related types is reviewed against this invariant.
The exception is the future `mvm-cve` crate (plan 60 §"Roadmap
support") which may parse OCI artifact metadata as input to the
CVE roller — that's a metadata path, not a runtime path.

## Alternatives considered

- **Keep Lima as a fallback**: rejected. Maintains a code path that doesn't get exercised in the pivot's primary use case. Either Lima is good enough to be the macOS path (it isn't, per UX measurements) or it's dead code.
- **Cloud Hypervisor as primary**: rejected for now. CH is heavier than Firecracker and lacks the existing security work; revisit when GPU passthrough (VFIO) is needed (ADR-030).
- **Hand-rolled Nix flake (no microvm.nix)**: rejected. The previous iteration's hand-rolled flake was ~5000 LOC of NixOS module work; microvm.nix replaces most of that and is actively maintained.

## Threat model impact

- **microvm.nix** as a third-party dep widens the supply-chain surface. Mitigated by hash-pinning in `flake.lock`, CI re-audit on every bump, and reproducibility double-build.
- **libkrun 0.4.5** is itself a third-party dep. Same mitigation.
- The per-backend tier matrix from ADR-002 is updated: Firecracker tier remains "strict"; libkrun tier is "standard" until parity work lands (post-Phase 6).

## Compliance impact

- SOC 2: positive — narrower scope (one fewer trust boundary on macOS).
- PCI: neutral — neither backend is PCI-certified out of the box.
- HIPAA: neutral.
- FedRAMP/FIPS: future — neither backend ships FIPS 140-3 crypto today.


## Consolidated from ADR-054 — Ur-seed Stage –1 bootstrap layer

**Status:** accepted 2026-05-18, implements Plan 86.

## Context

Plan 77 W5 added a hard seed contract to Stage 0
(`bootstrap_builder_vm_image_via_dev_image_stage0`): the dev image
serving as the Stage 0 seed must contain `/sbin/mvm-builder-init` and
declare it in its `manifest.json`. The contract closes a real
kernel-panic class (Plan 77 §"Why W5 + W6 were added") but creates a
catch-22 for contributor hosts:

- The dev image is built **by** Stage 0 (`mvmctl dev up` → Plan 77 W1
  via the dev-image-as-seed path).
- The dev image needs `/sbin/mvm-builder-init` to satisfy the W5
  contract for **future** Stage 0 runs.
- Contributors who upgraded `mvmctl` after the W5 commit landed have
  a pre-W5 dev image in their cache. That image lacks
  `/sbin/mvm-builder-init`, so the W5 check rejects it. Building a
  W5-compliant image requires Stage 0, which requires a W5-compliant
  seed image. No path forward.

Plan 77 W4 correctly gates the `download_builder_vm_image` fallback
behind an off-by-default feature so contributor builds can't pull a
prebuilt — this matches the
`feedback_no_prebuilt_builder_vm_artifact.md` invariant. The result is
that on a contributor host with only a pre-W5 dev image,
`mvmctl dev up` is permanently dead-ended.

ADR-046 §"Two artifact layers, two acquisition paths" explicitly
authorises this stance: the contributor path must not depend on
mvm-published artifacts, and a contributor edit to
`nix/images/builder-vm/flake.nix` must reflect in the next `dev up`.
The W5 catch-22 violates that invariant in practice — there is no
"next `dev up`" possible from the stuck state.

## Decision

Introduce a **Stage –1** bootstrap rootfs, the **ur-seed**, that sits
upstream of the builder VM and is independent of every other flake in
the repo. The chain becomes:

```
ur-seed (built once, installed explicitly)
    ↓
builder VM (built locally from nix/images/builder-vm/flake.nix)
    ↓
dev image (built locally from nix/images/builder/flake.nix)
```

### Ur-seed shape

`nix/ur-seed/flake.nix` produces a single tarball per arch
(`ur-seed-<arch>-linux.tar.gz`) containing:

| Artifact         | Source                                                        |
| ---------------- | ------------------------------------------------------------- |
| `rootfs.ext4`    | mkfs.ext4-formatted image built in the flake                  |
| `vmlinux`        | TSI-patched kernel from `nix/images/builder-vm/kernel/`       |
| `manifest.json`  | Stage 0 seed contract metadata (`image_kind=ur-seed`)         |
| `cmdline.txt`    | Kernel cmdline (informational; Stage 0 uses its own)          |

The rootfs ships:
- `busybox-static` (POSIX shell + utilities).
- `mvm-builder-init` cross-compiled to `aarch64-unknown-linux-musl`
  at `/sbin/mvm-builder-init` (the W5 contract path).
- The same runtime package closure the steady-state builder VM uses
  (`bash`, `coreutils`, `nix`, `e2fsprogs`, `iptables`, `util-linux`,
  …) staged under `/nix/store` and symlinked into `/usr/local/bin`
  + `/sbin`.
- The kernel module tree at `/lib/modules/<kver>/` (virtio-fs, fuse).

The rootfs and kernel are bundled into the tarball alongside the
manifest + cmdline; the host extracts them atomically to
`~/.cache/mvm/ur-seed/<arch>/`.

### Acquisition policy (Shape C — explicit only)

Per `feedback_no_prebuilt_builder_vm_artifact.md`, **`mvmctl dev up`
NEVER fetches the ur-seed automatically**. Two explicit paths:

1. **`mvmctl dev fetch-ur-seed [--arch …] [--mirror …]`** —
   download from the documented release mirror (GitHub release for
   the running `mvmctl` version by default). SHA-256 verified before
   atomic-install.
2. **`mvmctl dev import-ur-seed --from <tarball> [--sha256 <path>]`** —
   air-gapped install from a local file (release CI output, a
   sibling machine, or a manually-built tarball).

The release mirror is populated only when a release is explicitly
cut. Until then, contributors with no prior mvm state use
`import-ur-seed` against a manually-built tarball.

**Corollary — no in-development republish.** A bug fix that lands
in any binary baked into the ur-seed (`mvm-builder-init`, ur-seed
init scripts, etc.) does NOT trigger an ur-seed release republish.
Contributors who want the fix on their own host rebuild the ur-seed
locally and `mvmctl dev import-ur-seed --from <tarball>` it; the
release mirror moves on its own cadence, tied to a prod release
cut. Same hermetic-build principle as ADR-046's contributor path:
the published artifact has a trust/signature lifecycle that should
not be churned by routine bug fixes, and the "is this artifact
prod-blessed or dev-WIP?" line stays clean. PR descriptions and
follow-up checklists for ur-seed-baked-binary fixes should reflect
the local-rebuild path, not a release republish.

### Stage 0 fallback order

`bootstrap_builder_vm_image_via_*_stage0` selection:

1. Builder-VM cache hit → no Stage 0 needed.
2. Contract-compliant dev image at `~/.mvm/dev/{current,prebuilt/v*,builds/*}/`
   → dev-image Stage 0 (existing Plan 77 W1 path).
3. **NEW:** ur-seed at `~/.cache/mvm/ur-seed/<arch>/` → ur-seed Stage 0.
4. Hard fail with actionable `fetch-ur-seed`/`import-ur-seed` hint.

The ur-seed kernel is preferred over any other local kernel because
it is guaranteed TSI-patched (libkrun's AF_INET sockets require it —
Plan 72 W5.D bullet 10) and version-matched to the rootfs's module
tree.

### Trade-offs

- **The ur-seed's `mvm-builder-init` is release-frozen.** Contributor
  edits to `crates/mvm-builder-init/` reflect in the steady-state
  builder VM (rebuilt every `dev up`) but **not** in the ur-seed.
  This is a small ergonomic cost; in exchange the bootstrap path is
  trivially reproducible from a fixed artifact set.
- **The ur-seed's kernel is shared with the builder VM's TSI kernel
  package** (`nix/images/builder-vm/kernel/default.nix`). Contributor
  edits to the kernel package invalidate the ur-seed too — same
  rebuild lever as the builder VM cache. That alignment is desirable;
  the kernel is the load-bearing piece for libkrun network parity.
- **Tarball size ~190 MiB per arch (compressed).** Kernel modules
  dominate. Acceptable for an explicit-fetch artifact; not acceptable
  for a vendored-in-repo blob (Shape B in the Plan 86 discussion was
  rejected on this basis).
- **Adds `nix-portable` and `proot` as transitive concepts.** Plan 86's
  v1 used nix-portable; v2 dropped it in favour of the full runtime
  package closure for simplicity. The bounded-bridge memory note still
  applies — if we ever decide to ship a slimmer ur-seed, nix-portable
  is the natural pivot.

## Alternatives considered

- **Shape A: vendor the ur-seed via git-lfs.** Rejected: 85+ MiB per
  arch in repo history is a permanent tax. Contributors without
  git-lfs hit a partial-fetch failure mode that's hard to diagnose.
- **Shape B: vendor the ur-seed as raw bytes in-tree.** Rejected for
  the same reason as A, minus the git-lfs dep. Repo bloat is
  permanent.
- **Modify the W5 contract check to accept pre-W5 dev images.**
  Rejected: re-opens the kernel-panic class Plan 77 W5 closed
  (a contract-stale seed silently violates the boot contract). The
  ur-seed satisfies the W5 contract by carrying
  `/sbin/mvm-builder-init` directly.
- **Implement `extract_bundled_kernel()` to pull a TSI kernel from
  `libkrunfw.dylib`'s `.rodata`** (referenced in the
  `reference_libkrun_gotchas.md` memory). Tabled until the kernel
  patches in `nix/images/builder-vm/kernel/patches/` need to drift
  meaningfully from libkrunfw upstream; for now sharing the in-repo
  TSI package is simpler and version-coherent with the builder VM
  output.

## Consequences

- **Closes the Plan 77 W5 catch-22.** New contributors install the
  ur-seed once (`mvmctl dev fetch-ur-seed` or `mvmctl dev import-ur-seed`),
  then `mvmctl dev up` works end-to-end.
- **Adds a release-artifact obligation.** Each cut release must
  publish `ur-seed-<arch>-linux.tar.gz` + `.sha256` alongside the
  existing dev-image artifacts. Until that pipeline lands, the
  `--from <tarball>` path is the only acquisition route.
- **No change to the `mvmctl dev up` happy path** once the
  builder-VM cache is populated. The ur-seed is a one-shot bootstrap
  asset; it's not consulted on subsequent runs.

## Security model addendum

Security claim 6 (CLAUDE.md §"Security model" — "Pre-built dev image
is hash-verified") is extended to cover ur-seed acquisition:
`fetch-ur-seed` and `import-ur-seed` both verify a SHA-256 sidecar
before atomic-install. The mirror URL is the same GitHub releases
trust root as the dev image. The release CI must produce the
`ur-seed-*.tar.gz.sha256` sidecar alongside the tarball.

## References

- Plan 86 — `specs/plans/86-ur-seed-stage0-bootstrap.md`
- Plan 77 — `specs/plans/77-stage0-bootstrap-via-dev-image.md` (the
  W5 contract this addresses)
- Plan 72 — `specs/plans/72-builder-vm-via-libkrun.md` (libkrun
  builder VM, W5.D fix list — the catalog of "what breaks at each
  layer" that informed the ur-seed contents)
- ADR-046 — `specs/adrs/046-builder-vm-via-libkrun.md` (the
  two-artifact-layers invariant)
- ADR-002 — `specs/adrs/002-microvm-security-posture.md` (Claim 6)
- Memory `feedback_no_prebuilt_builder_vm_artifact.md` — the
  contributor-host policy this ADR honours.


## Consolidated from ADR-057 — Symmetric builder VM across hosts

**Status:** Proposed
**Sprint:** 56 (W1)
**Plan:** [Plan 100](../plans/100-symmetric-builder-vm-rollout.md)

## Context

Today's execution paths are asymmetric across host operating systems:

- macOS: `Host → libkrun Linux VM (builder/runner) → Firecracker microVM`
- Linux: `Host → Firecracker microVM (direct on host KVM)`

Builder-backend dispatch lives at `crates/mvm-build/src/builder_backend_select.rs:86-91` (`resolve_builder_backend()`). On Linux, the host's userland sits in the TCB for every workload because workload microVMs share Linux's host kernel and a host process can `ptrace` Firecracker or read its `/proc/<pid>/mem` without ever crossing a hypervisor boundary. On macOS the same operations would first require breaching the libkrun Linux VM that sits between mvmctl and the workload — a different threat tier.

This asymmetry undermines the security claims listed in ADR-002. Claim 1 ("no host-fs access from a guest beyond explicit shares") is meaningful only relative to the host being trusted not to peek. ADR-002 explicitly carves out "a malicious host" as out-of-scope, granting the host the hypervisor and the private build keys — but no more. On Linux today the host has more capability than the carve-out grants it, by virtue of running the workload directly. On macOS, it doesn't. The claim should hold uniformly.

## Decision

Workload microVMs always run inside a builder VM, regardless of host OS:

- macOS keeps the libkrun-based builder VM it already has.
- Linux gains a libkrun-based builder VM with nested KVM. Execution becomes: `Host KVM → libkrun Linux builder VM (nested KVM) → Firecracker workload microVM`.

The signing identity is established inside the builder VM on both hosts. The host userland is no longer in the TCB on either; the host's role narrows to "owns the hypervisor process and the private build-key escrow, nothing else."

## Consequences

- **Boot-time cost.** A small Linux builder VM cold-starts on `mvmctl up` / first `mvmctl run` on Linux contributors. Reused across workloads in a single `mvmctl dev` session; the marginal cost across N workloads tends to zero. Plan 100 W0 measures the cold-start delta.
- **Trust-claim uplift.** Claim 1 ("no host-fs access from a guest beyond explicit shares") becomes true on both OSes via identical mechanism. Claims 2, 3, 4, 5, 8, 9 inherit the strengthened TCB.
- **Code simplification.** One execution model replaces two. The `mvm-backend/firecracker.rs` direct-launch path retires.
- **Performance.** Nested KVM on Linux is well-supported in mainline kernels (`kvm-intel.nested=1`, `kvm-amd.nested=1` — default-on on most distros since ~5.10). Overhead is single-digit percent on hot paths.
- **Doctor probe needed.** Some hosts (cloud Linux runners, container hosts, locked-down corporate workstations) disable nested virtualization. `mvmctl doctor` must detect and report.

## Rejected alternatives

- **Stay asymmetric.** Uneven trust story; can't make a uniform claim 1. Code paths diverge further over time.
- **Reintroduce Lima for Linux symmetry.** Reverses the 2026-05-14 Lima removal for cosmetic symmetry; brings back YAML lifecycle, ssh-only access, and image distribution complexity. The trust property is independent of Lima — `mvm-libkrun` on Linux gives the same property cleanly without the abstraction debt.

## Open questions

- Builder VM cold-start latency on Linux CI runners. Plan 100 W0 measures this against the current Firecracker-direct baseline.
- Nested KVM availability on cloud Linux hosts. Some cloud hypervisors disable nested virt by default (or expose it via per-VM capabilities). Doctor probe + clear failure mode required.

## Relationship to Plan 98 (Vz builder backend)

Plan 98 ships a second builder-VMM impl (Apple Virtualization.framework / Vz) on macOS 26+ Apple Silicon, parallel to libkrun. That work is **complementary** to this ADR's symmetric-builder uplift:

- **Plan 98** picks which host VMM runs the macOS builder VM (libkrun or Vz). It does not change which OSes have a builder VM at all.
- **This ADR (Plan 100)** adds a builder VM to Linux too, so workload microVMs always run nested.

Plan 98's macOS work narrows the asymmetric-trust gap *on macOS* (it stops requiring the third-party `slp/krun` Homebrew trio when Vz is the default), but Linux still runs Firecracker directly until Plan 100 W2 lands the nested libkrun-on-Linux path. The two efforts ship independently; their selection layers compose via `mvm_build::builder_backend_select::resolve_choice` (Plan 98 introduced) which already has a third arm reserved for future Linux-builder dispatch (Plan 100 W2 will populate it). Builder-backend parity discussion lives in **ADR-046 §"Vz as a second builder backend (Plan 98)"**.

## References

- [ADR-001](001-firecracker-only.md) — Firecracker-only execution (needs update for nested model)
- [ADR-002](002-microvm-security-posture.md) — microVM security posture (claim 1 reworded by Plan 100 W8)
- [ADR-046](046-builder-vm-via-libkrun.md) — builder VM via libkrun + Plan 98 Vz extension
- [Plan 100](../plans/100-symmetric-builder-vm-rollout.md) — implementation rollout


## Consolidated from ADR-065 — Single builder/dev image with mvmctl-embedded Linux binaries

**Status:** Proposed (2026-05-29). Refactored 2026-05-29 to embed the
Linux binaries in `mvmctl` itself (`build.rs` + `include_bytes!`)
rather than invoking cargo at `dev up` runtime. See §Decision.
**Supersedes:** the dev-image-vs-builder-VM-image split established by
ADR-046 §"Two artifact layers, two acquisition paths" — see §Migration.
**Related (do not change in this ADR):** the SDK end-user transparency
story (`crates/mvm-sdk/src/compile/flake.rs`, ADR-0007), and ADR-046's
source-checkout invariant (preserved unchanged here).
**Concurrent work to track:** Plan 107 A1a/A1b — `mvm-builder-init` is
being renamed to `mvm-host-vm-init` (commit `58c737dd` merged, PR
#506 open for the crate rename). ADR-065 names match whichever lands
first; the implementation plan should adopt the final name.

## Context

`mvmctl dev up` from a source checkout today drives this chain:

1. mvmctl spawns Stage 0 (libkrun + libkrunfw kernel + Alpine + nix).
2. Stage 0 runs `nix build path:/work/nix/images/builder-vm#packages.<system>.default`.
3. The flake calls `rustPlatform.buildRustPackage` for `mvm-builder-init`,
   `mvm-egress-proxy`, and (via the dev-image flake) a second copy of
   `mvm-builder-init`.
4. Nixpkgs translates `Cargo.lock` into ~290 per-crate `fetchCrate`
   derivations.
5. Each `fetchCrate` curls `https://crates.io/api/v1/crates/<name>/<v>/download`
   with no User-Agent and gets HTTP 403 under crates.io's data-access
   policy. The build collapses.

Two further smells were uncovered while debugging this:

- **Two flakes producing nearly the same artifact.** `nix/images/builder-vm/`
  produces the headless builder VM; `nix/images/builder/` produces the
  "dev shell" image. The only structural reason the dev image existed
  separately was a circular Stage-0 bootstrap: when the builder-VM cache
  was empty, mvmctl could boot the dev image as PID 1 (`mvm-builder-init`)
  and ask it to build the builder VM. The dev image carries its own
  copy of `mvm-builder-init` solely for that fallback.
- **mvm is rebuilding its own product on every contributor's `dev up`.**
  `mvm-builder-init`, `mvm-egress-proxy`, and (out of scope here)
  `mvm-guest-agent`, `mvm-runner` are mvm's binaries — not user code.
  They should be *inputs* to the builder-VM image build, the same way
  the Linux kernel and busybox are inputs. Today they are translated
  through nixpkgs's curl-based crate fetcher every time, which is both
  the wrong tool (cargo handles this trivially with a proper UA) and
  the wrong responsibility (the builder VM exists to build microVMs,
  not to recompile mvm's source code).

The crates.io 403 problem will be fixed upstream in days (PR
NixOS/nixpkgs#525067 merged 2026-05-28; backport PR #525491 open). A
nixpkgs overlay would unblock today's `dev up`. But shipping that
overlay would entrench both smells above. We have a chance to address
the underlying shape instead.

## Decision

1. **Collapse the dev image and the builder VM image into a single flake
   with two attributes.** `nix/images/builder/flake.nix` is deleted.
   `nix/images/builder-vm/flake.nix` becomes the only flake, producing:
   - `packages.<system>.default` — the headless builder VM. Boots
     for `mvmctl build`, `mvmctl run`, and every other command that
     needs an internal builder. Exits when its job completes.
   - `packages.<system>.dev` — the same base image plus the
     interactive layer: `bashInteractive`, `cargo`, the Rust toolchain
     matching the workspace, an editor, motd, and PTY-over-vsock
     console plumbing. Boots only for `mvmctl dev up`, which always
     attaches a shell — there is no headless `dev` variant by design.

   The Stage 0 chicken-and-egg dance (`bootstrap_builder_vm_image_via_
   dev_image_stage0`) dissolves because there is no longer a separate
   dev image to bootstrap from. Only the Alpine + libkrunfw Stage 0
   path remains.

2. **mvm's Linux binaries are embedded in `mvmctl` at *its own build
   time*, not at `dev up` runtime.** A new contract, all compile-time:

   - **`crates/mvm-cli/build.rs` cross-compiles the Linux binaries
     during `cargo build` of mvm-cli.** For each entry in a Rust
     manifest constant (`crates/mvm-cli/src/host_binaries/
     manifest.rs`), the build script invokes `cargo zigbuild --target
     aarch64-unknown-linux-musl --release -p <cargo_package>` (or
     plain `cargo build` when the build host *is* aarch64-linux) and
     writes the binary to `$OUT_DIR/mvm-host-bins/<name>`. The paths
     are baked into mvmctl as `include_bytes!` byte arrays plus a
     precomputed SHA-256 content hash.

   - **Runtime is just extraction, never compilation.** On the first
     use per mvmctl process, mvmctl extracts each embedded binary to
     `~/.cache/mvm/host-bins/<content-hash>/<name>` (idempotent: a
     fresh mvmctl process with the same binary content hits the
     existing dir; a different mvmctl version writes a different dir).
     mvmctl sets `MVM_HOST_BIN_DIR` to that dir before invoking the
     in-VM nix build. **No runtime cargo invocation. No runtime
     manifest parsing. No `target/` lookup.** mvmctl is a true
     single-binary unit of distribution.

   - **The flake-side view: `nix/lib/mvm-host-binaries.nix`.** A small
     Nix attrset, parallel to `workspace-filter.nix`. Same set of
     entries as the Rust manifest, declaring each binary's
     `install_path` and `mode`:
     ```nix
     {
       mvm-builder-init = {
         install_path = "/sbin/mvm-builder-init";
         mode = "0755";
       };
       mvm-egress-proxy = {
         install_path = "/sbin/mvm-egress-proxy";
         mode = "0755";
       };
     }
     ```
     The flake reads this attrset natively, iterates entries under
     `--impure` using `MVM_HOST_BIN_DIR` to locate the extracted
     binaries, and generates `extraFiles` mechanically — no
     hand-written per-binary entries.

   - **CI invariant: the Rust manifest and the Nix attrset stay in
     sync.** A small xtask (`xtask check-mvm-host-binaries-sync`)
     parses both and asserts the entries match by name and
     `install_path`. Cheap because the manifest is small and changes
     rarely.

   - **No `rustPlatform.buildRustPackage` for mvm's binaries** in the
     builder-VM flake (or in the deleted dev-image flake). The
     `fetchCrate` path stops being on `dev up`'s critical path
     entirely, regardless of what crates.io's data-access policy does.

   - **Contributor toolchain delta:** `brew install zig` plus
     `cargo install cargo-zigbuild` — needed at `cargo build`-of-
     mvmctl time, not at `dev up` runtime. Probed by `mvmctl doctor`
     with install hints, same surface as the existing libkrun trio.
     Native Linux contributors require nothing new.

3. **The dev VM is the builder VM with interactivity.** Both attrs build
   from the same kernel, base userland, networking, mvm binaries,
   security posture, audit chain. The `dev` attr adds packages and
   wires a TTY; nothing about the underlying VM model changes. There
   is no headless dev VM and no interactive builder VM.

## Why cargo zigbuild

Three reasons, in order of how much each actually matters. (These
apply whether zigbuild runs at mvmctl-build-time or at runtime; the
embedding choice in §Decision doesn't change the tool.)

1. **Crates with C in `build.rs` actually compile.** `ring`,
   `aws-lc-rs`, `openssl-sys`, etc. typically fail under Homebrew's
   `aarch64-elf-gcc` because there is no glibc sysroot. Zig ships its
   own multi-arch C toolchain with a real glibc sysroot.
2. **Single Homebrew install (`brew install zig`), no Docker.** Uses
   cargo's native `target/` directory, so incremental compile shares
   state with the contributor's normal `cargo build`. Editing
   `mvm-builder-init` source triggers an incremental cross-compile
   inside `build.rs`, not a full rebuild.
3. **Static musl, so no rootfs loader needed.** The pinned target is
   `aarch64-unknown-linux-musl` (static; see
   `[workspace.metadata.mvm.toolchain]`). The builder VM's minimal
   NixOS-derived rootfs ships no FHS dynamic loader
   (`/lib/ld-linux-aarch64.so.1`), so a glibc-dynamic init binary
   panics the guest with `Requested init … failed (error -2)` (ENOENT
   on the interpreter). A static binary has no interpreter dependency —
   it runs as PID 1 in any rootfs, the same reason mkGuest static-links
   its own `/init`. This supersedes the earlier glibc-version-pinning
   approach (`gnu.2.17`), which only worked if the rootfs carried a
   matching loader. Both host binaries are libc-only (no `ring` /
   `openssl-sys` / TLS), so the musl build is unencumbered.

Alternatives considered:

- **`cross`** (Docker-based) — slower startup, separate target dir
  from cargo's, Docker dependency on macOS contributors.
- **Hand-rolled Homebrew cross-toolchain** — high per-contributor
  setup tax, breaks on C-in-`build.rs` crates, no glibc sysroot.
- **Cargo at `dev up` runtime instead of `mvm-cli`'s `build.rs`** —
  the rejected earlier draft. Conflates mvmctl's orchestration
  responsibility with build-system orchestration; introduces a
  runtime dependency on cargo + zigbuild even after mvmctl is built;
  makes mvmctl-the-binary not a self-contained unit.
- **Build inside a Linux container/VM** — slower inner loop, runs
  against the responsibility split established here (the dev/builder
  VM's job is *building microVMs*, not recompiling mvm).
- **Cargo inside the builder VM, bootstrap-staged** — recreates the
  Stage 0 chicken-and-egg shape in a new place.

## Architecture / data flow

### Layers (with sharp boundaries)

- **mvmctl build time (`cargo build` of mvm-cli)** — `build.rs`
  cross-compiles each entry in the host-binaries manifest via
  `cargo zigbuild`. Outputs land in `$OUT_DIR/mvm-host-bins/<name>`
  and are baked into the mvmctl binary via `include_bytes!` plus a
  precomputed SHA-256. From the artifact perspective: the mvmctl
  binary now contains everything it needs to run a builder/dev VM.
- **mvmctl runtime (host)** — On first use per process, extracts the
  embedded binaries to `~/.cache/mvm/host-bins/<content-hash>/`
  (idempotent). Sets `MVM_HOST_BIN_DIR` for downstream use. **No
  cargo invocation. No `target/` lookup. No manifest parsing.**
- **Stage 0 (libkrun + libkrunfw kernel + Alpine + nix)** —
  unchanged in role. New inputs: the extracted binary dir mounted at
  `/mvm-bins` via virtio-fs, and `MVM_HOST_BIN_DIR=/mvm-bins` in env.
  Output: builder-VM image artifacts (`vmlinux` + `rootfs.ext4` +
  cmdline.txt + manifest.json). The flake never compiles Rust.
  Rootfs assembly uses `mkfs.ext4 -d <staged-dir>` (a populate-at-
  format pattern) so the final image is built from a populated
  directory tree in one step.
- **Builder VM (the produced image)** — one image, two attrs as
  defined in §Decision.

### `mvmctl dev up` end-to-end

Steps in **bold** are new or substantially changed; the rest match
today's shape.

1. User runs `mvmctl dev up` (always interactive).
2. mvmctl detects source-checkout mode (workspace + flake present).
3. **mvmctl extracts the embedded Linux binaries to
   `~/.cache/mvm/host-bins/<content-hash>/`** if not already there.
   The hash is part of the mvmctl binary; identical mvmctl binaries
   produce identical extractions and reuse the same dir.
4. mvmctl boots Stage 0 with two virtio-fs shares: `/work`
   (workspace) and **`/mvm-bins`** (the extracted dir from step 3).
5. Stage 0 runs `nix build path:/work/nix/images/builder-vm#packages.
   <system>.dev --impure` (`.default` for non-`dev` commands).
   `MVM_HOST_BIN_DIR=/mvm-bins` set in env.
6. **The flake reads `mvm-host-binaries.nix`, iterates entries, and
   generates `extraFiles` entries pointing at `/mvm-bins/<name>` with
   the declared `install_path` and `mode`.** No `rustPlatform`. No
   `fetchCrate`.
7. Nix produces `vmlinux` + `rootfs.ext4` (assembled via
   `mkfs.ext4 -d`); Stage 0 powers down.
8. mvmctl extracts to `~/.cache/mvm/builder-vm/<system>/`, keyed on
   (workspace SHA, mvmctl host-bin content hash, flake SHA).
9. mvmctl boots the dev VM via whichever backend the host selects
   (libkrun / Vz / Apple Container per the existing
   `MVM_BUILDER_BACKEND` rules).
10. mvmctl opens a PTY-over-vsock console into the running VM.

For `mvmctl build`, `mvmctl run`, and other non-`dev` commands: same
path, but step 5 targets `packages.<system>.default`, step 9 boots
headless, no step 10.

### Cache invalidation

- **mvmctl binary changes** (e.g., because `mvm-builder-init` source
  changed and `build.rs` re-cross-compiled) → embedded content hash
  changes → cache key changes → rebuild.
- `mvm-host-binaries.nix` changes → flake re-bakes → cache key
  changes → rebuild.
- Workspace SHA changes elsewhere → cache key changes → rebuild.
- Nothing changed → mvmctl boots straight from cache; extraction is
  a no-op (target dir already exists).

## Component-level diff

### New

- `nix/lib/mvm-host-binaries.nix` — flake-side attrset (the manifest's
  Nix view). Single purpose, pure data.
- `crates/mvm-cli/build.rs` — orchestrates the cross-compile during
  `cargo build` of mvm-cli. Invokes `cargo zigbuild` per manifest
  entry, computes SHA-256 of each output, writes both bytes and
  hashes into `$OUT_DIR/mvm-host-bins/`.
- `crates/mvm-cli/src/host_binaries/` — small module: `manifest.rs`
  declares the Rust-side manifest constant; `embedded.rs` exposes
  the `include_bytes!`'d binaries + their hashes; `extract.rs`
  handles the idempotent extraction to `~/.cache/mvm/host-bins/
  <hash>/`.
- `xtask check-mvm-host-binaries-sync` — CI lane asserting the Rust
  manifest and `nix/lib/mvm-host-binaries.nix` agree on name set and
  `install_path`.

### Modified

- `nix/images/builder-vm/flake.nix` — substantially rewritten:
  - Two attrs: `packages.<system>.default` and `packages.<system>.dev`.
  - No `rustPlatform.buildRustPackage` for mvm binaries.
  - Reads `mvm-host-binaries.nix` and `MVM_HOST_BIN_DIR` under
    `--impure`; generates `extraFiles` mechanically.
  - The `dev` attr adds `bashInteractive`, `cargo`, Rust toolchain,
    editor, motd, PTY-over-vsock console wiring.
  - Rootfs assembly: explicit `mkfs.ext4 -d <staged-dir>` (or the
    nixpkgs equivalent if `mkGuest` already does this internally —
    confirm during implementation; either way the assembly step is
    legible in the flake, not buried).
- `nix/lib/workspace-filter.nix` — drops `nix/images/builder` from
  its list of consumers (3 → 2).
- `crates/mvm-cli/src/commands/env/apple_container.rs` — collapses
  the source-checkout dispatch: the `find_dev_image_flake` /
  `ensure_source_checkout_dev_image` /
  `resolve_source_checkout_dev_image` branches go away.
  `cmd_dev_libkrun` / `cmd_dev_vz` call into
  `host_binaries::ensure_extracted()` (cheap on warm runs) before
  invoking nix, and target the `dev` attr.
- `crates/mvm-build/src/pipeline/dev_build.rs` —
  `dev_build_with_builder_vm` mounts the host-bin dir from
  `host_binaries::ensure_extracted()` and passes `MVM_HOST_BIN_DIR`
  into the in-VM nix invocation.
- `crates/mvm-cli/src/doctor.rs` — adds a build-time probe report
  for `zig` and `cargo-zigbuild` on macOS contributors with install
  hints (these are needed for `cargo build` of mvm-cli, not for `dev
  up`). Native Linux contributors pass trivially. The doctor also
  reports the embedded-binary content hashes (one-line each) so
  contributors can sanity-check what their mvmctl carries.
- `CLAUDE.md` "Host dependencies (macOS)" — adds `zig` and
  `cargo-zigbuild` as build-time deps for source-checkout
  contributors. Clarifies these are not needed at `dev up` runtime.

### Deleted

- `nix/images/builder/flake.nix` — gone.
- The four `rustPlatform.buildRustPackage` call sites for
  `mvm-builder-init` / `mvm-egress-proxy` across the builder-vm and
  builder flakes.
- `find_dev_image_flake`, `ensure_source_checkout_dev_image`,
  `resolve_source_checkout_dev_image`,
  `bootstrap_builder_vm_image_via_dev_image_stage0` in
  `apple_container.rs`.
- The `mvmBuilderInitFor` helper duplicated between the two flakes —
  only one consumer survives, and it's not `rustPlatform`-based.

### Touched only mechanically

- Tests referencing the deleted flake or dispatch helpers — updated
  to the single-flake shape or removed if redundant.
- `nix/images/runtime-overlay/flake.nix` — left intact (out of scope;
  it still uses `rustPlatform` for `mvm-runner` and the guest agent).
  The mechanism defined here is reusable by a later spec that
  converts runtime-overlay to embed those binaries the same way;
  doing so is explicitly *not* required for this spec.

## Error handling

- **`zig` or `cargo-zigbuild` missing during `cargo build` of mvm-cli
  on macOS:** `build.rs` exits with a `cargo:warning=…` line that
  names the missing tool and the install command. Failing the build
  is correct — without zigbuild we cannot produce a working mvmctl.
- **Cargo build fails for any configured package at mvmctl-build
  time:** cargo's normal stderr appears; `build.rs` surfaces the
  failing package name in its own error context so the cause is
  locatable.
- **At runtime, extraction fails (filesystem error, perms):**
  mvmctl fails fast with the target dir path and the underlying I/O
  error. No fallback to "try cargo" — there is no runtime cargo path.
- **`MVM_HOST_BIN_DIR` not set when the flake is evaluated:** the
  flake errors loudly with the contract documented inline (a
  contributor running `nix build` directly without going through
  mvmctl gets a useful message, not a Nix evaluation failure 12
  layers deep).
- **A binary declared in `mvm-host-binaries.nix` not present in
  `MVM_HOST_BIN_DIR`:** the flake errors with the missing name +
  the dir path. The CI sync check makes this combination impossible
  in CI but it's still possible on a contributor's machine if
  someone manually rewrites the Nix attrset without rebuilding
  mvmctl.

## Testing

- **Unit tests (`crates/mvm-cli/src/host_binaries/`):** parse the
  manifest, assert the embedded SHA-256 matches the embedded bytes,
  assert extract is idempotent against an existing populated dir.
- **`build.rs` integration test:** a small fixture asserts `build.rs`
  produces non-empty binaries with valid ELF headers for
  aarch64-unknown-linux-gnu and embeds them under the expected names.
- **`xtask check-mvm-host-binaries-sync` test:** asserts the Rust
  manifest and `mvm-host-binaries.nix` agree on name set and
  install_path; deliberate divergence triggers a clear failure.
- **Flake-side fixture test:** feeds a hand-crafted
  `MVM_HOST_BIN_DIR` (with placeholder binaries) into `nix build`
  and asserts the produced rootfs.ext4 has files at the declared
  install paths with the declared modes.
- **End-to-end smoke (CI macOS lane):** runs the real `cargo build`
  of mvm-cli (triggering the embedded cross-compile), then runs
  `mvmctl dev up`, asserts the produced builder-VM image has
  `/sbin/mvm-builder-init` and `/sbin/mvm-egress-proxy` with
  SHA-256 matching the embedded hashes.
- **Tests touching the deleted dev-image dispatch helpers** —
  updated to reflect the collapse (most likely removed; the helpers
  are gone).

## Out of scope

- **Converting `nix/images/runtime-overlay/flake.nix` and the guest
  agent's build to use the embedded-binary contract.** The mechanism
  is reusable; doing the conversion is a follow-up spec. Keeps blast
  radius small.
- **The SDK's `mkGuest` adoption of the same contract** for end-user
  microVMs (so end-user `mvmctl compile` becomes
  `fetchCrate`-independent). Same reasoning — separate spec, separate
  PR. The mechanism here is designed to be adopted there later
  without changes.
- **Release pipeline changes.** Today's release workflow already
  cross-compiles to `aarch64-unknown-linux-gnu`; the embedded-binary
  pattern means the release pipeline only needs to ship the mvmctl
  binary (everything else rides inside it). No standalone Linux
  binary release artifacts to publish. Called out as a simplification
  this spec enables but does not enforce.
- **The `builder_vm_timeout()` value** and the partial-cache
  promotion bug observed during debugging this. Both are pre-existing,
  unrelated, and out of scope. Calling them out so future readers
  know they were noticed and parked.
- **Merging `mvm-builder-init` and `mvm-egress-proxy` into a single
  multi-call binary.** Considered (busybox-style would save ~5 MB on
  the embedded payload). Rejected because they have different uid
  policies and different threat-model exposure: builder-init is PID
  1, egress-proxy is uid 1801 and internet-facing. Merging conflates
  two things the security model treats separately. Future cleanup
  not blocked here.
- **Any change to `mvm.toml` shape or the SDK's end-user transparency
  story.** Reserved for the SDK's own specs.

## Future directions

(Not part of this spec — flagged so the implementation plan doesn't
paint future work into corners.)

- **OCI-base userland.** An external reference design pulls a Debian
  OCI image as the rootfs base, customises it in a chroot, and
  `mkfs.ext4 -d`'s the result. We already have `mvm-oci` in the
  repo (claim 10) for the end-user workload path. Using the same
  pattern for the *builder/dev VM rootfs* — Debian/Alpine base + mvm
  binaries on top, no nixpkgs busybox/iptables/etc. — would drain
  Nix from the rootfs userland side, complementing how ADR-065 drains
  it from the Rust-build side. Big architectural shift with its own
  threat-model implications (provenance of the OCI base, signature
  chain). Worth its own brainstorm later.
- **Apply the embedded-binary contract to runtime-overlay** so
  `mvm-runner` and `mvm-guest-agent` follow the same shape. Removes
  another `rustPlatform.buildRustPackage` site.
- **SDK's `mkGuest` adoption.** End-user `mvmctl compile` becomes
  `fetchCrate`-independent the moment `mkGuest` consumes the same
  contract.
- **Plan 107 A1b crate rename.** `mvm-builder-init` →
  `mvm-host-vm-init` is in flight (PR #506). ADR-065's implementation
  plan should adopt whichever name lands first and is expected to
  use the new name end-to-end if A1b merges before this work begins.

## Consequences

### Positive

- **`fetchCrate` exits mvm's hot path.** crates.io's User-Agent policy,
  rate limits, and future surprises stop being a `dev up` concern.
- **mvmctl is a true single-binary unit of distribution.** No
  runtime cargo dependency. No `target/` lookup. No separate Linux
  binary release artifacts. End-user downloads one file; that file
  contains everything it needs to build and run a builder/dev VM.
- **Single image, single source of truth.** The dev/builder split
  dissolves. The Stage-0 chicken-and-egg fallback (boot dev image to
  build builder VM) dissolves with it.
- **Cleaner responsibility split.** mvmctl is a VM orchestrator;
  cargo is a build system; nix assembles the rootfs. Each does
  exactly one job. The previous draft had mvmctl shelling out to
  cargo at runtime — this version eliminates that.
- **Less surface area in mvmctl.** Three dispatch helpers
  (`find_dev_image_flake`, `ensure_source_checkout_dev_image`,
  `resolve_source_checkout_dev_image`) go away. One bootstrap path
  remains, not two.
- **Aligns with existing release infrastructure.** `release.yml`
  already cross-compiles to `aarch64-unknown-linux-gnu`; the
  embedded path uses the same target triple and toolchain logic
  inside mvm-cli's `build.rs`.

### Negative

- **mvmctl binary grows by the embedded payload** (probably +5–15 MB
  for two static `-gnu` binaries; less if we eventually go `-musl`
  static). Cost is real but bounded.
- **`cargo build` of mvm-cli now does the cross-compile.** First
  build adds ~30–60s for the two Linux binaries. Subsequent builds
  are incremental — editing `mvm-builder-init` source rebuilds only
  that crate via cargo's normal incremental detection, then re-links
  mvmctl (the link step is what feels slow, not the cross-compile).
- **Iterating on `mvm-builder-init` source incurs a mvmctl re-link.**
  Not a full rebuild, but noticeable on a hot loop. Mitigation:
  contributors who are deep in `mvm-builder-init` work can run
  `cargo build -p mvm-builder-init --target aarch64-unknown-linux-gnu`
  directly and skip the mvmctl link; mvmctl's `MVM_HOST_BIN_DIR_OVERRIDE`
  env var (TBD during implementation) can point at the bare target/
  output for that workflow. Not required for normal use.
- **The Rust manifest and the Nix attrset are two-sided.** CI sync
  check enforces equivalence. Cost is small because the manifest is
  small and changes rarely.
- **New host build-time deps for macOS source-checkout contributors:**
  `zig` + `cargo-zigbuild`. One brew install + one cargo install,
  probed by doctor. Native Linux contributors are unaffected.

## Migration

The deletion of `nix/images/builder/flake.nix` is the high-blast
change. Specifically:

- Anything that called `find_dev_image_flake()` returns `Err` because
  the file is gone; the dispatch above it is removed in the same PR
  so the call no longer exists.
- The Stage 0 path `bootstrap_builder_vm_image_via_dev_image_stage0`
  is deleted. Only `bootstrap_builder_vm_image_via_root_dir_stage0`
  remains (the Alpine + libkrunfw path that's been the source-checkout
  default since Plan 92/95).
- `~/.mvm/dev/current/` (the cached dev image, separate from the
  builder-VM cache) becomes a stale concept. A best-effort cleanup
  on first `dev up` after the upgrade isn't required; the dir simply
  stops being read.
- **Existing mvmctl binaries that predate this change cannot use the
  new flake.** Cache invalidation is automatic (the content-hash key
  for the builder-VM cache will not match), but contributors must
  rebuild mvmctl once after the merge.

## Verification

- `mvmctl dev up` from a clean macOS source checkout, after a
  successful `cargo build` (with `zig` + `cargo-zigbuild` installed):
  no runtime cargo invocation; Stage 0 produces the builder-VM
  image from the embedded binaries; dev VM boots with a working
  interactive shell. No `crates.io` reachability required at any
  point during Stage 0's `nix build`.
- `mvmctl build` (or any non-`dev` command requiring the builder VM)
  from the same setup: same Stage 0 path, builder VM boots headless,
  job completes, VM exits.
- Edit a file in `mvm-builder-init/src/` and re-run `cargo build`
  followed by `mvmctl dev up`: `build.rs` incrementally re-cross-
  compiles `mvm-builder-init`; mvmctl re-links with the new embedded
  payload; new content hash; Stage 0 re-bakes the rootfs; the rest
  of the closure stays cached in the persistent `/nix-store`.
- Manually running `nix build path:.#packages.<system>.default --impure`
  without `MVM_HOST_BIN_DIR` set: clear, documented error pointing
  at the contract.
- Audit chain (claims 8 / 9 / 10): builder VM image's audit
  emission and verification are unaffected because the rootfs
  contents, paths, and binaries' SHA-256s are still deterministic
  given a fixed mvmctl binary + flake.

## References

- ADR-046 — Builder VM via libkrun. This ADR amends the "Two artifact
  layers" rule by collapsing the dev image into the builder VM image.
- Plan 72 — Builder VM via libkrun (the implementation of ADR-046).
- Plan 92, 95 — Alpine + libkrunfw Stage 0; the path this spec
  doubles down on as the only Stage 0 path going forward.
- Plan 107 A1a/A1b — Concurrent `mvm-builder-init` →
  `mvm-host-vm-init` crate rename (commit `58c737dd` merged; PR
  #506 open). ADR-065 implementation should adopt the final name.
- `crates/mvm-sdk/src/compile/flake.rs` and ADR-0007 — the end-user
  flake generation path, which adopts the same embedded-binary
  contract in a future spec.
- An external microVM reference project's build tooling — the
  `mkfs.ext4 -d <staged-dir>` rootfs assembly pattern we lift, and the
  direct-kernel-boot precedent we already follow.
- NixOS/nixpkgs PR #525067 — the upstream `fetchCrate` fix
  (static.crates.io) that motivated this redesign. The overlay was
  considered as a workaround and explicitly rejected in favor of
  removing the dependency on `fetchCrate` for mvm's own binaries.


## Consolidated from ADR-068 — Stage 0 dispatches through the `BuilderVm` trait (backend-agnostic bootstrap seam)

**Status**: Accepted
**Date**: 2026-06-01
**Cross-refs**: ADR-013 (libkrun pivot — host never needs Nix), ADR-046 (builder VM via libkrun, the canonical builder-VM ADR), ADR-065 (single builder/dev image, embedded host binaries), ADR-066 §1 (name by role, front with a trait, hide impls), ADR-002 (security posture — dev-tier builder VM). Planning input: Plan 91 (Alpine-minirootfs Stage 0), Plan 97 (`VmBackendForBuilder` hypervisor-agnostic seam), Plan 98 (libkrun/Vz builder-backend selection).

## Context

"Stage 0" is the from-source bootstrap that produces the steady-state builder VM (`vmlinux` + `rootfs.ext4`) on a contributor host with no host Nix and no prebuilt artifacts (ADR-046). The live path (Plan 91) boots an Alpine minirootfs guest under libkrun whose `/init` runs `apk add nix`, builds `nix/images/builder-vm/flake.nix`, and writes the artifacts to `/out`.

The build path (`run_build`) and the per-VM spawn primitive (`VmBackendForBuilder`, Plan 97) are already fronted by traits with libkrun + Vz impls. **Stage 0 was the exception:** `run_stage0` lived as a libkrun-*inherent* method on `LibkrunBuilderVm`, and the orchestration in `mvm-cli` called `LibkrunBuilderVm::default().run_stage0(...)` directly. That hard-wires the bootstrap to one VMM and violates ADR-066 §1 ("name by role, front with a trait, hide impls"). It also reads as a hack: the very first thing the tool does on a fresh host is welded to libkrun, even though macOS 26+ Apple Silicon defaults to the Vz builder backend (Plan 98) for every *subsequent* build.

## Decision

**`run_stage0` moves onto the `BuilderVm` trait.** The orchestration dispatches Stage 0 through `&dyn BuilderVm`, the same seam `run_build` uses. The signature is backend-agnostic — `(guest_root_dir, entry_path, workspace_dir, artifact_out, host_bin_dir)`, all `&Path`/`&str`, no libkrun types. The libkrun impl adapts those to its `BuilderVmImage::RootDir` internally.

```
BuilderVm (mvm-build/src/builder_vm.rs)
  fn run_build(..)                 -> existing
  fn run_stage0(root, entry, ..)   -> NEW; default = fail-closed gap
  fn cleanup(..)                   -> existing

impl BuilderVm for LibkrunBuilderVm  -> overrides run_stage0 (the only impl today)
impl BuilderVm for VzBuilderVm       -> inherits the default gap
impl BuilderVm for StubBuilderVm     -> inherits the default gap
```

### Backend gaps

The default `run_stage0` is a **fail-closed gap, not a silent no-op and not a `todo!()` panic**: it returns `BuilderVmError::VmmUnavailable { requested: "stage0-bootstrap", reason }` naming the supported backend (libkrun) and this ADR. Stage 0 is implemented for **libkrun only** today.

- **Vz Stage 0** — deferred. Vz is the macOS-26+ default for *builds* (Plan 98), but the Alpine-bootstrap Stage 0 has no Vz impl yet. The orchestration therefore binds libkrun concretely for Stage 0 (it does **not** route through the Plan 98 libkrun/Vz selector), so macOS-26+ hosts still bootstrap via libkrun and then run builds under Vz. Tracked in Plan 133.
- **Firecracker Stage 0** — deferred. Firecracker is the Linux runtime path; on Linux contributor hosts Stage 0 runs the same libkrun-backed bootstrap. mvmd drives Firecracker+jailer independently and does not consume this seam. Tracked in Plan 133.

Routing Stage 0 through the Plan 98 selector is **out of scope** until a second backend implements `run_stage0`; doing it now would regress macOS-26+ hosts to the gap error. The seam exists so that wiring is a localized change (one impl + flip the dispatch) when a Vz/Firecracker Stage 0 lands, with no change to the `mvm-cli` orchestration.

### Why this and not the deeper `VmBackendForBuilder` port

Plan 97 already landed `VmBackendForBuilder` — the lower-level spawn primitive (`run_attached_with_mounts` + `console_log_path`) — with the intent that a future `BuilderVmRuntime` helper lifts ~850 lines of orchestration (cmd.sh emission, `/job/result` parsing, panic detection, `NixStoreImageLock`) out of `LibkrunBuilderVm` so Vz reuses it. That port is the larger effort. This ADR is the *complementary, smaller* move: `run_stage0` belongs on the high-level `BuilderVm` driver next to `run_build`, and promoting it is a contained change that delivers the backend-agnostic Stage 0 dispatch immediately without blocking on the full port.

## Consequences

- The `mvm-cli` Stage 0 orchestration no longer names a concrete VMM in its call path — it holds `&dyn BuilderVm`. Adding a backend is an impl, never an orchestration edit (ADR-066 §1).
- No behavior change today: libkrun remains the sole Stage 0 backend; the artifact bytes and the `.mvm-artifacts.sha256` / `.mvm-provenance.json` sidecars are unchanged.
- A backend that forgets to implement Stage 0 fails loudly with a recovery hint, not silently.
- Security posture unchanged: Stage 0 is the dev-tier builder VM (ADR-002 out-of-scope for the hardened workload claims); this is a structural refactor of the dispatch, not of the trust model.

## Status of work

Libkrun dispatch + the fail-closed default + tests landed with this ADR. Vz and Firecracker Stage 0 impls are sequenced in Plan 133.


## Consolidated from ADR-071 — Stage 0 bootstrap trust model: hash-pinned Nix tarball seed, one userland

**Status**: Accepted
**Date**: 2026-06-05
**Cross-refs**: ADR-013 (libkrun pivot — host never needs Nix), ADR-046 (two artifact layers; contributor path never downloads mvm-published artifacts), ADR-065 (single builder/dev image; host-vm binaries cross-compiled to static `aarch64-musl` + embedded by `mvm-cli/build.rs`), ADR-068 (Stage 0 dispatches through the `BuilderVm` trait), ADR-002 (security posture — Stage 0 is the dev-tier builder VM, out of scope for the hardened workload claims). Planning input: Plan 160 (this seed swap), Plan 126 A1/B3 (dependency baseline — `pgp` was the single biggest closure in the default `mvmctl` binary).

## Context

"Stage 0" is the one-shot from-source bootstrap that stands up the *first* working Nix on a contributor host with no host Nix and no prebuilt artifacts (ADR-013, ADR-046). That first Nix then builds the steady-state busybox builder VM (`nix/images/builder-vm/`), which builds everything else.

The chicken-and-egg is unavoidable: **you cannot Nix-build the first Nix.** The seed has to come from outside the Nix build. The previous seed (Plan 91) solved it with an **Alpine minirootfs**: `stage0.rs` downloaded Alpine's tarball, SHA-256-checked it, **PGP-verified it against Natanael Copa's embedded release key**, and booted its `/init` (`stage0/init.sh`), which ran `apk add nix e2fsprogs …` — Alpine existed *solely* to provide `apk` so it could install Nix.

This made the repo depend on **two userlands**: busybox everywhere that matters (the builder VM rootfs + every workload microVM, via `nix/lib/mk-guest.nix`'s `pkgsStatic.busybox`), and Alpine only as a throwaway Stage-0 scaffold. The split cost us:

- The **`pgp` crate — a 168-crate closure, the single largest dependency in the default `mvmctl` binary** (Plan 126 A1) — which existed *only* to verify the Alpine seed tarball.
- An external supply-chain trust dependency on **Alpine's mirror + Copa's release key + `apk`'s repo trust chain**, layered on top of the SHA-256 pin that already bound the bytes.

## Decision

**Seed Stage 0 with the official Nix release tarball, hash-pinned, plus an in-repo static `stage0-init` PID 1. One userland — busybox. No Alpine, no `apk`, no PGP.**

### What we download and how it's pinned

The seed is the **official Nix release tarball** —
`https://releases.nixos.org/nix/nix-<ver>/nix-<ver>-<arch>-linux.tar.xz` — pinned by **URL + SHA-256** in source (`NIX_SEED_AARCH64` / `NIX_SEED_X86_64`, `NIX_SEED_VERSION` in `crates/mvm-build/src/stage0.rs`). Extracted, its `store/` *is* a populated `/nix/store` carrying `nix` + its full runtime closure: `bash`, `curl`, `xz`, **`nss-cacert`** (CA trust comes free), glibc, openssl. The tarball is a self-contained, upstream-published artifact — the same category Alpine's minirootfs was.

The **SHA-256 pin is the binding integrity check** (verified at fetch *and* re-verified at extract, fail-closed both times — `prepare_assets_in` + `materialize_root_dir_in`). A `VendorBlobReport` is emitted per fetch/revalidation into the chain (`LocalAuditKind::VendorBlobFetched`), carrying `url`, `sha256`, `bytes`, `outcome` — every supply-chain trust decision on the no-prebuilt-download path stays auditable.

### Why dropping the Alpine PGP layer is safe

A pinned SHA-256 over a specific upstream-published version is a *stronger* binding than a detached signature over a moving "latest": the hash names exactly one byte sequence, fail-closed, with no trust delegated to a third-party key whose rotation we'd have to track. The previous PGP step verified Alpine's tarball against Copa's key; that's a guarantee *about Alpine's release process*, not about the bytes we actually want — which the hash already nails. Removing it deletes an external trust dependency (Alpine mirror + key + `apk`) without weakening the integrity guarantee on the seed we boot. This is consistent with the repo's broader posture (ADR-046 — the contributor path is hermetic and never trusts mvm-published prebuilts; here it trusts only a hash-pinned upstream Nix release).

### The seed userland: `stage0-init`, not a shell script

The Nix tarball's bundled `busybox-1.36.1` is **`busyboxMinimal`** — `sh`/`ash` only, no `mount`/`ip`/`udhcpc`/`mkfs`. So the seed cannot provide a full `/init` userland from the tarball alone, and busybox.net has no reliable aarch64 prebuilt to pin alongside it (sourcing a second external userland would reintroduce exactly the dependency we're removing).

Instead the seed's PID 1 is **`stage0-init`** — a small static `aarch64-unknown-linux-musl` binary in this repo (`crates/mvm-build/src/bin/stage0-init.rs`), cross-compiled and embedded by `mvm-cli/build.rs` through the same machinery as the other host-vm binaries (ADR-065), registered via a host-side-only `SEED_BINARIES` list (it is never installed into a VM and is absent from the nix attrset / the host-binaries sync gate). `materialize_root_dir` lays down the extracted `/nix/store` and writes `stage0-init` as `/init`; libkrun runs it via `krun_set_exec`.

`stage0-init` does the irreducible bring-up in Rust (no external userland): mount the pseudo-filesystems + the `/work`/`/out`/`/mvm-bins` virtio-fs shares; make `/nix` a writable store (copy the seed closure into a tmpfs and bind it over `/nix` — **overlay-over-virtiofs writes fail in libkrun**, nix's `/nix/store/.links` hits `ECONNRESET`); write `/etc/resolv.conf` pointing at gvproxy's gateway (libkrun's `NET_FLAG_DHCP_CLIENT` brings up eth0 + DHCP but **not** DNS); then `nix build` the in-repo builder-VM flake (single-user: `NIX_REMOTE=` + `--option build-users-group ""`, default sandbox kept), copy `vmlinux` + `rootfs.ext4` to `/out`, and power off. This is the `BuilderVm::run_stage0` libkrun impl (ADR-068); the host-side contract (`/out/stage0-build.conf`, output modes) is unchanged.

## Consequences

- **`pgp` is deleted outright** — no feature gate, no caveat. `cargo tree -i pgp` is empty; the default `mvmctl` closure drops ~168 crates (379 unique vs the 407 Plan 126 A1 baseline, net of overlap).
- **One userland story.** Everything mvm boots is busybox: the seed's shell, the builder VM rootfs, every workload microVM. Alpine, `apk`, the embedded release key, and `init.sh` are gone from the tree.
- **`MVM_STAGE0_SEED` is gone.** The nix seed is the only Stage 0 path; there is no Alpine fallback to select. (No backwards compatibility — this is the first version.)
- **Security posture unchanged.** Stage 0 is the dev-tier builder VM (ADR-002 out-of-scope for the hardened workload claims). The seed integrity check is *strengthened in surface* (one hash-pinned upstream artifact, fail-closed at fetch + extract) and *narrowed in trust* (no third-party signing key).

## Status of work — validation caveat

Proven **end-to-end on aarch64 / libkrun** (this contributor host): a cold `mvmctl dev up` materializes the nix seed, boots `stage0-init`, runs `nix build` (substituting the toolchain from `cache.nixos.org`), produces `vmlinux` (31 MiB) + `rootfs.ext4` (743 MiB), boots the builder VM from them, and reaches "Dev environment ready (libkrun)" — no Alpine/apk/pgp. The tmpfs-copy store did not OOM on the full build.

Outstanding, sequenced as Plan 160 follow-ups (do not block this ADR):

- **x86_64 is not wired yet — mvmctl is aarch64-guest only today.** This is *not* merely "the x86_64 seed is unbooted." The embedded host-vm binaries (`stage0-init`, `mvm-host-vm-init`, `mvm-egress-proxy`) are all cross-compiled to a **single pinned target** — `aarch64-unknown-linux-musl` (`[workspace.metadata.mvm.toolchain] target` in the root `Cargo.toml`; `mvm-cli/build.rs` reads it). So on an x86_64 Linux host, mvmctl would embed an **aarch64** `stage0-init` and hand it to an x86_64 Stage 0 VM — a wrong-arch ELF that cannot exec. The `NIX_SEED_X86_64` pin in `stage0.rs` is therefore real but **unreachable** until the embed toolchain selects its musl target from the guest arch. This is a **pre-existing ADR-065 limitation** (it predates this seed swap — all three embedded binaries have always been aarch64-only), not something Plan 160 introduced. Making it multi-arch — `build.rs` picks the target per guest arch, the Cargo metadata lists both, and a `/dev/kvm`-backed CI lane (ubuntu-latest exposes `/dev/kvm`) boots a cold x86_64 Stage 0 — is its own workstream, broader than Plan 160 and properly scoped against ADR-065.
- **Persistent ext4 `/nix` store.** `stage0-init` currently copies the seed closure into tmpfs each boot; the host still attaches the persistent `nix-store-stage0-<arch>.img` disk (`/dev/vda`), but `stage0-init` does not yet bootstrap e2fsprogs + format + use it. This is a RAM optimization (build once, reuse the closure across `dev up` runs), not a correctness requirement — the tmpfs store holds for the full build.
- ~~**In-process xz decode.**~~ **Done (2026-06-05).** `extract_nix_store_tarball` now decodes the `.xz` with `lzma-rs` (pure Rust, no host `tar`, no liblzma C dep) and unpacks via the `tar` crate, with `lift_single_top_level` doing the `--strip-components=1` equivalent. Host-side seed materialization is fully self-contained.


## Consolidated from ADR-096 — Stage 0 seed Nix (2.31.1) computes divergent flake narHashes; fresh-machine builder-VM build is broken

**Status:** Proposed — **decision needed** (do not merge a fix from this doc; this is the write-up + the question)
**Relates:** ADR-005 §"Consolidated from ADR-071" (Stage 0 seed Nix is URL+SHA-256 pinned), ADR-014 (consolidated from ADR-093) (builder auto-fallback — why this stays masked), Plan 160 (the nix-seed Stage 0 cutover that introduced the seed version).

## Symptom

On a machine **without a warm builder-VM cache**, the very first
`mvmctl machine run --image <oci>` (and any builder-VM build) fails: the Stage 0
bootstrap's `nix build path:/work/nix/images/builder-vm#packages.<arch>.dev`
exits 1 with:

```
error: mismatch in field 'narHash' of input
  '{"__final":true,"lastModified":1778430510,
    "narHash":"sha256-Ti+ZBvW6yrWWAg2szExVTwCd4qOJ3KlVr1tFHfyfi8Q=",
    "owner":"NixOS","repo":"nixpkgs",
    "rev":"8fd9daa3db09ced9700431c5b7ad0e8ba199b575","type":"github"}',
  got
  '{… "narHash":"sha256-hOlf/RVFs9vVyapFtW6+/jp209mi+UAat/cqa2hrc+Y=" …}'
```

Both builder backends fail it (vz first, then the ADR-093 libkrun fallback), so
the log shows two failures. The command can still *appear* to succeed — see
"Why it's masked".

## Why it's masked (and how it was found)

It was observed on a macOS-26 dev box where `mvmctl machine run --image alpine`
still printed its output. That only worked because the ADR-093 builder fallback,
after both rebuilds failed, reused a **pre-existing cached `rootfs.ext4` +
`vmlinux`** under `~/.cache/mvm/builder-vm/<arch>/`. The narHash check is
input-deterministic (it fails on every evaluation, independent of cache), so the
failure is real — a clean machine has no cached image to fall back to and the
command fails. The on-disk failed job
(`~/.cache/mvm/builder-vm/jobs/<id>/{cmd.sh,result,nix-stderr.log}`) is the
clean-build attempt.

## Evidence / root cause

Same nixpkgs **rev** (`8fd9daa3…`) and same **lastModified**, but a **different
narHash** depending on the Nix version computing it:

| Who | nixpkgs narHash for rev `8fd9daa3` | Agrees with the lock? |
|---|---|---|
| repo flake.locks (generated ~2026-05-15, `c05f5666`) | `sha256-Ti+ZBvW6…` | — (this *is* the lock) |
| **Stage 0 seed Nix 2.31.1** (the builder bootstrap) | `sha256-hOlf/RVFs9…` | **NO** |
| Nix 2.34.7 (an independent modern Nix) | `sha256-Ti+ZBvW6…` | **YES** |

So the **locks are correct** (a modern Nix 2.34.7 agrees with them); the
**Stage 0 seed Nix 2.31.1 is the outlier** — it computes a divergent flake-input
narHash for the identical source tree. Same rev + same lastModified + different
narHash ⇒ a Nix-version narHash-*computation* difference, not a content change.

**Timeline.** The flake.locks date to ~2026-05-15. Plan 160 cut Stage 0 over to
a pinned **`nix-2.31.1`** seed on 2026-06-05
(`crates/mvm-build/src/stage0.rs:61` `NIX_SEED_VERSION = "2.31.1"`, plus the
per-arch URLs + SHA-256). From that cutover onward, the seed Nix's narHash
diverges from the (correct) locks, so **every fresh builder-VM build on `main`
has been broken since ~2026-06-05**, masked by warm caches.

This is **not** caused by any in-flight bridge/Plan-209 work — it's pre-existing
on `main` and touches no bridge code.

## Affected

All four flake.locks pin the same nixpkgs rev with the same `Ti+ZBvW6` narHash:
`nix/flake.lock`, `nix/images/builder-vm/flake.lock`,
`nix/images/runtime-overlay/flake.lock`, `nix/images/default-tenant/flake.lock`.
(The `builder-vm` and other locks also carry a `microvm` input whose narHash was
locked by the same older Nix — see open question 3.)

## Options

1. **Bump the Stage 0 seed Nix off 2.31.1 to a version whose narHash matches the
   locks (e.g., 2.34.7, verified above).** Update `stage0.rs`
   `NIX_SEED_VERSION` + both per-arch URLs + SHA-256 pins (ADR-071 trust anchor)
   + the stage0 tests that assert the version. **This is the likely-correct
   fix** — it aligns the seed with the (correct) locks and modern Nix.
   - Pro: locks, CI, and modern Nix already agree on `Ti+ZBvW6`; only the seed is
     wrong. Built artifacts are unchanged (same nixpkgs rev), so dm-verity
     roothashes (claim 3) and image-hash manifests (claim 6) are unaffected.
   - Con: it's a bootstrap **trust-anchor** change (new pinned SHA-256s); needs
     the right tarball hashes for both arches and a clean-build verification.
2. **Re-lock the flakes with Nix 2.31.1 (so the locks carry `hOlf/RVFs9`).**
   **Rejected** — it makes the locks match the anomalous seed but mismatch
   modern Nix 2.34.7, CI's Nix, and anyone else's toolchain; it spreads the bug
   instead of fixing it.
3. **Revert Stage 0 to the pre-Plan-160 bootstrap.** Not viable — Plan 160
   deliberately removed the Alpine/apk path; the nix-seed is the only Stage 0
   path now.

## Open questions (the decision)

1. **Which Nix version do we bump the seed to?** 2.34.7 is verified to match the
   locks and is a real upstream release; is that the target, or the latest
   stable at fix time (confirm its narHash matches the locks before pinning)?
2. **Is 2.31.1's divergence a known upstream Nix bug** (so *any* 2.31.x seed is
   unsafe), or specific to 2.31.1? Worth a quick upstream check so we pick a
   version on the right side of the fix.
3. **Does the *in-builder runtime* Nix also diverge?** The seed Nix builds the
   builder-VM image; the resulting builder VM then runs *its own* Nix (from the
   pinned nixpkgs `nixos-25.11`, rev `8fd9daa3`) for subsequent in-VM builds
   (dev-image / default-microvm). If that runtime Nix is also 2.31.x, those
   later builds would diverge on *their* locks too — meaning bumping only the
   seed is insufficient and we'd also need to bump the nixpkgs pin or override
   the in-image Nix package. **Needs verification** (what Nix does rev
   `8fd9daa3` ship, and does it compute `Ti+ZBvW6` or `hOlf/RVFs9`?).
4. **Regression gate?** Should CI assert the Stage 0 seed Nix and the committed
   flake.locks agree on narHash (a cheap check that would have caught this at the
   Plan 160 cutover), so a future seed bump can't silently break fresh installs?

## Verification plan (once a direction is chosen)

On the Hetzner x86_64 KVM box (or any clean Linux KVM host): build `mvmctl` with
the bumped seed, **clear `~/.cache/mvm/builder-vm/`**, run
`mvmctl machine run --image alpine -- echo hi`, and confirm the builder-VM image
builds from scratch (no narHash error) and the workload boots. Cross-check that a
built artifact's hash is unchanged vs. a warm-cache build (claims 3/6).


## Consolidated from ADR-106 — The Phase-A / Phase-B build boundary — in-process rootfs materialization on the host

- Status: Proposed
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-050 (supersedes its **mechanism**, preserves its **guarantee**),
  ADR-002 (microVM security posture — claim 3, claim 7, claim 11),
  ADR-046 / ADR-013 (no host tools / no host Nix),
  ADR-093 (builder auto-fallback), ADR-107 (virtiofs-root integrity — future),
  Plan 221 (this decision is its B0 deliverable), Plan 214 (HVF VMM),
  the `#1388` seam (`mvm_hostd::plan_admission::admit_and_start`).

## Context

"Build a microVM" is routinely treated as one indivisible act that must happen
inside the builder VM. It is not. It is two phases with completely different
security and portability profiles, and conflating them is what forces the
builder VM onto code paths that do not need it — including the last mandatory
subprocess on the local **run** path (`mkfs.ext4 + cp + veritysetup` shelled
inside a booted builder VM).

**Phase A — Nix evaluation + build.** Fetch sources, evaluate derivations,
compile, and *execute build logic* (nixpkgs, third-party flakes, `uv pip
install`, `pip-audit`). Produces a Nix closure / unpacked layer set. This phase
runs semi-untrusted, attacker-influenced code.

**Phase B — rootfs materialization.** Assemble an already-resolved closure /
unpacked OCI tree into an ext4 image + dm-verity Merkle tree + roothash. This
phase runs **no untrusted code** — it is deterministic byte-assembly over a
fixed input tree.

ADR-050 mandated materialize + verity *inside the builder VM* because that is
where `veritysetup` and `mkfs.ext4` live and where the result is deterministic.
But ADR-050's **security property is the roothash**, not the *location* the
roothash is computed in. Once a pure-Rust, memory-safe writer can produce a
byte-identical ext4 + verity tree, the location constraint is incidental.

Two forces make the split worth formalizing now:

1. **Portability.** macOS (and a hypothetical Windows host) has no `mkfs.ext4` /
   `veritysetup`. Phase B done in-process in pure Rust works on every host for
   free; shelling host tools never could.
2. **Operational fragility.** Nearly all builder-VM pain — Stage 0 nix
   fetcher-cache corruption, degraded-store `dev up` loops, cold-cache
   `BadActivate`, stale-supervisor stdio — is Phase-B *plumbing*, not Phase A.
   In-process materialize deletes that surface without touching the Nix
   boundary.

The tension: moving Phase B onto the host **removes the VM sandbox that
currently isolates materialize**. Materialize consumes attacker-influenced OCI
trees and its output feeds dm-verity (claim 3), so the writer becomes a new
host-side trusted-input surface. The host is nominally trusted (ADR-002 lists
"malicious host" out of scope), but that governs what we *defend*, not an
invitation to *widen* the host attack surface carelessly.

## Decision

Draw and enforce the **Phase-A / Phase-B boundary** as the rule that decides
what may run on the host versus what must stay in a VM:

**Phase B (materialize) MAY run in-process on the host** — and becomes the
default for the local run path — subject to the three preservation invariants
and the trusted-input posture below.

**Phase A (Nix evaluation + build execution) MUST stay in a VM we launched.**
Three independent reasons, any one sufficient:

- **Portability / physics.** On macOS there is no native path to Linux closures;
  a Linux userland is mandatory.
- **Determinism (ADR-046/013).** Host Nix is never used, even when present, so
  the same `mvmctl` yields byte-identical artifacts on every host. Building on
  the host reintroduces the host-variance this invariant exists to kill, and
  is where claim 7's reproducibility double-build lives.
- **Supply-chain blast radius (claim 11).** Phase A executes untrusted build
  input. The VM is what stops a poisoned nixpkgs / flake / app-dep package from
  reaching the key-holding host at build time. App-deps install *in a builder
  microVM, never on host* — this ADR makes that a boundary rule, not a habit.

**The deciding invariant, stated once:** *work that executes attacker-influenced
code stays in a VM; work that only assembles bytes from an already-resolved,
trusted-input tree may run in-process on the host — provided it is memory-safe
and its input surface is fuzzed.*

### Preservation invariants (Phase B in-process must hold all three)

1. **Claim 3 — integrity at boot.** The pure path emits a dm-verity roothash
   proving the rootfs bytes match a known-good hash — a pure-Rust SHA-256 Merkle
   tree replacing `veritysetup`. CI byte-diffs the hash tree against real
   `veritysetup` (`ext4-real-mount` lane).
2. **Claim 8 — signed-plan admission.** Unchanged. `admit_and_start` gates every
   boot regardless of how the rootfs was materialized.
3. **Determinism / reproducibility.** Fixed block size, zero verity salt, fixed
   inode order, zeroed timestamps, fixed allocation → same input tree yields a
   byte-identical rootfs and roothash.

### Trusted-input-surface posture (the price of moving off the VM)

Removing the builder-VM sandbox around materialize is only acceptable because:

- The writer is `#![forbid(unsafe_code)]` (`crates/mvm-ext4`): worst case is a
  returned error or a caught panic, **never host memory corruption**. The
  105-`unsafe`-block `am-fs-ext4` / `fs_ext4` crate is a **dev-only differential
  oracle**, never a runtime dependency.
- The writer's surface is **minimal**: create-dir / create-file / extents /
  symlink / perms (+ xattr only if a real OCI image needs it — open, see
  Consequences). No journaling, htree, casefold, ACL, inline-data, or fsck in
  the trust base.
- The writer's input surface **is** fuzzed and adversarially tested before the
  run path is flipped to the pure default. `build_image` carries a `cargo-fuzz`
  target (sibling to the OCI `unpack_layer` fuzz, wired into the `security.yml`
  fuzz lane) and a deterministic adversarial-tree suite (deep / huge /
  symlink-loop / malformed) mounted through the independent reader. That suite
  hardened the writer's contract — a malformed or impossible tree now returns
  `Err` (`NotADirectory`, `DuplicatePath`, tightened `BadPath`) rather than
  emitting an unreachable inode. A clean `deny.toml` over the writer's (tiny)
  dependency set completes the posture. **Wiring the run path to the pure path
  before this coverage is on `main` is out of order.**

## Consequences

- **ADR-050 is superseded in mechanism, preserved in guarantee.** Materialize +
  verity move from the builder VM to in-process pure Rust; the roothash +
  determinism + no-host-tools guarantees are unchanged. A vendored pure-Rust
  crate is *not a host tool*, so this does not weaken ADR-046/013.
- **No claim regression, one claim arguably strengthened.** Claims 3/7/8/11 all
  hold. We now own the verity computation in audited, memory-safe Rust instead
  of trusting a shelled `veritysetup`, which is a modest claim-3 improvement.
- **The trust-base foundation has landed.** The pure-Rust ext4 writer, the
  pure-Rust dm-verity Merkle roothash + hash tree (byte-diffed against real
  `veritysetup` in CI), the real-kernel loop-mount lane, the fuzz target, and the
  adversarial-tree suite are all on `main`. What remains is integration
  (`materialize_ext4_pure` OCI-dir walk), run-path wiring, and the default flip.
- **The local run path can become fully in-process, zero-shell** once the run
  path wires `LocalBackend::run_machine` to `materialize_ext4_pure` with an
  ADR-093-style auto-fallback to the builder VM on pure-path failure.
- **A new host-side trusted-input surface exists** and is gated by the posture
  above. This is a real, accepted cost; the `#![forbid(unsafe_code)]` floor
  bounds it to availability failures, not memory-safety failures.
- **Open — xattrs.** The current `Node` model (`Dir`/`File`/`Symlink` + `mode`)
  has no xattr channel. If any target OCI image carries capabilities/xattrs the
  writer silently drops them today. Resolve before the default flip (either prove
  no target needs them, or add a faithful xattr path with its own oracle).
- **Open — large images.** The writer currently caps at a single 128 MiB block
  group (over-cap input returns `Err(TooLarge)`). Multi-block-group support is a
  mechanical follow-up; until it lands, the pure path must fall back to the
  builder VM for larger rootfs.
- **Windows, if ever a target, gets Phase B for free** — no host `mkfs` needed.

## Alternatives considered

- **Full host build, including Phase A.** Rejected. Violates the determinism
  invariant (ADR-046/013), hands claim 11's threat model a host-level
  code-execution path, and is impossible on macOS anyway. The out-of-scope
  "malicious host" caveat is not license to widen the surface.
- **Keep materialize in the builder VM (status quo, ADR-050 as-is).** Rejected as
  the default — it keeps the last mandatory subprocess on the run path and all
  its plumbing fragility, and is unavailable where the host lacks `mkfs`. Retained
  only as the auto-fallback when the pure path can't handle an input (e.g. an
  over-cap image before multi-block-group lands).
- **Adopt `am-fs-ext4` / `ext4_rs` as the runtime writer.** Rejected. `ext4_rs`
  needs nightly and can't mkfs from scratch; `am-fs-ext4` carries ~105 `unsafe`
  blocks and ~80% unused attack surface for a read-only rootfs — unacceptable in
  the host trust base. Both survive as dev-only test oracles.
- **Virtiofs root (Option A), deleting materialize entirely.** The end state
  (supermachine / Plan 214), but claim 3 for a virtiofs dir needs a new integrity
  mechanism — deferred to ADR-107. Option B ships the "never shell out" run path
  without waiting on that decision.

## Scope / sequencing (Plan 221 Option B)

**Landed on `main`:** the `mvm-ext4` pure-Rust writer; pure-Rust dm-verity
roothash + hash tree with the `veritysetup` CI differential; the real-kernel
loop-mount lane; the `build_image` fuzz target; and the adversarial-tree
regression suite (which hardened the writer's error contract).

**In flight:** `materialize_ext4_pure` — the OCI-dir walk that turns an unpacked
tree into the writer's node set, behind a `pure-mkfs` feature.

**Remaining:** wire the run path (`LocalBackend::run_machine` → pure materialize,
builder-VM fallback); resolve the xattr and multi-block-group open items; flip
the pure path to the run-path default and update the CLAUDE.md "never on the
host — ADR-050" note to cite this ADR.

Note the order things actually landed diverged from a strict "ADR first" plan:
the writer, verity, and fuzz coverage merged before this record. That is fine for
a foundation with no consumers yet — but the **default flip** must not precede
this ADR's ratification and the full trusted-input posture being green on `main`.

Phase A stays in the VM indefinitely; this ADR does not touch the Nix-build
boundary. Option A (virtiofs root) continues under ADR-107.


## Consolidated from ADR-107 — Integrity model for a virtiofs root filesystem

- Status: Accepted
- Date: 2026-07-04
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — **claim 3**, threat model, tier
  matrix), ADR-106 (in-process rootfs materialization — Option B, block+verity),
  ADR-050 (materialize + verity; ADR-106 supersedes its mechanism, preserves its
  guarantee), ADR-051 (runtime overlay sealed like the rootfs), Plan 214
  (HVF VMM), Plan 221 (this is its Option A / A0 deliverable),
  Plan 223 (virtiofs-root implementation, gated on this ADR).

## Context

Plan 221 Option A proposes booting a guest with the **unpacked OCI directory as
a virtiofs root** — no ext4, no `mkfs`, no image at all. The host serves files
to the guest on demand over virtiofs. This is the supermachine model and the
Plan-214 hvf-HVF end state, and it deletes the last piece of
image-materialization on the virtiofs-capable run path (Option B's in-process
ext4 + dm-verity, ADR-106).

It runs straight into **claim 3** ("a tampered rootfs ext4 fails to boot"):

> dm-verity over the read-only ext4 lower layer; root hash on the (signed)
> kernel cmdline; `mvm-verity-init` mounts it; the guest kernel panics before
> userspace on a flipped data block.

dm-verity is **block-device-specific**. A virtiofs root is a host *directory*,
not a block device — there is no fixed block layout to build a Merkle tree over,
and the guest kernel cannot dm-verity a filesystem it does not own the blocks
of. So Option A cannot satisfy claim 3 by its current mechanism, and claim 3 is
a **numbered security claim**. This ADR decides what integrity a virtiofs root
provides, and therefore whether Option A can carry prod workloads.

### What does claim 3 actually buy, given the threat model?

ADR-002 puts a **trusted host** at the center: "mvmctl trusts the host with the
hypervisor and private build keys… a malicious host is out of scope." So claim 3
is **not** defending against a host that tampers with the rootfs at serve time.
What it *does* buy, on top of the trusted host:

1. **End-to-end binding of rootfs content to the signed plan.** The roothash
   lives on the signed `ExecutionPlan` cmdline. The guest kernel enforces every
   block against it. So the *bytes the guest actually executes* are
   cryptographically tied to what was admitted — not to whatever happens to be
   on disk at boot.
2. **Detection of at-rest tampering / corruption between admit and boot.** A
   flipped bit in `rootfs.ext4` — cache corruption, a stray writer, a swapped
   file across reboots, a tampered published `.mvm` artifact or registry layer —
   is caught at read time, not trusted blindly.
3. **A guest-side enforcement point** independent of the host userspace that
   assembled the image.

For a virtiofs root, the content's authenticity is instead established **at pull
/ unpack time**: `mvm-oci` verifies every layer's sha256 against the manifest,
and `--prod` additionally cosign-verifies the resolved manifest digest before
the layers are unpacked (ADR-002 claim 14). After that, the *trusted host*
serves those exact files read-only. The gap versus claim 3 is precisely
properties (1)–(3): there is **no guest-enforced, plan-bound, continuous
re-verification** of the served files. A corruption or substitution of the
unpacked tree *after* unpack and *before/while* the guest reads it is not caught
by the guest — it rests entirely on the trusted-host axiom.

### The candidate mechanisms

- **(i) Per-file fs-verity.** Enable fs-verity on each file in the host tree and
  have the guest verify each file's Merkle root against a signed manifest.
  Problems: fs-verity is a **host-kernel** feature that virtiofs does not
  transparently propagate to the guest; the guest would need its own enforcement
  layer; it requires the host filesystem to support fs-verity (ext4/f2fs/btrfs
  with the feature enabled); and it re-introduces a per-file Merkle build that is
  most of the cost Option A set out to remove.
- **(ii) Signed content manifest + guest-side verification.** Ship a manifest
  (path → sha256 for every file), signed and bound to the plan; the guest
  verifies files against it — either a full scan at mount (expensive: rehash the
  whole tree in-guest on every boot) or lazily per-read via a FUSE/overlay shim
  (complex: a new in-guest verification component on the read path). This is
  essentially re-implementing dm-verity at the file layer inside the guest.
- **(iii) Tiered posture.** Treat virtiofs-root as a **dev/local-tier** boot
  mechanism whose integrity contract is *unpack-time verification + read-only
  virtiofs + trusted host* — explicitly weaker than claim 3 — and keep **prod on
  Option B** (block + ext4 + dm-verity), where claim 3 holds unchanged. This
  mirrors the existing per-tier matrix, where dev/test tiers already carry
  relaxed guarantees (e.g. the QEMU/microvm_nix builder deliberately omits
  claim-10 egress enforcement as a Tier-2 dev/test backend).

## Decision

**Adopt (iii): virtiofs-root is a dev/local-tier mechanism; prod stays on
Option B.** Concretely:

1. **virtiofs-root does not witness claim 3.** Its integrity contract is a
   distinct, explicitly weaker property:

   > **Virtiofs-root integrity (dev tier).** The rootfs content is verified at
   > unpack time (per-layer sha256 against the manifest; cosign on the manifest
   > digest when a registry policy demands it), then served **read-only** from a
   > trusted host over virtiofs. There is no guest-enforced, plan-bound
   > re-verification of served files; integrity after unpack rests on the
   > trusted-host axiom (ADR-002 threat model).

   This is recorded as a documented posture, **not** promoted into ADR-002's
   numbered claim-3 prose. The claims catalog gains a note that claim 3's
   witness (dm-verity) applies to the **block+ext4** backends
   (Firecracker + Option B), and that the virtiofs-root dev path carries the
   weaker contract above.

2. **Prod refuses virtiofs-root.** A sealed / `--prod` workload continues to
   require Option B: in-process (or builder-VM) ext4 + dm-verity + roothash on
   the signed cmdline. The run path selects virtiofs-root **only** for the
   dev/local tier on virtiofs-capable backends (HVF, libkrun, Vz);
   `--prod` and any sealed-image admission path fall back to Option B, on every
   backend. **Firecracker always uses Option B** (it has no virtiofs root
   device; ADR-106).

3. **A stronger path is left open but deferred.** If prod-on-virtiofs is ever
   required, candidate (ii) — a plan-bound **signed content manifest** with
   guest-side verification — is the promotion path to a claim-3-equivalent
   guarantee, and would get its own ADR. Candidate (i) (fs-verity) is recorded
   as considered-and-not-chosen for the reasons above. Nothing here forecloses
   them; this ADR only declines to block Option A's dev-tier value on solving
   prod-grade virtiofs integrity first.

### Why this is the right call

- **It respects the threat model rather than overclaiming.** The trusted host
  already serves the guest's memory, devices, and vsock; a trusted host serving
  a read-only, unpack-verified directory adds no new *host* trust. What it drops
  versus claim 3 is defense-in-depth against **at-rest tampering between admit
  and boot** — a real property, but one whose value is concentrated in the
  **prod** distribution story (published artifacts, registry layers, long-lived
  caches), exactly where we keep Option B.
- **It keeps Option A's whole point.** Option A exists to delete
  materialization on the fast dev/local loop. Gating it behind a full guest-side
  file-verification subsystem would erase that win. The tiered decision ships the
  dev-loop speedup now without weakening any *numbered* prod guarantee.
- **It matches the existing architecture.** ADR-002 already grades guarantees by
  tier; this is one more per-tier distinction, made explicit and CI-notable
  rather than implicit.

## Consequences

- **Claim 3 is unchanged for prod and for Firecracker.** No numbered claim is
  weakened. The claims catalog gains a scoping note (block+ext4 backends witness
  claim 3; virtiofs-root dev path carries the weaker contract).
- **The run path grows a tier gate.** Selecting virtiofs-root requires: a
  virtiofs-capable backend, the dev/local tier, and a non-sealed / non-`--prod`
  workload. Everything else routes to Option B. This gate is testable and is a
  named deliverable of Plan 223.
- **Unpack-time verification becomes load-bearing for the virtiofs path.** The
  per-layer sha256 check in `mvm-oci` (and cosign for policy-gated pulls) is the
  *only* content-authenticity step for a virtiofs boot, so it must run before the
  tree is exposed to the guest and must fail closed. (It already does for the
  materialize path; the virtiofs path must not bypass it.)
- **Documentation debt is explicit, not hidden.** A reader of ADR-002 will find
  claim 3 scoped to block+ext4 and a pointer to this ADR for the virtiofs-root
  posture, so no one mistakes a dev-tier virtiofs boot for a claim-3 boot.

## Alternatives considered

- **Make virtiofs-root witness claim 3 via a signed manifest now (ii).** Correct
  end state for prod-on-virtiofs, but it re-adds a full guest-side verification
  component (mount-time rescan or per-read FUSE shim) that negates Option A's
  performance rationale and is a large surface to get right. Deferred, not
  rejected.
- **fs-verity (i).** Host-fs-dependent, does not cross the virtiofs boundary to
  the guest transparently, and re-introduces per-file Merkle builds. Rejected as
  the primary mechanism.
- **Ship virtiofs-root for all tiers and quietly relax claim 3.** Rejected:
  claim 3 is CI-enforced and load-bearing for the prod distribution story;
  silently weakening it to cover a dev optimization is exactly the overclaiming
  ADR-002's discipline exists to prevent.
- **Never ship virtiofs-root; keep Option B everywhere.** Rejected as the
  default: it forfeits the dev-loop speedup and the Plan-214 end state for a
  prod property the dev tier does not need. Option B remains the prod path.
