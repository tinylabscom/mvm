# Contract — portable application composition

Status: release-candidate design, **not** an accepted or published feature.
See `mvm-packs` ADRs 004–006. This contract replaces the fixed-default-base,
single-application assumptions of the first source-only candidate without
changing any published pack or `mvm.pack-spec/v1` semantics.

## What is independently reusable

A portable **application pack** carries signed, digest-bound application bytes,
declared paths, immutable identity, requirements, policy and optional
entrypoint. It contains neither a kernel nor an independently bootable rootfs.
A **runtime/tool pack** carries separately signed software and policy; a
runtime layer has one publisher-authenticated registry descriptor binding its
external archive digest and size, **not** a second Ed25519 archive signer.
Neither kind can boot alone. Existing schema-2 application descriptors still
point at complete, independently signed `.mvmpkg` boot bundles, including the
published Claude versions; legacy policy-only versions remain immutable and
non-runnable. Keep both the existing v1 release reader and v1 authoring while
the new format reaches parity. Unknown versions fail closed.

The Linux **base** supplies the kernel and a generic, verifiable filesystem
composition source; `mvm` supplies the separately signed complete guest
runtime/overlay/initramfs. An app must work unchanged with either our default
or a compatible user-built base. `mvm-images` publishes one optional default
base on its own cadence, never per-app images or mvm runtime. Its unpublished
schema-3 signed `rootfs.tar.gz` is a composition source, not a second rootfs
or runtime role. The last known signed set, v0.2.4, lacks that tar; do not
advance `images.lock` or publish a set without the released-consumer gates and
specific authorization.

## Selection, compatibility and authority

`mvmctl run agent/claude` stays a single command with a fast compatible
default. An explicitly ordered composition with `--base` is also a single
command. The selected base, not a fixed compiled-in default, is an input to
**one** resolver, assembler, cache and admission path. Do not retry with the
default when a selected base is incompatible or untrusted.

A bounded, versioned selected-base record must bind its trust class,
architecture, boot protocol, kernel digest/size, composition filesystem
digest/size, base-image contract, filesystem ABI, minimum kernel features,
libc/loader compatibility, capability set, and independently signed guest
runtime evidence. Check the actual bytes and compatibility of all selected
roles. A development record may bind a user-built base with measured local
evidence; it must be marked local and cannot be relabelled, indexed or
admitted in production. Production requires independently trusted signed
base and runtime evidence, fresh revocations and a protected verifier; a
host-signed build is never official publisher authority. An unsigned or
incompatible production base is rejected with no fallback. Do not accept
unsupported special files, symlink escapes or an inconsistent base ext4/tar
pair merely because their declared digests are well formed.

Schema-8+ host-signed local bundles that can be installed or launched later
require explicit operator enrollment under mvm PR #5301. Same-host signing
alone is not operator enrollment or release trust. For one-command first use,
the chosen development path is a separate, one-use, Dev-only transient
admission proof (#5341), bound to the exact host-signed archive and its
reverified base. It never enters the installed registry or publisher trust
store, and a repeat run must mint a new proof after rechecking cached bytes.
The current source candidate stages a host-verified archive in an
invocation-private directory, carries one Dev admission attempt, and
reverifies it before boot. It does not put that archive in the installed
registry; the composition cache holds bytes, not launch authority. This
is not accepted until cold/repeat CLI guest output and refusal tests pass.
Neither route grants production/export authority; the separately signed
and fully bound production composition remains the long-term direction.

`mvm.pack-spec/v2` currently parses one local application, ordered `runtime/*`
requests, `/srv/app` copies, literal argv and resources. Its `[production]`
table expresses intent only: it neither signs nor authorizes a release.
The development-only CLI candidate accepts `mvmctl run --compose PACK.TOML`
with the signed default or an explicit local manifest/kernel/tar selection.
The local selection carries distinct schema-9 same-host proof, not canonical
publisher authority. The separate `base-compatibility/v1` descriptor verifier
binds exact base bytes and compares component requirements, but no signed
production descriptor is published or acquired by this CLI path. A new
versioned multi-component request must connect the existing v3 signed graph,
verified schema-3 application/schema-4 runtime and tool inputs, and entrypoint
choice without changing the old v2 recipe's meaning. An unpinned production
input, an unknown requirement, or a production request without separately
trusted base evidence fails closed.

`mvm.composed-run/v1` is the proposed one-file v3 invocation envelope: it
requires a Linux target, the `mvm.pack-spec/v3` ordered graph, and an
`mvm.entrypoint-request/v1` command selection. Base selection and host grants
are separate launch inputs; this authored envelope grants neither. Unknown
fields, including implicit service startup, are refused. The contract parses
and validates the envelope, but `mvmctl run --compose` does not consume it yet.

## Resolution, filesystem and cache

Resolve an **explicit ordered graph** of publisher-authenticated,
exact-version-and-manifest-digest-pinned components. Resolve dependency pins
before assembly; refuse duplicates, cycles, missing trust, revoked inputs
and arch/ABI/libc/kernel/capability mismatches. Authenticate descriptor
signatures and snapshot every external archive and signed policy file against
the descriptor's digest/size before unpacking. Check fresh, rollback-resistant
revocation feeds on every run, including cache hits.

Stage the selected base first, then locked runtime/tool components and
applications in their explicit order. Reject collisions, including a leaf
against a base directory, permission or ownership changes, whiteouts and
overlaps with host-owned guest paths. No component silently replaces a file,
mode, symlink or parent. No guest install script, boot-time package fetch or
implicit service start. Each application keeps its commands available by
name, but only the selected entrypoint executes.

Build and measure one ext4/verity workload **before first boot** and cache it.
The filesystem cache key is a versioned hash of the exact selected base
composition bytes, ordered component archive digests and declared filesystem
ABI, and assembler version. Do not key those bytes on the effective policy,
host grants or command if they are not written into the filesystem. If any
such data *is* embedded in the filesystem, it is explicitly hashed as an
assembly input. The v2 `run --compose` candidate bakes its literal authored
argv as a sealed `/etc/mvm/entrypoint` script, so its script digest belongs
in the filesystem key; changing that command rebuilds the filesystem.
Reverify cached bytes and their verity binding before use;
the cache is not a trust decision. First-run assembly, repeat boot, transfer
and retained disk must be measured separately. Reuse the candidate's
host-signed local-bundle/schema-8 path, not another composer or cache.

Entrypoint precedence is: **runtime override > user-defined workload/config
entrypoint > last application in explicit order declaring an entrypoint**.
“Last wins” applies only to command selection. The selected command is
separately admitted under the selected security profile and host-authorized
grants, even for production overrides. Record and audit the actual command
executed, not merely a declared default. Signed component policy requests
cannot grant themselves network, secrets or shares: denies win, ceilings
narrow, and effective requests intersect host grants. Resolve and test policy
in one authoritative path.

## Launch and export

Bind selected base identity and trust class, signed guest runtime,
ordered component manifest/payload/policy hashes, measured output,
effective policy, grants and selected *actual* command to the existing
signed bundle and signed execution plan. Host admission rechecks input
publisher trust, freshness and rollback of revocations, measurements,
effective policy and grants **immediately before launch**, even on a cache
hit. Missing or conflicting evidence refuses launch. Local composition is
always marked development-only.

For production, builder-vm materializes candidates without release
credentials. A separate protected pipeline independently verifies the
frozen graph and selected boot closure, checks the tested output and command,
and signs one self-contained `.mvmpkg` carrying kernel, initramfs, composed
ext4/verity, signed runtime evidence and full input provenance. The recipient
verifies it independently and applies current revocation and grant rules.
Neither a local receipt nor a host signature can stand in for protected
publisher signing. PR-only synthetic signing is allowed for tests but does
not enroll a production trust root or authorize publication. The prospective
`mvmctl pack publish ./my-pack` is a separate protected-publishing slice,
not an alias for local export.

There is **no guest NIC, TAP/TUN, NAT, SSH, CNI, SLIRP or fallback**. Permitted
networking uses only host-mediated, authenticated FlowMux/vsock.

## Approved warm custody direction (implementation not evidenced)

The existing persistent-machine start sets `warm_pool_size(0)`; the factory
parent refuses both PR-test runtime proof and kernel descriptor custody.
Neither changing that value nor trusting a signed cache index makes a named
composition safe to claim. The current `TrustedSnapshotBackend` and
`TrustedSnapshotService` already separate immutable publication from claim,
but the default backend refuses, APFS is opt-in and needs a privileged helper,
and `materialize` alone does not hand an immutable read view to the VMM.
These are implementation boundaries, not a warm capability claim.

The service now reserves each ID before staging, issues a fresh generation
per sealed publication, and holds a per-ID claim lease through materialization
so a concurrent removal cannot reclaim its backend read view. Failed staging
or cleanup leaves the ID reserved rather than handing it to another publisher.
After a failed removal, claims stay blocked and only the owning handle can
retry cleanup.
These in-process lifecycle guards do not themselves seal bytes, survive an
owner crash, or authorize a VM to boot from a writable materialization.

Extend that **one** publication/claim contract rather than add a composer
authority or accept a mutable path as proof. Before any claim, a resident owner
must authenticate and publish the exact selected kernel, rootfs, runtime and
factory-parent bytes under a platform-enforced immutable read view, with
their digest, provenance, backend boot shape and compatibility key bound to
the parent. The parent holds no tenant plan, secrets, writable volumes or
egress destinations. A Linux provider needs an evidenced sealed descriptor
or equivalent kernel-backed immutability; macOS needs the authenticated APFS
helper and live mount/tamper witnesses. Unsupported hosts refuse warm
publication instead of quietly claiming from an unsealed pool.

Each child still needs fresh revocation, policy, grant and one-use admission
checks **before** the admitted plan and child-owned effects can reach the
guest. A claim consumes a generation-checked parent only when its immutable
closure matches that plan; restart, expired evidence, changed inputs and an
unavailable owner refuse rather than treating a cache hit as authorization.
The VMM must map the verified immutable read view, not a newly writable
materialization that needs claim-time rehashing. Bound resident parents and
leases by the existing host budget, reclaim them only after the last child
releases custody, and test cancellation and owner crash recovery.

The simpler alternatives do not meet this contract: per-start restaging and
rehashing stay cold, while a host-signature/HMAC sidecar cannot seal the bytes
it names. Before enabling either backend, review the owner/descriptor API and
measure cold and warm *readiness including admission*, plus first-use
construction separately. The required thresholds remain <300 ms cold and
<50 ms warm; neither is evidenced by the current CLI timings.

A diagnostic `MVM_SPAN_TIMINGS=json` run of the native arm64 HVF
`release-witness` CLI measured 9.28 s for a named start after preparation:
`prepare_archive` took 0.86 s even on an authenticated cache hit,
invocation-private `stage_with` took 2.16 s, `consume` 0.44 s,
`start_persistent_oci_machine` 4.63 s (including 0.45 s of plan admission),
and retaining boot custody after launch 0.44 s. These are nested spans, not
additive totals. They show that moving the cache lookup ahead of filesystem
staging is useful but cannot by itself meet either launch threshold; private
staging, persistent boot preparation and admission remain on the hot path. A
second native arm64 HVF run measured 8.94 s including 3.62 s for persistent
boot preparation (2.95 s self) and 0.99 s for legacy boot completion (0.93 s
self). This is diagnostic timing, not an arm64 Linux/KVM witness.

## Acceptance and currently missing evidence

The staged v2 candidate authenticates runtime descriptors/policies and a
signed-base composition tar, rejects path collisions, and creates a
host-signed local development bundle for a default or explicitly selected
local base. A verified host-signed filesystem may be reused across command
choices only when no command bytes are baked into it and its ordered
filesystem identity is unchanged; current trust,
revocations and grants must still be readmitted. Typed v3 component readers,
an exact-pin acquisition helper, ordered staging and measured filesystem-only
lock, a separately signed base-descriptor verifier, and an authenticated
policy-snapshot adapter exist. The filesystem lock grants no command or host
authority; v3 is not wired into the CLI invocation, admission or production
export.
Direct-QEMU synthetic boots read `COMPOSED_GUEST_VALUE=print('ready')`, but
they are not CLI admission evidence. On PR #5326 at `4d9e5d21ad`, the
`release-witness` CLI and same-head signed PR base/runtime artifacts from
Actions run `43172747569` produced that value through `mvmctl run --compose`
on x86_64 Firecracker: 11.19 s on a cold composition, 8.52 s on an authenticated
cache hit. Both exited zero without enrolling a publisher; neither meets the
<300 ms cold or <50 ms warm launch target. At `4b95627ef9`, the same-head
PR-only signed CLI, x86_64 base and guest runtime from Actions run
`43284492364` also produced `COMPOSED_GUEST_VALUE=print('ready')` through
`machine create packed-fixed --pack ...`, `machine start packed-fixed` and
`machine logs packed-fixed` on Firecracker. Create took 4.70 s, the first start
11.03 s and a stop/restart with an authenticated composition cache hit 8.77 s.
These are named-machine guest-output witnesses, not speed acceptance; aarch64
Linux/KVM and immutable warm custody had not yet been witnessed at that commit.
On macOS arm64 HVF, a native `release-witness` CLI with the same PR-signed
aarch64 base and guest runtime assembled a named composition in 3.51 s and
produced `COMPOSED_GUEST_VALUE=ready` through a 9.74 s start and a 9.77 s
stop/restart cache hit. Its CLI was built locally rather than attested by the
PR workflow; this is a native HVF guest-output witness, not Linux arm64/KVM
or launch-speed acceptance.

At `02a5f6ee3c`, a locally cross-built arm64 Linux `release-witness` CLI and
host helpers, hash-checked after transfer, used the same-head PR-signed
aarch64 base and runtime from Actions run `43314770069` on a Raspberry Pi 4
running Linux 6.18.50 with accessible `/dev/kvm` (KVM API version 12).
The CLI created a named machine from the pack and local base in 20 s. Pinned
Firecracker v1.17.0 booted it via `machine start arm-witness` with explicit
`--hypervisor firecracker`; `machine logs` read `COMPOSED_GUEST_VALUE=ready`
after 53 s. Stop and restart produced the same guest value in 53 s; the
repeat Firecracker API log contained no `network-interfaces` request. The
console log is not hash-chained; the CLI is locally built rather than
release-attested. This demonstrates
an arm64 Linux/KVM guest read, **not** immutable warm custody, launch-speed
acceptance, or a production release.

Acceptance requires Linux **CLI** one-command default and selected-custom-base
cold/repeat runs, a value actually read from the guest on both runs, a proven
filesystem cache hit, and rejection of tampered, revoked, stale, conflicting
and incompatible inputs. Preserve the direct-VMM checks as additional
evidence. Measure assembly and boot times, transferred and retained bytes;
run formatting, Clippy, invariant/footprint and registry gates. Synthetic
applications avoid Claude redistribution. No compatible published base tar
or released CLI/full-runtime closure yet exists; no CI result alone overrides
that publication prerequisite.
