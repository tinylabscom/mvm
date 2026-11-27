# ADR-054: mvm-images owns the Linux layer; mvm ships the guest runtime

Backing: preview
Validation: none

## Status

Accepted, 2026-10-05. Tracking issue:
[#4100](https://github.com/tinylabscom/mvm/issues/4100).

Amends ADR-004 §Image source in a source checkout (both the builder image and every user-facing image
build from `mvm-images`) and ADR-004's account of how mvm's own Linux binaries
reach a guest. Supersedes the consumer half of
specs/plans/2026-09-29-guest-bins-artifact-decoupling.md (retired; recover from tag specs-archive-2026-11-02). Since
2026-11-27 ([#4839](https://github.com/tinylabscom/mvm/issues/4839)) it also
holds the runtime overlay, OCI root filesystem, guest protocol, distribution
and rootless-runtime decisions that used to be separate records; see "Guest
runtime contracts" below.

This records a decision. This repository's side has landed in source:
`mvmctl` assembles the guest runtime from its own release asset and no longer
reads it from the image set. What has not landed is publication. mvm-images' source
now builds only the Linux layer, with no `mvm` input, and its base root
filesystems declare the base-image contract; but the newest published image set,
`image-set/v0.2.4`, predates that and still lists the retired pieces. Release
evidence and installed-product boot evidence for the new asset are also still
missing; "Where the code is today" below says exactly what
runs now. The design detail lives in
specs/plans/2026-10-05-image-boundary-linux-layer.md (retired; recover from tag specs-archive-2026-11-02).

## Context

Since the image train moved out of this repository (ADR-004 §Image source in a source checkout,
specs/plans/2026-09-16-image-repository-extraction.md (retired; recover from tag specs-archive-2026-11-02)), `mvm-images` has
built two different kinds of thing:

1. **The Linux layer**: kernels, the base `default-tenant` and
   `rootless-tenant` root filesystems, the builder VM image, and the Stage 0
   seeds. These change when a kernel, a package or a toolchain moves.
2. **mvm's guest runtime**: the guest agent and its helpers, the universal
   initramfs, the runtime overlay, the glibc and musl SDK sidecars,
   `mvm-setpriv`, and `mkGuest`'s `/init`. `mvm-images` compiles these from
   mvm's source through an `mvm` flake input, so they change whenever mvm's
   guest code does.

The second kind turned every guest change in mvm into an image event, and the
cost was measured:

- The merge queue's guest-image-boot lane built the image pair from an
  `mvm-images` checkout in about 31 minutes, on Rust-only PRs as well
  (merge-group run 36367678633, measured 2026-09-29).
- The release e2e pair-built the SDK sidecar and the dev image, about 22 and
  39 minutes, until the release lane moved to the pinned set on 2026-10-04.
- Fetch-when-unchanged, which adopts a published member only when the tree's
  source fingerprint matches the one the set recorded, was abandoned for the
  release lane after twelve commits touching the fingerprint inputs landed in
  22 hours (2026-10-02T21:37Z to 2026-10-03T20:31Z). A release-window run
  almost never matched.
- `just release` in `mvm-images` could not finish on a Mac: evaluating the
  aarch64 `mvm` override took about five to six hours.

The obvious remedy, moving the guest-facing Nix library across with the
images, was measured too: since June, 38 of the 58 commits to
`nix/lib/mk-guest.nix` also changed mvm's guest or host crates. Moving or
vendoring `mkGuest` would make most guest work a two-repository change, which
is the cost this decision exists to remove.

## Decision

Three repositories, three owners:

| Repository | Owns | Changes when |
|---|---|---|
| `mvm-images` | Kernels; base `default-tenant` and `rootless-tenant` root filesystems that contain no mvm binaries and no mvm-authored `/init`; the builder VM image; the Stage 0 seeds. Nix-built, reproduced, cosign-signed, published as one image set, with SLSA build provenance. | A kernel, package or toolchain moves. Never as a consequence of an mvm merge. |
| `mvm` | `mvmctl` plus one signed guest-runtime release asset, version-locked to the CLI: the guest-bins archive (guest agent and helpers, the initramfs agent, `mvm-setpriv`, `libmvm_host_services.so` for glibc and musl, the GPU shims, the Python SDK tree). `mvmctl` assembles the runtime overlay, the initramfs and the SDK sidecar from it, or from a source build in a checkout, at boot. | Every CLI release. A guest change is a single-repository change. |
| `mvm-packs` | Packs. Each pack's CI builds its image on the pinned base set, rebuilds it to check reproducibility, signs it and attests it; `mvmctl pull` verifies. | Per pack. |

The rules that follow from the table:

1. **`mvm-images` builds only the Linux layer.** It drops the `mvm` flake
   input, and new work there does not add one. A base root filesystem carries
   no mvm binary and no mvm-authored `/init`. Image sets stay Nix-built,
   reproduced and cosign-signed under the `mvm-images` release workflow
   identity, and gain a build-provenance attestation. `mvm-images` is never
   part of mvm's merge queue: no mvm merge waits on an image build.
2. **mvm ships the guest runtime with each CLI release.** The archive is a
   release asset signed under the CLI release workflow identity, listed in the
   signed checksum manifest and covered by the release's build provenance. A
   downloaded `mvmctl` fetches the archive that matches its own version
   through the CLI-train verifier; a source checkout builds the same pieces
   with the pinned cargo-zigbuild toolchain. `mvmctl` assembles the runtime
   overlay (pure-Rust ext4 plus in-process dm-verity), the initramfs (Rust
   newc cpio) and the SDK sidecar from it. The image-set roles
   `RuntimeOverlay`, `SdkSidecar` and `Initramfs` leave the image-set
   contract.
3. **The initramfs agent is the only guest init.** Every boot, dev boots
   included, starts from the universal initramfs; nothing mvm boots runs
   `mkGuest`'s `/init`. `mvm-setpriv` reaches a workload through the runtime
   overlay and the builder through its boot payload, at builder boot ABI 2.
4. **Packs are the image registry.** A *published* workload image that is not
   one of the base images is a pack in `mvm-packs`, built in CI on the base set
   `crates/mvm-core/images.lock` pins, reproduced, signed and attested. Locally
   authored workload packs may instead use a Nix flake or a pinned Yocto rootfs
   archive as their producer. The `mvm` build path supplies the authenticated
   workload kernel and CLI runtime, checks the imported bytes, seals the final
   rootfs, health-boots it and signs a local archive. A host-signed local pack
   and the producer's declared layer revisions are not a reproduced,
   publisher-attested `mvm-packs` release. Neither producer adds a workload
   role or source dependency to `mvm-images`.
5. **`mkGuest` stays in mvm** as the workload-author library. It is the API a
   workload flake calls, and it co-changes with mvm's crates far more often
   than with anything in `mvm-images` (the 38-of-58 figure above).

`nix/packages/libkrunfw.nix` stays in mvm. It builds the kernel libkrun links
into its own host library for the libkrun backend; it is a host dependency, not
a guest image any image set carries, so rule 1 does not apply to it. Moving it
would make `mvm-images` publish host libraries. Decided by the maintainer on
2026-10-05 (#4015).

## Where the code is today

Text elsewhere in this repository must describe these as current behaviour
and cite #4100 for the direction, never the reverse.

- Every workload backend already boots through the universal initramfs: the
  static agent is PID 1, receives the rootfs and runtime-overlay verity
  parameters in `ActivateEnvironment` over vsock, mounts and checks them,
  mounts the SDK sidecar and volumes, and pivots in-process.
  Dev boots take the same path. `mkGuest` no longer writes a `/init` (#4106):
  its root carries the workload's packages, the fixed identities and the
  `/etc/mvm` markers, and the agent provisions what the shell init used to —
  the egress client and its FlowMux identity, addon DNS, the overlay and proxy
  environment of every workload process, the entrypoint and its exit report.
  The builder boots its payload's `mvm-host-vm-init`, and `mvm-images`' e2e
  boots an `init=` program its smoke image owns.
- A source checkout builds one guest-runtime archive from this tree
  (`mvm_build::guest_runtime::resolve_or_build_source_guest_runtime`), keyed
  by its digest, and assembles all three pieces from it on the host, whether
  or not an `mvm-images` checkout is selected: the runtime overlay with the
  GPU shims and the Python SDK tree
  (`mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime`:
  the pure-Rust ext4 writer and in-process verity), the initramfs from the
  archive's sealed initramfs agent (`mvm_build::initramfs::initramfs_cpio`),
  and the SDK sidecar without a bundled loader or libc
  (`mvm_build::sdk_sidecar::build_sdk_sidecar_from_guest_runtime`). The Wasm
  tier preopens the same overlay files as a directory. A selected checkout
  pair-builds only workload images and kernels.
- In a source checkout every route goes through that one archive and those
  assemblers. Bootstrap resolves the archive once and assembles all four
  pieces from it (`mvm_build::runtime_pieces::assemble_runtime_pieces`); the
  explicit `mvmctl dev runtime-overlay build` and
  `mvmctl dev sdk-sidecar build` assemble the piece they name from it, with
  no `mvm-images` checkout and no builder VM; outside a checkout they assemble
  it from the published guest runtime of the CLI's version. Neither has a
  `--source download`: the image set carries no such piece. A source build
  assembles from its tree in bootstrap whatever
  `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE` says. Each assembled piece records the
  digest of the archive it came from beside its version-keyed files, and
  `mvmctl doctor`'s `guest runtime` line reports, per piece, that archive (and
  whether it is the one this tree builds today, or this release's). The
  archive object is the one digest-keyed cache; the
  pieces keep their version-keyed slots because that is what the launch
  resolvers read, and the sidecar keys reuse on its host-services sources
  rather than the archive digest.
- The builder boot payload (builder boot ABI 1) already hands the builder
  `mvm-host-vm-init` and `mvm-builderd` per boot. `mvm-setpriv` is the one mvm
  binary the builder image still bakes, and `mvm-host-vm-init` runs it from
  `/sbin`.
- Each CLI release builds the guest-bins archive and publishes it as a signed
  asset (#4103): in the cosign sign loop, the signed checksum manifest and
  the build provenance, and `tests/release_assets.rs` still refuses the
  overlay, sidecar and initramfs as image assets of `release.yml`.
  `install.sh` and the deb and rpm packages install it beside `mvmctl`;
  `mvmctl bootstrap` on a release binary and `mvmctl env update` acquire it
  through `mvm_build::runtime_overlay::fetch_cli_release_archive` (digest,
  then signature).
- A release binary's `mvmctl bootstrap` assembles the overlay, the initramfs,
  both sidecars and the OCI guest runtime from that archive through the same
  assemblers a source build uses
  (`mvm_build::runtime_pieces::assemble_release_runtime_pieces`), so the
  overlay's roothash is computed on the host there too. It then records which
  archive it adopted, and `mvmctl doctor` names it. An archive that fails
  verification fails bootstrap, and nothing is adopted. `install.sh` tolerates
  a missing asset only for releases published before the archive existed, and
  a release carrying this code cannot be published without its archive.
- The guest runtime has left the image-set contract (#4105).
  `ImageSetRequirement::current_train()` names only the Linux layer — the
  builder image, both workload kernels and root filesystems, the Stage 0
  kernel on both architectures, and the smoke pack — so a set without an
  overlay, sidecars or initramfs is complete. A set that still lists them,
  such as the pinned `image-set/v0.2.4`, parses: the three roles deserialize,
  in their original wire spelling, as `ImageSetRole::RetiredGuestRuntime`, and
  the sidecars' `source_fingerprint` is parsed and never read. Nothing
  requires, selects or fetches a retired member except a portable bundle's
  boot assets (`BOOT_ASSET_OVERLAY_ROLE`, `BOOT_ASSET_INITRAMFS_ROLE`), which
  authenticate an overlay and initramfs through the set the bundle embeds;
  their replacement is #3928's to decide. An embedded set is no longer
  required to carry an overlay. `IMAGES_CHECKOUT_MARKERS` no longer lists the
  `runtime-overlay` and `initramfs` image definitions, and the pair builds of
  those roles are gone.
- There is no image-set fallback. Every launch resolver — the overlay
  attach, the SDK sidecar attach, the universal initramfs and
  `resolve_cached_runtime_overlay` — reads only the version-keyed slot this
  CLI assembled, and a miss names `mvmctl bootstrap`. A release binary that
  has not bootstrapped since it was installed refuses its first launch with
  that pointer; a release published before the archive existed is a
  different binary and keeps booting its own pinned set's copies.
  Fetch-when-unchanged is deleted with its module and environment variable.
  Two layers are meant here. The launch layer in `mvm-client` acquires nothing
  and refuses an unprepared runtime
  (`launch_refuses_an_unprepared_published_runtime_without_acquiring_it`,
  `required_overlay_cache_miss_names_explicit_bootstrap`,
  `a_download_mode_host_refuses_an_unprepared_sidecar`). `mvmctl machine run
  --image` prepares the overlay, initramfs and OCI guest runtime before it
  dispatches (`resolve_launch_image_source`), announced on its own line, so
  that path needs no `mvmctl bootstrap`. This statement does not cover a
  launch with no image reference, which resolves its default image through a
  separate path. What #4794 proposes and is not shipped is moving
  preparation inside the launch layer itself; if it lands, preparation must
  stay a separately reported lane that prepared-launch measurements exclude,
  and those witnesses change deliberately.
  `mvmctl image dev ensure` without a selected checkout installs the pinned
  set's dev members, which are Linux layer.

## Guest runtime contracts

These sections were separate decision records until 2026-11-27. Each keeps the
decisions that code, the claims ledger or the docs still rely on; text that no
longer described the code was dropped, not carried.

### Runtime overlay

Besides the initramfs, every workload microVM boots two block devices: the
root filesystem, which is image content, and the runtime overlay, which is mvm
content assembled from the guest runtime as above. Both are dm-verity sealed.
Their root hashes reach the initramfs agent in `ActivateEnvironment`, never on
the kernel command line, and the agent sets up and checks both verity devices
before it pivots. The overlay mounts read-only at `/mvm/runtime`. There is no
separate verity init.

- **The overlay is the only source of mvm's guest binaries.** `mkGuest` bakes
  none of the agent, netinit, addon DNS, exit reporter or egress client into a
  root filesystem, and there is no baked fallback: a launch without a prepared
  overlay refuses and names `mvmctl bootstrap` rather than booting without an
  agent.
- **An OCI root filesystem stays what the registry served.** mvm never
  injects its binaries into pulled content, so the image's digest identity
  holds. `/mvm` is reserved: an image carrying anything at or under it is
  refused while its layers are unpacked.
- **Overlay executables are static.** They carry no dynamic loader and assume
  nothing about the root filesystem's libc, so they run in a root with any libc
  or none. The glibc host-services library ships in the SDK sidecar instead.
- **The host re-verifies the cached overlay before every attach.** The
  resolver in `mvm_fs::overlay` re-hashes the cached files against the
  checksum manifest recorded beside them and requires the cached `VERSION` to
  equal the running `mvmctl` version. Either mismatch refuses at admission.
- **Assembly is deterministic.** The ext4 image and verity tree are written in
  process with pinned parameters (4096-byte data and hash blocks, zero salt),
  and assembly re-derives the tree and root hash from the written image and
  refuses a disagreement.
- **The SDK sidecar is attached per workload, from the signed plan.** It is a
  separate read-only ext4 mounted at `/mvm/sdk`, attached only when the plan's
  service bindings name an SDK-served host service, through one host-share
  grant in the plan and one read-only volume in the launch config.
  `enforce_sdk_sidecar_attachment` refuses both a bound workload without it
  and an attachment the plan did not authorize. It carries no dm-verity
  target; its integrity is the checksum manifest and the version pin.

Non-goals: one mvm-controlled overlay per architecture, never a per-tenant
variant; never writable; no shell, interpreter or libc for the workload's own
use.

### OCI root filesystems

- **Preparation and launch are separate operations.** `mvmctl image pull`
  fetches the manifest, verifies layer digests, unpacks through the
  allow-listed unpacker and prepares the root filesystem and its verity
  sidecars. Prepared-only resolution refuses a missing, incompatible or
  incomplete preparation instead of pulling, unpacking, materializing or
  verifying signatures online. It is cache-only, not write-free: it may adopt
  an already-built matching runtime variant into the index. A persisted
  selection is expected data, not admission. It is re-resolved at every launch
  and persistent start, compared on reference, manifest, root filesystem,
  runtime, platform and backend identity, and bound into the signed
  admission; a changed selection refuses rather than refreshing. Measuring an
  existing cache for the first time records those bytes; it is not evidence of
  how they were derived from the OCI image.
- **Verity is generated on every OCI materialization and enforced when
  sealed.** The run-image path always emits a Merkle tree and root hash with
  the overlay's pinned parameters, so the root hash depends on the input tree
  alone. The in-process writer (`mvm_build::rootfs::materialize_ext4_pure`) is
  the default; the builder-VM fallback for trees it cannot represent runs
  `veritysetup` with the same parameters and reaches the same root hash.
  ADR-004 owns that writer split. A sealed launch refuses a verity set that is
  recorded but incomplete; an unsealed development launch boots without
  enforcing it.
- **Production refuses a mutable reference before any network access.**
  `--prod` requires a digest-pinned reference and an explicit registry trust
  policy, and refuses a tag before the registry is contacted, for `mvmctl image
  pull` and for a launch. Cosign verification of the resolved digest is
  required during production preparation and the policy cannot disable it.
  Prepared-only production resolution checks its authenticated pull receipt
  against the current policy and the base-image scan instead of verifying
  online.
- **Every launch of a pulled image records its provenance** — registry,
  repository, supplied reference, resolved manifest digest, layer digests and
  trust policy — in the chain-signed audit log. That is claim 14; its witnesses
  are in ADR-001's ledger.

Provenance and verity answer different questions, where a launch came from
and whether these bytes are the ones verified, and a production launch needs
both. Open: the two verity writers are redundant work where the fallback runs.

### Guest protocol, readiness and receipts

- **Every session starts with a protocol hello.** A guest-agent session,
  reachability probes included, begins with `ProtocolHello`. A version
  mismatch, or any other first request, gets `ProtocolMismatch` naming the
  remedy (upgrade the host, rebuild the guest, or downgrade the host) before
  anything dispatches. Protocol types are closed enums that reject unknown
  fields; there is no untyped compatibility shim.
- **Capabilities are a closed enum** (`GuestCapability`). A caller that needs
  one the guest does not advertise fails before the command runs, naming it.
- **Readiness is separate from lifecycle.** The coarse VM state says whether
  the backend runs the VM; a readiness report says whether it is usable, per
  component (control plane, entrypoint, warm pool, integrations, probes,
  volumes), each `Disabled`, `Starting`, `Ready` or `Failed`. `Disabled` is
  never reported as `Ready`, and readiness invents no lifecycle state.
- **Control and data stay separate within one authenticated protocol.** Every
  frame is capped at 256 KiB. Data-plane content moves in chunks sized from
  that cap and the encoding's worst-case expansion, checked at build time.
  Payload bytes never enter audit entries, readiness reports or receipts; where
  a receipt refers to output it stores a hash.
- **Backpressure is typed and non-terminal.** A backpressured wait reports a
  closed reason (agent unreachable within its grace period, named services'
  probes pending, slow output consumer, full input buffer, paused artifact
  transfer, busy builder VM) and the caller keeps waiting.
- **Receipts are default-safe.** A run receipt records what ran as hashes and
  metadata (backend, network posture, exit status, output hashes), never raw
  argv, environment, stdin, stdout, stderr, secrets or tokens.

Not decided here: a structured progress-event stream across CLI text and JSON,
and a command mapping failures to remedies.

### Distribution

A release install on a supported host needs no package manager. On macOS 26+
Apple Silicon it uses HVF; libkrun is a source-build opt-in that uses the
host's own Homebrew installation, and the release ships no libkrun tier. The
release archive carries `mvmctl`, its per-VM helpers and the guest runtime,
installed beside one another, and every published archive is authenticated
under claim 20. Dropped with macOS below 26: vendoring and signing libkrun and
libkrunfw ourselves, and the root-flake bundle packager that was to do it.

### Rootless guest runtime (Proposed)

This subsection is Proposed, not accepted, and states no claim. What ships is
claim 2 (no guest binary can elevate to uid 0) and claim 1's confinement.

The target is that no workload or guest-controlled code runs as uid 0 and no
usable root account exists. Today uid 0 is held by the initramfs agent for
boot setup only: verity, mounts, the pivot and the guest environment. It then
narrows its capability bounding set and drops to the fixed workload identity,
keeping only named capabilities, before activation completes; workload
processes start through `mvm-setpriv` with `no_new_privs`. The privileged
helpers that must outlive that drop (CRNG reseed, late read-only volume
mounts) start before it. Privileged setup a workload needs happens before the
drop or through an explicitly granted capability, never by running workload
code as root, so workloads bind high ports.

Rejected: a literal rootless PID 1, since the kernel hands PID 1 to uid 0; and
user namespaces, which contain an in-guest root on the host side rather than
removing it.

Open, and blocking acceptance: a runtime witness that the agent and workload
euid is non-zero once live; a build-time scan that the production root
filesystem holds no setuid-root binary and no `su`, `sudo` or `doas`; and
confirmation that a production image has no root login or shell and the dev
console shell runs as the workload uid. The claim number is assigned in the
change that ships those witnesses. Related:
[#2101](https://github.com/tinylabscom/mvm/issues/2101) (the OCI workload
process runs with `NoNewPrivs=0` and a full bounding set),
[#4612](https://github.com/tinylabscom/mvm/issues/4612),
[#4819](https://github.com/tinylabscom/mvm/issues/4819).

## Consequences

### What moves

- The guest-bins archive grows to carry every guest artifact mvm owns,
  including the shared objects, `mvm-setpriv`, the initramfs agent and the
  Python SDK tree (#4102), and ships as a signed CLI release asset (#4103).
- `mvmctl` assembles the overlay, the initramfs and the SDK sidecar from the
  archive or a source build, with one cache keyed by the archive digest
  (#4104). The host-built sidecar is the library alone.
- Everything `mkGuest`'s `/init` did that the agent did not moved into Rust,
  and `mkGuest` writes no `/init` (#4106, landed). The base root filesystems
  `mvm-images` publishes stop carrying one when its `mvm` input advances past
  that change or is dropped (tinylabscom/mvm-images#49).
- `mvm-setpriv` joins the builder boot payload at ABI 2; the builder image
  then bakes no mvm binary, and the builder cache key stops folding the setpriv
  source closure for ABI 2 images (#4107).
- The guest runtime leaves the image-set contract, and fetch-when-unchanged is
  deleted, including its `pinned` value and its module (#4105, landed); the
  members' `source_fingerprint` stays parseable until no published set carries
  it. The `guest_agent_protocol` range is no longer copied into `images.lock`
  or checked: the guest-agent protocol is a property of the CLI and its own
  guest runtime, which ship together. It is replaced by a base-image contract
  version (`mvm_core::image_set::BaseImageContract`) that the base root
  filesystem declares in `/etc/mvm/base-image-contract`, the signed set copies
  into `compatibility.base_image_contract`, and `mvmctl` checks before any
  member is fetched (#4105, landed). Contract 0 is a set that declares none —
  every set up to `image-set/v0.2.4` — and is checked by that number rather
  than skipped; contract 1 is a base root filesystem with no mvm binary and no
  mvm `/init`, carrying the fixed guest identities. This CLI
  boots 0 and 1. `mvm-images` declares it in source (tinylabscom/mvm-images#64); no published set carries it yet.
- mvm's CI stops building guest pieces through `mvm-images` (#4108).
- `mvm-images` drops the `mvm` input and every read of mvm's source
  (tinylabscom/mvm-images#49) and attests build provenance for image sets
  (tinylabscom/mvm-images#50). Pack CI moves to the pinned base set
  (tinylabscom/mvm-packs#12).

### Ordering

The order is forced by what shipped CLIs accept. Every `mvmctl` released
before #4105 requires `runtime_overlay`, `sdk_sidecar_{glibc,musl}` and
`initramfs` on both architectures in every acquire of the locked set, every
image set embedded in a signed bundle, and `image boot verify
--require-complete`, so each refuses a set without those roles. The mvm
release carrying #4105 relaxes the requirement first; `mvm-images` publishes
a set without the roles only after it, and only that release or a later one
may pin such a set. Older CLIs keep pinning their own published sets and are
unaffected.

`ImageSetRole` is a closed serde enum, so deleting the three variants would
have made the pinned `image-set/v0.2.4` manifest unparseable. They live on as
one untagged `RetiredGuestRuntime` variant that keeps their wire spelling, so
the current pin and any set `mvm-images` publishes before it drops the roles
still parse, and the variant can go once no pinned set carries them.
`IMAGES_CHECKOUT_MARKERS` already recognises an `mvm-images` checkout without
the `runtime-overlay` and `initramfs` image definitions, so it does not have
to change when they are deleted. What a `.mvmpkg` that embeds an image set
records about the guest runtime it was tested with, and where a portable
bundle's boot assets take their overlay and initramfs from once no set
publishes them, is decided in #3928.

### Why `mkGuest` stays

Workload authors call `mkGuest` from their own flakes; it is mvm's API, not an
image definition. The commit history above says it moves with mvm's crates.
What changes is narrower: it writes no `/init` (#4106), it gains an option to omit its own `mvm-setpriv` copy, which the
builder image sets (#4107), and the workload-author guide is updated with it.

### Superseded

- The guest-bins plan's bump job, which had mvm's release workflow open PRs in
  `mvm-images` to advance a guest-bins pin.
- `mvm-images` consuming the archive through a `guest-bins.nix` recipe, and
  `image-set/v0.3.0` as the first set built on it.
- Vendoring `mkGuest` into `mvm-images` with a fixture test pinning the two
  copies together.
- Fetch-when-unchanged, deleted under #4105.

### What stays the same

- `crates/mvm-core/images.lock` pins one signed image set by root digest and
  exact release-workflow identity. It pins the base set: kernels, base root
  filesystems, the builder image and the Stage 0 seeds.
- Every downloaded byte is still digest-verified, and every signed root or
  release asset is still bound to an exact GitHub Actions workflow identity.
  The guest runtime is authenticated the way the CLI archive is, under the
  CLI release workflow, rather than under the image-set workflow.
- Host Nix is never used (ADR-004). The guest runtime was never a
  Nix build on the host and does not become one: it is cargo-zigbuild output
  from the pinned toolchain, the same mechanism ADR-004 uses for the builder
  binaries embedded in `mvmctl`.
- The claim posture is unchanged in substance. The runtime overlay is still
  dm-verity sealed and its root hash still reaches the agent in
  `ActivateEnvironment`; what changes is where the overlay's bytes come from.
  The ADR-001 rows whose witnesses name the image-set path (claims 3, 6
  and 20) are corrected in #4109, which owns the ledger.

### Costs

- Each CLI release carries the guest runtime for both architectures. The
  archive #3976 introduces measured about 11 MB for both architectures with
  ten static executables each, before the shared objects and the Python SDK
  tree join it.
- A fix to the guest agent now needs a CLI release; there is no image-only
  path for it. Kernel and package fixes still ship as image sets without one.
- During the transition the published image set still lists guest pieces
  until a set built from mvm-images' current source (which has no `mvm` input) is
  published; `mvmctl` parses them as retired
  roles and ignores them (#4105).

## Workstreams

In order; items on the same line can run in parallel.

1. [#4101](https://github.com/tinylabscom/mvm/issues/4101): record the
   decision (this ADR, `CLAUDE.md`, `AGENTS.md`, plans).
2. [#4102](https://github.com/tinylabscom/mvm/issues/4102): the guest-bins
   archive carries every guest artifact (builds on #3976).
3. [#4103](https://github.com/tinylabscom/mvm/issues/4103): ship it as a
   signed CLI release asset.
4. [#4104](https://github.com/tinylabscom/mvm/issues/4104): `mvmctl`
   assembles the overlay, initramfs and SDK sidecar from it ·
   [#4106](https://github.com/tinylabscom/mvm/issues/4106): the initramfs
   agent is the only guest init ·
   [#4107](https://github.com/tinylabscom/mvm/issues/4107): builder boot
   ABI 2 carries `mvm-setpriv`.
5. [#4105](https://github.com/tinylabscom/mvm/issues/4105): remove the guest
   runtime from the image-set contract and delete fetch-when-unchanged ·
   [#4108](https://github.com/tinylabscom/mvm/issues/4108): mvm CI stops
   building guest pieces through `mvm-images`.
6. [tinylabscom/mvm-images#49](https://github.com/tinylabscom/mvm-images/issues/49):
   `mvm-images` drops the `mvm` input and builds only the Linux layer ·
   [tinylabscom/mvm-images#50](https://github.com/tinylabscom/mvm-images/issues/50):
   build-provenance attestation for image sets.
7. [#4109](https://github.com/tinylabscom/mvm/issues/4109): claims ledger and
   docs.

In parallel from the start:
[tinylabscom/mvm-packs#12](https://github.com/tinylabscom/mvm-packs/issues/12):
pack CI builds on the pinned base set, reproduces, signs and attests.
