# Boot image lifecycle — gate it, version it, expose it

Backing: preview
Validation: none

**Status:** OPEN — documented in full, no workstream started, not scheduled
**Opened:** 2026-08-15

This plan is written to be executed later, possibly by someone who was not part
of the discussion that produced it, and possibly not in this repository. Every
workstream therefore names the files it touches, the functions it reuses, the
tests it adds, and how it is undone. Where a decision had a plausible
alternative, the alternative and the reason it lost are recorded, so the
question is not reopened from scratch.

## Why this plan exists

A boot image is the one artifact a user cannot inspect, cannot update on
purpose, and cannot tell the origin of. It is acquired implicitly, cached
implicitly, and replaced never. Four separate complaints share that root:

- **No visibility or control.** `mvmctl image` is OCI-only (`pull` / `ls` /
  `inspect`). Nothing answers "which boot image am I on, where did it come from,
  is it current" or refreshes one on request. The state lives under
  `~/.mvm/cache/default-microvm/{dev,prod}/` and is reachable only by deleting it.
- **The dev/installed split misfires.** The intended rule — a source checkout
  builds locally, an installed binary fetches — is implemented, but there is no
  way to observe which arm ran, so a misfire is invisible.
- **Local build is slow and has no opt-out.** In a source checkout the local
  build is unconditional. There is no supported way to say "I am working on the
  CLI, not the image — hand me a prebuilt".
- **Images ride the CLI's release train.** They publish from `release.yml` under
  the same `vN` tag as `mvmctl`, so an image cannot ship a fix without a CLI
  release, or the reverse.

The cost of the last two compounding is on record. A one-column whitespace change
in `nix/lib/mk-guest.nix` shifted `/init`'s shebang off byte 0, and every
published image from `v0.17.0` onward panicked with `ENOEXEC` before userspace
started. It survived five weeks. **Nothing boots a freshly built image before it
is published** — the only boot check in the repo runs against an *already
published* artifact, so it could report the breakage but never prevent it.

## Current behaviour, as of writing

Established by reading the tree, not from memory. An executor should re-verify
these before starting, since the surrounding code moves.

| Concern | Where it lives today |
|---|---|
| Dev-vs-installed detection | `find_builder_vm_flake()` in `crates/mvm-cli/src/commands/env/builder_vm.rs`; the `is_ok()` wrapper is `find_builder_vm_flake_is_source_checkout()` |
| Default microVM acquisition | `ensure_default_microvm_image` → `ensure_default_microvm_{prod,dev}_image` in `crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs` |
| Local build arm | `try_build_prod_default_locally` — returns `None` unless `find_builder_vm_flake().is_ok()`, then the caller falls through to `download_default_microvm_image` |
| Workload kernel | `resolve_kernel(&cache, arch, "workload", source_checkout)` in `mvm_build::kernel_fetch`, with `KernelResolution::{Cached,NeedsBuild,NeedsFetch}` |
| Hash verification | `fetch_expected_hashes` and `verify_artifact_hash`, both `pub(super)` in `crates/mvm-cli/src/commands/env/artifact_verify.rs` |
| Release publication | `default-microvm`, `builder-vm-image`, `runtime-overlay-image`, `sdk-sidecar-image` jobs in `.github/workflows/release.yml`, triggered on `push: tags: v*` |
| Image metadata sidecar | `GuestSidecar` / `SIDECAR_FILENAME = "mvm-meta.json"` in `crates/mvm-build/src/builder_vm.rs`; emitted by `nix/images/default-tenant/flake.nix` |
| Self-update machinery | `crates/mvm-cli/src/update.rs` — `fetch_latest_version()` against `/repos/<repo>/releases/latest`, with `MVM_UPDATE_API_URL` / `MVM_UPDATE_DOWNLOAD_URL` test overrides |
| Firecracker pin precedent | `FC_VERSION_DEFAULT` in `crates/mvm-core/src/config.rs`, an `option_env!`-backed constant |

## What this plan is not

Moving the rootfs to its own repository. That is a reasonable destination and it
is where comparable projects sit, but it is not reachable from here as things
stand: `nix/lib/mk-guest.nix` builds `guestAgentPkg` through
`pkgs.callPackage ../packages/mvm-guest-agent.nix`, which runs
`rustPlatform.buildRustPackage` against this workspace. The rootfs embeds
`mvm-guest-agent`, `mvm-seccomp-apply` and `mvm-verity-init`, compiled from
`crates/`. A repo boundary drawn today inverts the dependency — the image repo
would need this repo's source to build — and turns every host↔guest protocol
change into a two-repo sequence.

The prerequisite for drawing that boundary is recorded under **Destination**.

## Design

Four workstreams. WS1 is independent and worth landing alone. WS2 and WS3 share
a metadata format, so WS2 lands first. WS4 depends on nothing but reads better
after WS3.

---

### WS1 — Boot a freshly built image before publishing it

**The gap.** `release.yml`'s `default-microvm` job builds the image, copies
`vmlinux` / `rootfs.ext4` / `rootfs.verity` / `rootfs.roothash` /
`mvm-meta.json` into `staging/`, generates an SBOM via
`nix-store --query --requisites`, signs a pack manifest, and uploads. At no
point does anything start the thing.

**The change.** Add a boot step to that job between the build step and the
upload step, and make the upload depend on it. It boots the **staged** artifact,
never a published one.

On the `x86_64` matrix leg (`runs-on: ubuntu-latest`, the tier with nested KVM):

```yaml
- name: Boot the staged image before it becomes a release asset
  env:
    MVM_RUNTIME_BOOT_BENCH: "1"
    MVM_RUNTIME_BOOT_BACKEND: firecracker
    MVM_RUNTIME_BOOT_KERNEL: staging/default-microvm-vmlinux-x86_64
    MVM_RUNTIME_BOOT_ROOTFS: staging/default-microvm-rootfs-x86_64.ext4
    MVM_RUNTIME_BOOT_READY: guest-agent
    MVM_RUNTIME_BOOT_RUNS: "1"
    MVM_RUNTIME_BOOT_CONCURRENT: "1"
    MVM_RUNTIME_BOOT_BUDGET_MS: "60000"
  run: |
    cargo test --test runtime_boot_bench \
      prebuilt_runtime_image_boots_within_budget -- --exact --nocapture
```

The step needs the same three prerequisites the existing boot lane sets up:
Firecracker installed at the version `FC_VERSION_DEFAULT` names, `/dev/kvm`
made accessible to the runner user, and `mvm-meta.json` present in the rootfs's
own directory under the name the runtime-overlay admission gate looks for. Copy
those steps from the `boot-latency` job rather than writing new ones.

**This is not a latency assertion.** `MVM_RUNTIME_BOOT_BUDGET_MS` is set an
order of magnitude above the observed median deliberately, and `RUNS`/
`CONCURRENT` are 1. The question this gate answers is "does it reach userspace",
which is the question the five-week breakage needed asked. Latency belongs to
the separate `boot-latency` lane, which has its own threshold discussion.

**The `aarch64` asymmetry.** That leg runs on `ubuntu-24.04-arm`, which has no
nested KVM, so it cannot boot. It gets a static check instead: read `/init` out
of the built ext4 and assert its first two bytes are `#!`. This catches the exact
defect class that shipped, and nothing else. It is a stated compromise, not a
claim of equivalence — an aarch64-only regression that is not a shebang defect
still gets through. The reader for this already exists: `ext4-view` is a
workspace dependency and `mvm-fs` has its own ext4 code.

**Files touched.** `.github/workflows/release.yml` only.

**Tests.**

- `a_rootfs_whose_init_shebang_is_shifted_fails_the_gate` — build a fixture ext4
  whose `/init` begins with a space, run the aarch64-style header check against
  it, assert refusal. Run this red before wiring the check in; a gate that
  passes on the artifact it was written for is worth nothing.
- The x86_64 boot leg is exercised by the release workflow itself. There is no
  hermetic substitute — booting is the point.

**Undo.** Delete the step and the `needs` edge. No state, no migration.

---

### WS2 — Give images their own release train

**Tag namespace.**

```
v0.18.0              -> mvmctl binaries, crates
boot-image/v0.1.0    -> vmlinux, rootfs, verity sidecars, meta, SBOM, pack
```

Plain semver on its own counter, starting at `0.1.0`. Three choices worth
stating, since each had a plausible alternative:

- **The tag does not encode the guest protocol.** Tying the major to
  `PROTOCOL_VERSION_AUTHENTICATED` reads as self-documenting until the two axes
  diverge — a rootfs layout change that an older `mvmctl` cannot mount is
  breaking without being a protocol break, and then the major cannot move
  honestly. The tag carries identity and ordering; the sidecar's
  `protocol_version` carries compatibility. One fact, one place.
- **It starts at `0.x`, not `1.0.0`.** The CLI is pre-1.0; an image line opening
  at `1.0.0` would imply a stability commitment that has not been made.
- **The counter is fresh rather than continuing `v0.17.x`.** Images have never
  had a version of their own, so continuing a number would imply a history that
  does not exist. Previously published assets stay reachable under their old
  tags either way — that is what the dual-publish window below is for.

`boot-image/v*` does not match the existing `v*` release trigger: GitHub tag
globs do not cross `/` and the pattern anchors at the start, so neither train
can fire the other by accident. An executor should re-check this against
GitHub's current matching behaviour rather than trusting the sentence.

**The split.** Move the four image jobs — `default-microvm`, `builder-vm-image`,
`runtime-overlay-image`, `sdk-sidecar-image` — out of `release.yml` into a new
`.github/workflows/release-boot-image.yml` triggered on
`push: tags: 'boot-image/v*'`. The binary and crate jobs stay where they are.

Two details that are easy to lose in the move:

- Those jobs run under `environment: release-signing`, which constrains which
  ref can mint a keyless signing identity. The new workflow needs the same
  environment, or pack signing silently stops working. `continue-on-error: true`
  on the signing step means a broken identity does **not** fail the job — it just
  stops shipping a pack — so this failure is quiet by design and will not be
  noticed without looking.
- The flakes stay in `nix/images/`. This is what keeps the source-checkout
  invariant true for free: a contributor editing `nix/images/builder-vm/flake.nix`
  still sees that change on the next boot with no release round-trip, because
  the flake is right there. Moving the flakes is what the **Destination** section
  is about, and it is not part of this workstream.

**The consumer side.** `mvmctl` needs a compiled-in default naming the image
line it expects. Follow the `FC_VERSION_DEFAULT` precedent — an `option_env!`
constant in `crates/mvm-core/src/config.rs`, overridable at build time:

```rust
pub const DEFAULT_BOOT_IMAGE_TAG: &str = match option_env!("MVM_BOOT_IMAGE_TAG") {
    Some(t) => t,
    None => "boot-image/v0.1.0",
};
```

`download_default_microvm_image` and `download_workload_kernel` build their
release URLs from this instead of the CLI's own version.

**Files touched.** `.github/workflows/release.yml` (remove four jobs),
`.github/workflows/release-boot-image.yml` (new), `crates/mvm-core/src/config.rs`,
`crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs`.

**Tests.**

- Extend the `xtask check-workflow-paths` style assertion to cover the emitted
  asset names for both namespaces, so a rename cannot land silently.
- A unit test that `DEFAULT_BOOT_IMAGE_TAG` composes the same asset URL shape
  the release workflow uploads to. A mismatch here is a 404 at first boot on a
  fresh install, which is the worst place to find it.

**Undo.** Move the four jobs back and revert the constant. Published
`boot-image/*` tags are additive and can simply be left in place.

---

### WS3 — Provenance, and a command surface over it

**Metadata.** `GuestSidecar` records `name`, `sealed`, `accessible`,
`entrypoint_kind`, `entrypoint_argv`, `init_system`, `expected_boot_ms`,
`agent_binary`, `rootless_entrypoint`, `hypervisor`, `overlay_aware` — and
nothing about *which* image this is. Add:

| field | type | why |
|---|---|---|
| `image_tag` | `String` | which release line and version this came from |
| `source` | `String` | `built-local` \| `fetched` — makes a split misfire observable |
| `built_at` | `String` | RFC 3339; orders two local builds |
| `protocol_version` | `u8` | the host↔guest contract this rootfs speaks |
| `generator_rev` | `String` | the commit whose `mk-guest.nix` produced it |

`source` is the field that turns "the split misfires" from a suspicion into a
readout. `protocol_version` is the one that makes a future repo split checkable.

Every field is `#[serde(default)]`. That is not a new convention — `GuestSidecar`
already carries `#[serde(default)]` on `entrypoint_argv` and `overlay_aware` for
exactly this reason, and the repo's standing rule is that new fields default
rather than gate. An old sidecar in a warm cache keeps deserializing and reads
as empty.

The emitter is `nix/images/default-tenant/flake.nix`, which writes
`mvm-meta.json` from `sidecarJson meta`. `generator_rev` has to come in as a
flake input or build arg; a Nix build has no ambient git access.

**Commands.** New subcommands under the existing `Image` verb, beside
`pull` / `ls` / `inspect`:

```
mvmctl image boot status  [--json]
mvmctl image boot check   [--json]
mvmctl image boot update  [--tag <t>] [--force]
```

- **`status`** — for each cached variant (`dev`, `prod`): tag, source,
  built/fetched time, protocol version, on-disk size, and whether the current
  process would use it. Reads the cache only; no network.
- **`check`** — compare the cached tag against the latest published
  `boot-image/v*`. Read-only. Exits nonzero when behind, so it can gate a script
  without parsing output.
- **`update`** — fetch and verify the newer image, then atomically replace the
  cache entry. `--tag` pins a specific release. Refuses to act in a source
  checkout unless `--force`, because there the local build is authoritative and
  silently replacing it with a prebuilt would make the working tree a lie.

**Reuse, not reimplementation.** `check` and `update` extend
`crates/mvm-cli/src/update.rs` rather than growing a second HTTP path — it
already queries `/repos/<repo>/releases/latest` and carries
`MVM_UPDATE_API_URL` / `MVM_UPDATE_DOWNLOAD_URL` overrides that make the network
leg testable without a network. Hash verification calls the existing
`fetch_expected_hashes` + `verify_artifact_hash`, which stream an artifact
through SHA-256 against the release's own checksum manifest and delete on
mismatch; those are `pub(super)` today and need widening to `pub(crate)`.

**Files touched.** `crates/mvm-build/src/builder_vm.rs` (sidecar fields),
`nix/images/default-tenant/flake.nix` (emit them),
`crates/mvm-cli/src/commands/image/` (new subcommand module),
`crates/mvm-cli/src/update.rs` (widen reuse),
`crates/mvm-cli/src/commands/env/artifact_verify.rs` (visibility).

**Tests.**

- `an_old_sidecar_without_provenance_fields_still_deserializes` — the
  compatibility guarantee, tested against a literal old JSON blob rather than a
  round-trip of the new struct, since a round-trip cannot catch a missing default.
- `check_reports_behind_when_the_published_tag_is_newer` — against a stubbed
  releases API via `MVM_UPDATE_API_URL`.
- `a_failed_update_leaves_the_previous_image_in_place` — serve an artifact whose
  hash does not match the manifest, run `update`, then assert the cache still
  holds the original bytes. This is the test that matters most; an update path
  that can leave a half-written image is worse than no update path.
- `update_refuses_in_a_source_checkout_without_force`.

**Undo.** The commands are additive and can be deleted. The sidecar fields
default, so a rollback leaves older sidecars readable by both versions.

---

### WS4 — An escape hatch for the dev inner loop

In a source checkout the local image build is unconditional. Add an opt-out for
when the image is not what is being worked on:

| `MVM_BOOT_IMAGE` | behaviour |
|---|---|
| unset | today's behaviour, unchanged |
| `build` | force a local build even when installed |
| `fetch` | fetch a prebuilt even in a source checkout |

Precedence follows the `--builder` / `MVM_BUILDER_BACKEND` pattern already in the
repo: explicit flag, then env var (case-insensitive, whitespace-trimmed, an
unrecognised value logs a warning and falls through), then auto-detect.

The resolved choice and its reason go on `mvmctl doctor`'s output in the shape
the `builder backend` line already uses — `<choice> — <source> — <availability>`
— so the override path is observable rather than folklore. This is also what
makes complaint two ("the split misfires") diagnosable: `doctor` says which arm
was chosen and why, and `image boot status` says which arm actually produced the
bytes on disk.

`fetch` in a source checkout writes `source: fetched` into the sidecar, so a
stale prebuilt cannot later be mistaken for a build of the working tree. This is
the one place the plan deliberately weakens the "source checkouts never depend
on published artifacts" invariant, and it does so only on explicit opt-in. The
default is unchanged and the sidecar records which arm ran. That trade is worth
stating in `CLAUDE.md` alongside the invariant when this lands, rather than
leaving the invariant reading as absolute when it has an opt-out.

**Files touched.** `crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs`,
`crates/mvm-cli/src/doctor/`, and `CLAUDE.md`.

**Tests.**

- Each knob value resolves to the intended arm — table-driven over the three
  states plus an unrecognised value.
- The resolved choice reaches `doctor`'s output.
- `fetch`-in-checkout writes `source: fetched`.

**Undo.** Delete the knob. Unset is today's behaviour, so nothing to migrate.

---

## Not breaking anything on the way

The constraint that shapes every step: **no change lands that can only be
validated after it ships.** That is the failure mode this plan exists to close,
and the migration must not reproduce it.

**Ordering.** WS1 first, alone, and let it run green on a real release before
anything else moves. It adds a gate and changes no acquisition path, so its
blast radius is "a broken image fails to publish" — the outcome wanted anyway. It
also means WS2 moves jobs that are already gated, rather than moving and gating
them in one step.

**Old tags keep working.** Publishing under `boot-image/v*` does not retract
`v0.17.0`'s assets. An installed `mvmctl` pinned to a `vN` image tag keeps
resolving it. WS2 adds a namespace; it removes nothing.

**Dual-publish window.** For at least one CLI release, the image jobs publish to
*both* the `vN` release and the new `boot-image/vN`. Binaries in the wild that
predate `DEFAULT_BOOT_IMAGE_TAG` keep finding assets where they expect them. The
window closes when a CLI release that understands the new namespace is the
oldest supported one — which is a judgement about the user base, not a fact
derivable from the code, so it wants a deliberate decision rather than a default.

**Sidecar fields are additive.** Every new provenance field is
`#[serde(default)]`, matching what `entrypoint_argv` and `overlay_aware`
already do. An old `mvm-meta.json` in a warm cache keeps deserializing; the
fields read as empty and `status` prints `unknown` rather than failing. No cache
wipe, no schema version bump.

**Cache replacement is atomic or absent.** `update` fetches to a temp path,
verifies the hash, and only then renames into place, keeping the previous entry
until the new one verifies. A failed or interrupted update leaves the working
image untouched. This mirrors `ensure_fc_loadable_kernel`'s existing
tmp-then-rename discipline, which exists for the same reason.

**The default never moves silently.** WS4's knob is unset by default and
resolves to exactly today's behaviour. WS3's `update` refuses to run in a source
checkout without `--force`. A user who does nothing sees no change.

**Rollback.** Each workstream reverts independently: WS1 is a workflow step, WS2
is a trigger plus a constant, WS3 is additive CLI surface and defaulted fields,
WS4 is a knob that is off. None is a data migration.

**What could still bite, stated rather than hidden.**

- The `aarch64` boot gate is a header check, not a boot. An aarch64-only
  regression that is not a shebang defect gets through.
- Splitting the release train means a stale `DEFAULT_BOOT_IMAGE_TAG` on a
  long-lived branch resolves to an older image than its code expects. The
  `protocol_version` field is what makes that detectable; wiring a refusal on it
  is left to the Destination work rather than claimed here.
- Pack signing fails quietly by design (`continue-on-error: true`). Moving those
  jobs to a new workflow with a misconfigured `environment` would stop pack
  publication without failing anything. Check for a published pack after the
  first `boot-image/*` release specifically.

## Testing posture

Biased toward the negative case, because the defect that motivated this plan was
a positive-path success: everything the pipeline asserted was true, and the
image still could not boot.

Every test above runs without a hypervisor except the WS1 x86_64 boot, which is
CI-only by nature. Where a test exists to catch a specific regression, run it
red against the unfixed behaviour first and record that output in the change
that adds it — the repo has a standing practice of this, and the tunnel-bound
witness is the worked example of why: its first version asserted on a byte that
a passing and a failing run both produce, and it passed with the fix reverted.

## Destination — what a real repo split needs first

Recording this so the option stays open and its cost stays honest.

The blocker is the source-path dependency from the image build to the workspace.
Removing it means the guest side becomes a *consumed artifact* rather than a
*local build input*:

1. Publish `mvm-contract` — already `no_std` + `forbid(unsafe_code)`, already
   holding the wire types — as a versioned crate. Both sides depend on it.
2. Publish the guest binaries (`mvm-guest-agent`, `mvm-seccomp-apply`,
   `mvm-verity-init`) as release artifacts tagged with the protocol version they
   speak, and have `mk-guest.nix` consume a pinned published set instead of
   `../..`.
3. Gate on protocol compatibility: a host refusing an image whose
   `protocol_version` it does not speak, with a real refusal test.

The wire protocol is already versioned (`PROTOCOL_VERSION_AUTHENTICATED = 2`,
`PROTOCOL_VERSION_LEGACY = 1`, ADR-019), so step 3 has a foundation. Steps 1 and
2 are the work, and step 2 is the one that changes how contributors work day to
day: a guest-agent change would stop being a single-PR operation.

The kernel is separable at any time and independently of all of the above. It
carries no workspace source, and already has its own build lane, its own
required checks, and a fetch/build seam in `resolve_kernel`. If a boot-image
repository is wanted sooner rather than later, the kernel is the piece that can
move first at low cost, and doing it would exercise the two-repo release
mechanics on the artifact where a mistake is cheapest to correct.

## Workstreams

- [x] WS1 — boot the staged image before publish (x86_64 boot, aarch64 header check)
- [ ] WS2 — `boot-image/v*` release train (semver from `v0.1.0`), dual-publish window, `DEFAULT_BOOT_IMAGE_TAG`
- [x] WS3 — sidecar provenance fields + `mvmctl image boot status｜check｜update`
- [ ] WS4 — `MVM_BOOT_IMAGE` escape hatch + doctor readout

## Open questions for whoever picks this up

- How long should the dual-publish window be? Stated as "at least one CLI
  release" above, which is a floor rather than an answer. It depends on how far
  back installed binaries are expected to keep working, which is not recorded
  anywhere in the repo.
- Should `mvmctl image boot check` run automatically — on `doctor`, or once a
  day on some command — or stay strictly opt-in? Automatic checking is friendlier
  and is also an unannounced outbound request from a tool whose posture is that
  the host originates every connection deliberately.
- Does the aarch64 header check earn its keep, or is a leg that cannot boot
  better left uncovered and honestly labelled than covered by a check that only
  catches one defect class?
