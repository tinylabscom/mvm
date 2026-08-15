# Boot image lifecycle — gate it, version it, expose it

Backing: preview
Validation: none

**Status:** OPEN — no workstream started
**Opened:** 2026-08-15

## Why this plan exists

A boot image is the one artifact a user cannot inspect, cannot update on
purpose, and cannot tell the provenance of. It is acquired implicitly, cached
implicitly, and replaced never. Four separate complaints turn out to share that
root:

- **No visibility or control.** `mvmctl image` is OCI-only (`pull`/`ls`/`inspect`).
  Nothing answers "which boot image am I on, where did it come from, is it
  current" or refreshes one on request. The state lives under
  `~/.mvm/cache/default-microvm/{dev,prod}/` and is reachable only by deleting it.
- **The dev/installed split misfires.** The intended rule — a source checkout
  builds locally, an installed binary fetches — is implemented
  (`try_build_prod_default_locally` returns `None` unless
  `find_builder_vm_flake().is_ok()`, then falls through to
  `download_default_microvm_image`), but there is no way to observe which arm ran.
  A misfire is invisible.
- **Local build is slow and has no opt-out.** In a source checkout the local
  build is unconditional. There is no supported way to say "I am hacking on the
  CLI, not the image — hand me a prebuilt".
- **Images ride the CLI's release train.** They are published by `release.yml`
  under the same `vN` tag as `mvmctl`, so an image cannot ship a fix without a
  CLI release and vice versa.

The cost of the last two compounding is on record. A one-column whitespace
change in `nix/lib/mk-guest.nix` shifted `/init`'s shebang off byte 0, and every
published image from `v0.17.0` onward panicked with `ENOEXEC` before userspace.
It survived five weeks. **Nothing boots a freshly built image before it is
published** — the only boot check in the repo runs against an *already published*
artifact, so it could report the breakage but never prevent it.

## What this plan is not

Moving the rootfs to its own repository. That is a reasonable destination and
it is where comparable projects sit, but it is not reachable from here as-is:
`nix/lib/mk-guest.nix` builds `guestAgentPkg` through
`pkgs.callPackage ../packages/mvm-guest-agent.nix`, which runs
`rustPlatform.buildRustPackage` against this workspace. The rootfs embeds
`mvm-guest-agent`, `mvm-seccomp-apply` and `mvm-verity-init`, compiled from
`crates/`. A repo boundary drawn today inverts the dependency — the image repo
would need this repo's source to build — and turns every host↔guest protocol
change into a two-repo sequence.

The prerequisite for drawing that boundary honestly is recorded under
**Destination** below.

## Design

Four workstreams. WS1 is independent and worth landing alone. WS2 and WS3 share
a metadata format, so WS2 lands first. WS4 depends on nothing but reads better
after WS3.

### WS1 — Boot a freshly built image before publishing it

The gap: `release.yml`'s `default-microvm` job builds the image, copies
`vmlinux` / `rootfs.ext4` / verity sidecars / `mvm-meta.json` into `staging/`,
generates an SBOM, signs a pack manifest, and uploads. At no point does anything
start the thing.

Add a boot step to that job, between build and upload, on the `x86_64` matrix
leg (the runner tier with nested KVM). It boots the **staged** artifact — not a
published one — under Firecracker and waits for guest-agent readiness. Upload is
`needs`-gated on it, so a rootfs that cannot reach userspace never becomes a
release asset.

This reuses the existing harness: `MVM_RUNTIME_BOOT_BENCH` and the
`runtime_boot_bench` test already boot a kernel+rootfs pair from explicit paths.
The gate points those env vars at `staging/` instead of a downloaded release.

Deliberately **not** a latency assertion — a generous ceiling only, so runner
noise cannot block a release. The question this gate answers is "does it boot",
which is the question the five-week breakage needed asked.

The `aarch64` leg cannot boot under KVM on the current runner tier. It gets a
static check instead — `/init` is read out of the built ext4 and its first bytes
asserted to be `#!` — which is cheap and catches the exact defect class that
shipped. Recorded as a known asymmetry rather than papered over.

### WS2 — Give images their own release train

Images move to their own tag namespace and publish independently:

```
v0.18.0              -> mvmctl binaries, crates
boot-image/v3        -> vmlinux, rootfs, verity sidecars, meta, SBOM, pack
```

`release.yml` splits: the binary/crate jobs stay on `v*`, the four image jobs
(`default-microvm`, `builder-vm-image`, `runtime-overlay-image`,
`sdk-sidecar-image`) move to a workflow triggered by `boot-image/v*`.

The flakes stay in `nix/images/`. This is what keeps the source-checkout
invariant true for free: a contributor editing `nix/images/builder-vm/flake.nix`
still sees that change on the next boot with no release round-trip, because the
flake is right there.

`mvmctl` needs a compiled-in default of which image line it expects
(`DEFAULT_BOOT_IMAGE_TAG`), the way `FC_VERSION_DEFAULT` already pins Firecracker.

### WS3 — Provenance, and a command surface over it

`GuestSidecar` (`mvm-meta.json`) records `name`, `sealed`, `accessible`,
`entrypoint_kind`, `agent_binary`, `expected_boot_ms`, `hypervisor` — and
nothing about *which* image this is. Add provenance fields:

| field | why |
|---|---|
| `image_tag` | which release line and version this came from |
| `source` | `built-local` \| `fetched` — makes a split misfire observable |
| `built_at` | ordering two local builds |
| `protocol_version` | the host↔guest contract this rootfs speaks |
| `generator_rev` | the commit whose `mk-guest.nix` produced it |

`source` is the field that turns "the split misfires" from a suspicion into a
readout. `protocol_version` is the one that makes a future repo split checkable.

New subcommands under the existing `Image` verb, beside `pull`/`ls`/`inspect`:

- `mvmctl image boot status` — what is cached, per variant: tag, source,
  built/fetched time, protocol version, size. `--json` for scripting.
- `mvmctl image boot check` — compare cached tag against the latest published
  `boot-image/v*`. Read-only; exits nonzero when behind so it can gate a script.
- `mvmctl image boot update` — fetch and verify the newer image, atomically
  replace the cache entry, keep the previous entry until the new one verifies.
  `--tag <t>` pins; refuses to act in a source checkout unless `--force`, since
  there the local build is authoritative.

`crates/mvm-cli/src/update.rs` already queries `/repos/<repo>/releases/latest`
and carries `MVM_UPDATE_API_URL` / `MVM_UPDATE_DOWNLOAD_URL` overrides for
hermetic tests. `check`/`update` extend that machinery rather than growing a
second HTTP path.

Hash verification is not re-implemented: `fetch_expected_hashes` +
`verify_artifact_hash` (`commands/env/artifact_verify.rs`) already stream an
artifact through SHA-256 against the release's own checksum manifest and delete
on mismatch. `update` calls them.

### WS4 — An escape hatch for the dev inner loop

In a source checkout the local image build is unconditional. Add an opt-out for
the case where the image is not what is being worked on:

- `MVM_BOOT_IMAGE=fetch` — fetch a prebuilt even in a checkout
- `MVM_BOOT_IMAGE=build` — force a local build even when installed
- unset — today's behaviour exactly

The resolved choice and its reason go on `mvmctl doctor`'s output, in the shape
the `builder backend` line already uses (`<choice> — <source> — <availability>`),
so the override path is observable rather than folklore.

`fetch` in a checkout writes `source: fetched` into the sidecar, so a stale
prebuilt cannot later be mistaken for a build of the working tree. This is the
one place the plan deliberately weakens the "source checkouts never depend on
published artifacts" invariant, and it does so only on explicit opt-in — the
default is unchanged, and the sidecar records which arm ran.

## Not breaking anything on the way

The constraint that shapes every step: **no change lands that can only be
validated after it ships.** That is the failure mode this plan exists to close,
and the migration must not reproduce it.

**Ordering.** WS1 first, alone, and let it run green on a real release before
anything else moves. It adds a gate and changes no acquisition path, so its
blast radius is "a broken image fails to publish" — the outcome wanted anyway. It
also means WS2 moves jobs that are already gated, rather than moving them and
gating them in one step.

**Old tags keep working.** Publishing under `boot-image/v*` does not retract
`v0.17.0`'s assets. An installed `mvmctl` pinned to a `vN` image tag keeps
resolving it. WS2 adds a namespace; it removes nothing.

**Dual-publish window.** For one CLI release, the image jobs publish to *both*
the `vN` release and the new `boot-image/vN`. Binaries in the wild that predate
`DEFAULT_BOOT_IMAGE_TAG` keep finding assets where they expect them. The window
closes when a CLI release that understands the new namespace is the oldest
supported one.

**Sidecar fields are additive.** Every new provenance field is
`#[serde(default)]`. An old `mvm-meta.json` in a warm cache keeps
deserializing; the fields read as empty and `status` prints `unknown` rather
than failing. No cache wipe, no schema version bump — consistent with the
repo's standing rule that new fields default rather than gate.

**Cache replacement is atomic or absent.** `update` fetches to a temp path,
verifies the hash, and only then renames into place, keeping the previous entry
until the new one verifies. A failed or interrupted update leaves the working
image untouched. This mirrors `ensure_fc_loadable_kernel`'s existing
tmp-then-rename discipline.

**The default never moves silently.** WS4's knob is unset by default and
resolves to exactly today's behaviour. WS3's `update` refuses to run in a source
checkout without `--force`. A user who does nothing sees no change.

**Rollback.** Each workstream reverts independently: WS1 is a workflow step,
WS2 is a trigger plus a constant, WS3 is additive CLI surface and defaulted
fields, WS4 is a knob that is off. None is a data migration.

**What could still bite, stated rather than hidden.** The `aarch64` boot gate is
a header check, not a boot — an aarch64-only regression that is not a shebang
defect gets through. Splitting the release train means a stale
`DEFAULT_BOOT_IMAGE_TAG` in a long-lived branch resolves to an older image than
its code expects; the `protocol_version` field is what makes that detectable,
and wiring a check on it is deliberately left to the destination work below
rather than claimed here.

## Testing

Per workstream, biased toward the negative case, since the defect that motivated
this plan was a positive-path success.

- **WS1** — a fixture rootfs whose `/init` shebang is shifted one byte must fail
  the gate. Run it red before wiring the gate in, the way the tunnel-bound
  witness was.
- **WS2** — the release workflow's emitted asset names for both tag namespaces,
  asserted in the existing `xtask check-workflow-paths` style so a rename cannot
  land silently.
- **WS3** — sidecar round-trip including an old sidecar with no provenance
  fields; `check` against a stubbed releases API via `MVM_UPDATE_API_URL`;
  `update` against a served artifact whose hash does not match, asserting the
  cache still holds the original bytes afterward.
- **WS4** — each knob value resolves to the intended arm, and the resolved
  choice reaches `doctor`'s output. `fetch`-in-checkout writes `source: fetched`.

Every test runs without a hypervisor except the WS1 boot itself, which is CI-only.

## Destination — what a real repo split needs first

Recording this so the option stays open and its cost stays honest.

The blocker is the source-path dependency from the image build to the workspace.
Removing it means the guest side becomes a *consumed artifact* rather than a
*local build input*:

1. Publish `mvm-contract` (already `no_std` + `forbid(unsafe_code)`, already
   holding the wire types) as a versioned crate. Both sides depend on it.
2. Publish the guest binaries — `mvm-guest-agent`, `mvm-seccomp-apply`,
   `mvm-verity-init` — as release artifacts with the protocol version they
   speak, and have `mk-guest.nix` consume a pinned published set instead of
   `../..`.
3. Gate on protocol compatibility: a host refusing an image whose
   `protocol_version` it does not speak, with a real refusal test.

The wire protocol is already versioned (`PROTOCOL_VERSION_AUTHENTICATED = 2`,
`PROTOCOL_VERSION_LEGACY = 1`, ADR-019), so step 3 has a foundation. Steps 1 and
2 are the work.

The kernel is separable at any time and independently of all of the above: it
carries no workspace source, and already has its own build lane, its own
required checks, and a fetch/build seam in `resolve_kernel`. If a boot-image
repository is wanted sooner rather than later, the kernel is the piece that can
move first at low cost.

## Workstreams

- [ ] WS1 — boot the staged image before publish (x86_64 boot, aarch64 header check)
- [ ] WS2 — `boot-image/v*` release train, dual-publish window, `DEFAULT_BOOT_IMAGE_TAG`
- [ ] WS3 — sidecar provenance fields + `mvmctl image boot status｜check｜update`
- [ ] WS4 — `MVM_BOOT_IMAGE` escape hatch + doctor readout
