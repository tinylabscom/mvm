# Plan 85 — mvm-oci as user-facing image-runner primitive

> Status: Shipped (2026-05-26)
> Owner: TBD
> Started: 2026-05-16
> Completed: 2026-05-26 — Phases A.1–A.6, B, C, D, E, F, G all merged;
> claim 10 added to CLAUDE.md §"Security model"; six named CI lanes
> (`oci-layer-unpack-adversarial`, `oci-digest-mismatch-reject`,
> `oci-malformed-manifest`, `oci-mutable-tag-prod-reject`,
> `oci-reproducibility`, `oci-image-runner-smoke`) added to
> `.github/workflows/ci.yml` alongside the pre-existing
> `oci-layer-unpack-fuzz` lane. The full pull → unpack → materialize
> → boot round-trip against `docker.io/library/alpine:3.20@sha256:...`
> additionally requires libkrun/KVM, which github-hosted runners
> cannot provide (no nested KVM); the boot half stays under the
> self-hosted Vz/libkrun lanes.
> Supersedes: Plan 75 (retired by commit `b02a5e8` on 2026-05-14, which deleted Plan 75's spec file and ADR-049 along with the broader removal of the earlier external sandbox runtime — external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`). Plan 85 keeps Plan 75's security envelope but **drops the Stage 0 entanglement** — Plan 77's vendored-seed path is the active Stage 0 design and Plan 85 does not propose to replace it.
> Depends on: `mvm-oci` W1.1 + W1.2 (manifest fetch, digest verification, layer fetch w/ size cap + bounded retry) — already on `main`. Plan 72 (libkrun builder VM). Plan 77 (Stage 0 via vendored seed).
> Does not supersede / does not change: Plan 77's vendored-seed Stage 0 path (CLAUDE.md "Source-checkout builds never depend on mvm-published artifacts" invariant stays load-bearing). ADR-046's two acquisition paths (source vs installed binary) stay intact.

---

## Why this plan exists

Three things converge:

1. **`mvm-oci` already exists as a primitive.** W1.1 (reference parser, manifest fetcher) and W1.2 (layer streaming with digest verification + size cap + bounded retry) landed on `main` and are being maintained. The pull-half of OCI ingest is shipped.
2. **The runner-half — turning a pulled image into a bootable microvm — does not exist** anywhere in the workspace. mvm can build microvms from in-repo Nix flakes (Plan 72 + Plan 77); it cannot today consume an OCI image (e.g. `docker.io/library/alpine:3.20`) as a workload.
3. **Plan 75 conflated this user-facing capability with a Stage 0 replacement for the removed predecessor sandbox.** That coupling was the wrong design choice — Stage 0 is now Plan 77's vendored-seed path, and the user-facing image runner is its own coherent feature with its own security envelope. Decoupling lets each ship on its own review cadence.

The user-facing claim Plan 85 delivers: **`mvmctl run --image <oci-reference>` boots that image as a microvm with the same audit / cosign / digest-verification guarantees that apply to Nix-built workloads.**

## What is in scope

- **A new `mvm-oci::layer::unpack` module** that materializes pulled OCI layers (cached by W1.2) into a directory tree on disk, with explicit handling of every OCI layer-tar feature: whiteouts, opaque dirs, symlinks (no-escape-at-unpack), hardlinks (within-layer only), xattrs (allow-listed), device nodes (allow-listed to /dev/{null,zero,random,urandom} only), setuid/setgid bits (policy-controlled), absolute-path / traversal refusal.
- **A new `mvm-build::rootfs::materialize_ext4` step** that takes the unpacked tree from the previous step and emits an `ext4` rootfs image, running `mkfs.ext4` **inside a libkrun VM** (never on the macOS host — ADR-050 invariant). The libkrun VM used here is the existing builder VM (Plan 72); no new VM class.
- **A new `mvmctl image <subcommand>` family**: `pull`, `inspect`, `ls`, `rm`. Read-only and mutation-of-cache verbs. None of these boot a VM; reviewable as cache-plumbing.
- **A new `mvmctl run --image <ref>` verb** that composes pull + unpack + materialize_ext4 + the existing runtime path. Delivers the user-facing claim.
- **Audit-chain claim 10**: every `mvmctl run --image` admission records the registry, resolved digest, layer digest list, trust policy in effect, and (if present) cosign signature verdict. `mvmctl audit verify` continues to detect drift. The claim file at `specs/claims/claim-10-oci-image-provenance.md` is already on `main` from the original Plan 75 W0; Plan 85 W5 flips it from `Planned` to `Enforced`.
- **CI gates**: layer-unpack fuzz target, adversarial-fixture suite, digest-mismatch rejection, mutable-tag-prod refusal, reproducibility double-build.

## What is NOT in scope

- **Replacing Plan 77's Stage 0 path.** Stage 0 stays vendored-seed-driven. Plan 85 does not consume the OCI primitive from Stage 0 even though it technically could. The reasoning: Stage 0's seed source is a contributor-host operational concern (rebuild on flake change, no published-prebuilt dependency); the user-image runner is a runtime concern (pull whatever the user names at the command line). They have different cache lifecycles, different trust policies, different audit shapes. Coupling them was Plan 75's mistake.
- **microvm → OCI export.** The "bidirectional OCI" story (Plan 75 W7) is a separate workstream. It's strategically valuable but doesn't gate the user-image runner. Tracked as Plan 86 (future).
- **OCI-runtime-spec compliance.** Plan 85 pulls OCI **images**; it does not implement `runc` / `containerd` / OCI-runtime-spec semantics. The booted workload runs under libkrun/Firecracker per the existing runtime path, not under an OCI runtime.
- **Private-registry credentials.** Phase D ships anonymous-only pulls. Bearer-token + OS-keyring integration is Phase E (post-launch).
- **`mvmctl image push`.** Push-to-registry comes after the export workstream (Plan 86). Plan 85 is read-from-registry only.
- **Docker-daemon paths.** The existing `crates/mvm-backend/src/docker.rs` "run a Nix-built rootfs as a Docker container" stays untouched. Plan 85 does not load images via Docker; it speaks the OCI distribution wire format directly.

## Phasing — small reviewable PRs, each with explicit security gates

### Phase A — `mvm-oci::layer::unpack` (the load-bearing piece)

**Goal:** take cached layer tarballs (output of W1.2) and assemble them into a directory tree on the host filesystem, with explicit handling of every OCI layer-tar feature documented in the OCI Image Spec v1.1 §"Layer Filesystem Changeset."

#### Sub-phases

- **A.1 — base unpacker, no special features.** Tar entries: regular files, directories, symlinks. **Refused**: absolute paths, paths containing `..`, paths > 4096 bytes. Per-entry path is canonicalized at unpack time *only against the unpack root* — never resolved through symlinks the unpacker itself wrote. Reproducibility: timestamps zeroed by default (configurable via `UnpackOptions::preserve_timestamps`).
- **A.2 — whiteouts and opaque directories.** OCI v1.1 `.wh.<name>` file removes `<name>` from prior/lower-layer state without hiding entries from the same layer. `.wh..wh..opq` clears the parent directory's prior-layer content while preserving same-layer entries regardless of tar ordering. Whiteout-path traversal refused with the same strictness as A.1.
- **A.3 — hardlinks.** Tar `LINK` typeflag (`1`) entries that reference an existing target *within the same layer* are materialized as hardlinks. Cross-layer hardlinks (target absent from this layer but present in lower/prior layer state) materialize as full copies. CVE-2019-14271 mitigation: a hardlink to a non-existent target is **refused**; we don't trust the unpack pre-image to construct hardlink targets retroactively. Hardlink target paths are checked with the same absolute-path, traversal, length, joined-root, and symlink-parent guards as entry paths, and targets must be regular files.
- **A.4 — xattrs (allow-listed).** `SCHILY.xattr.*` pax records for `user.*`, `security.capability`, and `security.selinux` are preserved by default. Everything else is dropped with a warning in `UnpackReport::xattr_warnings`. Configurable per-policy at `UnpackOptions::xattr_policy`.
- **A.5 — device nodes (allow-listed).** Only `/dev/null` `/dev/zero` `/dev/random` `/dev/urandom` are permitted, and only as character devices with their standard Linux major/minor pairs. Any other character/block special file in any layer **refuses** the entry with `RefusalReason::DeviceNodeRefused` / audit tag `device_node_refused`. Defense-in-depth against CVE-2019-14271 and friends.
- **A.6 — setuid / setgid bits, policy-controlled.** Default: preserved with audit annotation via `UnpackReport::setid_entries`. Under `TrustPolicy::Production` *without* cosign verification of the image: callers set `UnpackOptions::setid_policy = SetidPolicy::RefuseUnsigned`, refusing setuid/setgid regular files with `RefusalReason::SetuidUnsigned` / audit tag `E_OCI_SETUID_UNSIGNED`. Under `TrustPolicy::Production` *with* valid cosign: callers set `SetidPolicy::PreserveVerified`, preserving the bits with a cosign-verified audit annotation. The audit annotation lists every setuid/setgid entry's path + mode.

#### Phase A PR boundaries

- One PR per A.1, A.2, A.3, A.4, A.5, A.6. Each PR ships its sub-feature behind a fixture-driven test suite.
- A.1 ships first. After A.1 lands and bakes for one CI cycle, A.2 stacks on top. And so on.
- Each PR adds new fuzz corpus entries; the fuzz lane re-runs cumulatively (Plan 75's 30-min PR-time gate). The corpus is committed under `crates/mvm-oci/fuzz/corpus/<sub-phase>/`.

#### Phase A test surface

| Test | Sub-phase | Layer |
|---|---|---|
| Path traversal: `../etc/passwd` entry → refused | A.1 | Unit |
| Absolute path entry → refused | A.1 | Unit |
| Path > 4096 bytes → refused | A.1 | Unit |
| Symlink target that resolves to escape — symlink itself written, *but* a subsequent entry trying to traverse the symlink → refused | A.1 | Unit |
| Whiteout removes an entry from the assembled tree | A.2 | Unit |
| Opaque whiteout clears prior-layer dir contents | A.2 | Unit |
| Hardlink to within-layer target → materialized as hardlink | A.3 | Unit |
| Hardlink to absent target → refused | A.3 | Unit |
| Cross-layer hardlink → materialized as copy | A.3 | Unit |
| Allowed xattr preserved, denied xattr dropped with warning | A.4 | Unit |
| Allowed device node materializes; refused device node fails unpack | A.5 | Unit |
| Setuid binary preserved under dev policy; refused under prod-no-cosign; audit annotation under prod-cosigned | A.6 | Unit |
| Pulled + unpacked `docker.io/library/alpine:3.20@sha256:<pin>` against hermetic fixture registry → `/bin/sh` present + executable | A.1+A.4 | Integration |
| Reproducibility: unpack same layers twice into clean dirs → byte-identical content-hash | A.1 | Integration |
| Fuzz: `mvm_oci::layer::unpack_one` on malformed tar inputs, ≥30 min per PR | A.1+ | CI gate |

### Phase B — `mvm-build::rootfs::materialize_ext4`

**Goal:** turn the directory tree from Phase A into an `ext4` rootfs image that libkrun can boot. **No host `mkfs.ext4` on macOS**; the formatting happens inside a libkrun VM that already has `e2fsprogs` from its Nix closure (the existing builder VM from Plan 72).

#### Behavior

1. Allocate a sparse file of size `sum(layer.uncompressed_size) * 1.5 + 64 MiB floor`.
2. Hand the sparse file + the unpacked tree from Phase A to the builder VM via the existing virtio-fs mount mechanism.
3. Inside the builder VM, `mkfs.ext4 -F /dev/vda`, mount it, `cp -aR /work/unpacked/. /mnt/`, unmount.
4. The sparse file is now a bootable ext4 rootfs.

#### Why-not-on-host

Plan 85 explicitly avoids host `mkfs.ext4` even though Plan 75 W2's draft had an `MVM_OCI_HOST_MKFS=1` escape hatch. The escape hatch is removed because:

- macOS has no `mkfs.ext4`. On macOS the host path doesn't exist; gating on env var means "fail unless you happen to be on Linux." A consistent libkrun-VM path works on both.
- Host `mkfs.ext4` would shell out to a host binary — adds an additional supply-chain surface for what's otherwise a userspace primitive. Routing through libkrun keeps the supply chain inside the builder-VM image's closure.

#### Phase B PR boundaries

- One PR. Ships the `materialize_ext4` function + integration with Phase A's unpack output.
- The PR adds a smoke test that pulls + unpacks + materializes `docker.io/library/alpine:3.20`, then boots the resulting rootfs.ext4 via libkrun + asserts `/bin/sh -c 'echo hi; exit 0'` succeeds. CI lane is `oci-image-runner-smoke`.

### Phase C — `mvmctl image inspect` / `ls` / `rm` (read-only verbs)

**Goal:** ship the discoverability verbs that operate on the W1.x-shipped cache. These are cheap to add, immediately useful, and reviewable as "does this print/list/delete cache entries correctly?" in isolation.

- `mvmctl image inspect <ref|digest>` — print manifest + config + layer digest list + `mvm-claims.json` annotation if present.
- `mvmctl image ls [--registry <host>] [--json]` — list cached OCI images by ref + resolved digest + fetched-at + size.
- `mvmctl image rm <ref|digest>` — drop a cached image with reference-counted layer GC.

No new security surface; these verbs don't fetch, don't mutate filesystem outside `~/.cache/mvm/oci/`, don't admit workloads. Ships as one PR.

### Phase D — `mvmctl image pull <ref>` + `mvmctl run --image <ref>`

**Goal:** wire Phase A + Phase B + the existing runtime path into the two user-facing verbs.

- `mvmctl image pull <ref> [--prod]`: composes Phase A unpack + Phase B materialize, leaves the resulting rootfs at `~/.cache/mvm/oci/rootfs/<digest>/rootfs.ext4`, registers it as a template (`kind = "oci"`) so the existing `mvmctl up` machinery sees it.
- `mvmctl run --image <ref> [--prod]`: equivalent to `image pull` + `up` in one verb. Audit-chain entry per Phase E.

The `--prod` flag flips trust policy: refuse mutable tags (require `@sha256:...` pinning), refuse setuid without cosign, demand explicit registry policy (per Phase F).

### Phase E — Audit-chain claim 10 (flip to Enforced)

**Goal:** every `mvmctl run --image` admission emits a chain-signed audit entry recording the OCI provenance. The claim file is already on `main` (Plan 75 W0 left it); Plan 85 wires the producer side.

- Audit entry fields: registry host, repo, reference (as supplied), resolved manifest digest, layer digest list, trust policy, cosign verdict (verified | unsigned | refused | not-configured).
- `mvmctl audit verify` keeps detecting chain drift — byte-flip an OCI-provenance entry → chain invalid, same as for existing claim 8 entries.
- Claim 10 file flips from "Planned" to "Enforced." `check-no-overclaim` lint enforces no docs reference the property until Phase E lands.

Ships as one PR after Phase D.

### Phase F — Cosign verification + per-registry policy

**Goal:** trust establishment so `--prod` is defensible.

- Verify cosign signatures against project-pinned keys at `~/.mvm/cosign-pubkeys/*.pem`.
- Optional sigstore (fulcio + rekor) verification, gated by `~/.mvm/registry-policy.toml::cosign_use_sigstore = true`.
- Per-registry policy file at `~/.mvm/registry-policy.toml` (mode 0600): registry → trust policy mapping, cross-origin redirect allow list, `prod_unsigned_allow = [...]` for explicit ops admission of unsigned registries.

Ships as one PR after Phase E.

### Phase G — Optional bearer/keyring auth

**Goal:** support private registries via OS keyring (macOS Keychain, Linux Secret Service). **Never** read `~/.docker/config.json` — that file has credential-helper escape hatches that shell out to arbitrary binaries; out of scope for our trust posture.

Ships as one PR after Phase F.

## Security envelope (preserved from Plan 75, scoped to user-image runner)

CLAUDE.md security claims affected:

- **Claim 6 extension** (already drafted in Plan 75 W0): "Every OCI image is content-addressed-digest-verified before any byte is consumed." Phase A enforces.
- **Claim 10 (new, file already on main)**: "OCI image provenance is recorded in the admission audit chain." Phase E enforces.
- **No changes to claims 1–5, 7–9.** The Plan 85 path never touches the runtime workload's security model (signed plans, audit chains for plan admission, sealed deps volumes). It's an additional admission point with its own audit shape.

Threat model additions (T-OCI-1 through T-OCI-5 from Plan 75) carry over verbatim. They're well-stated and don't need redrafting:

- T-OCI-1: Compromised registry → mitigated by digest pinning + cosign when configured.
- T-OCI-2: Layer-unpack CVE class → mitigated by allow-listed unpacker + fuzz + libkrun isolation defense-in-depth (the unpacked rootfs runs in a microVM, not on the host).
- T-OCI-3: Tag mutation race → `--prod` refuses unpinned refs.
- T-OCI-4: TLS substitution / DNS rebinding at pull time → HTTPS-only, SNI pinned, system CA + optional pinned-CA bundle, no DoH/DoT bypass.
- T-OCI-5: Supply-chain via base image → audit-chain records the pin; rotation is a deliberate PR-reviewed action.

## What does NOT change

- `mvmctl dev up` (Plan 77 path).
- The existing Nix-flake → libkrun → microvm runtime path.
- CLAUDE.md "Host Nix is never used by `mvmctl` at runtime" (mvm-oci has no Nix dep).
- ADR-046's two acquisition paths (source checkout vs installed binary).
- The vendored seed slot under `nix/images/dev-prebuilt/<arch>/` (Plan 77).

## Risks

### R1 — Layer-unpack CVE class (carries over from Plan 75 R1)
Mitigated by:
- Defense-in-depth: unpacked tree consumed inside libkrun, not on host.
- Per-sub-phase PR review (A.1 through A.6) — narrow review surface per merge.
- Dedicated fuzz lane on `mvm_oci::layer::unpack_one`, ≥30 min per PR-on-mvm-oci.
- Adversarial fixture suite covering every documented CVE pattern (CVE-2019-14271, path traversal, symlink escape, hardlink chains, setuid surprise, xattr privilege carry).
- Default-deny policies for setuid (without cosign in prod), device nodes (4-allowed-only), xattrs (allow-listed).

### R2 — Reproducibility of imports (Plan 75 R4)
Carries over. Mitigation: timestamps stripped by default; CI gate `oci-reproducibility` asserts byte-identical rootfs.ext4 on consecutive pulls.

### R3 — Phase A is multi-PR — partial-merge state needs careful gating
Mitigation: each sub-phase's unpacker function is `#[cfg(not(feature = "oci-image-runner"))]`-fenced **off** by default. Phase D's `mvmctl run --image` only compiles when `oci-image-runner = []` is enabled. Until A.1 through A.6 all land + Phase B is wired, the feature flag stays off in default builds. CI runs both flag-on and flag-off matrices.

### R4 — Cargo-fuzz CI cost (Plan 75 R8)
Carries over. Mitigation: 30-min fuzz gate runs *only* on PRs touching `crates/mvm-oci/**`; other PRs run a 1-min corpus replay. Daily CIFuzz lane runs long-form.

### R5 — Trust-boundary widening if cosign is partial-coverage (Plan 75 R2)
Carries over. `--prod` requires cosign by default; per-registry `prod_unsigned_allow` opt-in with audit-chain recording.

## Acceptance criteria (whole-plan)

When all hold, Plan 85 moves to `specs/backlog/`:

1. `mvmctl run --image docker.io/library/alpine:3.20@sha256:<pin>` boots Alpine as a microvm and runs `/bin/sh -c 'echo hi'` to completion on macOS Apple Silicon **and** Linux KVM.
2. `mvmctl run --image docker.io/library/alpine:latest --prod` refuses with `E_OCI_MUTABLE_TAG_PROD`.
3. `mvmctl audit verify` after a sequence of `image pull` + `run --image` invocations reports the chain valid; byte-flipping an audit entry breaks the chain.
4. CI lanes pass:
   - `oci-layer-unpack-fuzz` (≥30 min, per-PR-on-mvm-oci)
   - `oci-layer-unpack-adversarial` (every PR, fast)
   - `oci-digest-mismatch-reject`
   - `oci-malformed-manifest`
   - `oci-mutable-tag-prod-reject`
   - `oci-reproducibility`
   - `oci-image-runner-smoke` (Phase B onward)
5. CLAUDE.md claim 6 extension and claim 10 are wired to enforcing CI gates (no `check-no-overclaim` exemptions).
6. `cargo metadata` shows zero crate hits for the removed predecessor sandbox (already true post-`b02a5e8`; Plan 85 doesn't regress this).

## Why Plan 75 is retired, not amended

The b02a5e8 cleanup deleted the Plan 75 spec same-day it merged. That's a strong signal — whoever ran b02a5e8 was retiring the document. Two paths from there: re-litigate the deletion (restore the spec, fight that battle), or write a fresh plan that captures what's still right about Plan 75 and explicitly drops what isn't.

Plan 85 takes the second path. It carries forward Plan 75's security envelope verbatim (the threat model, the allow-list philosophy, the fuzz lane, the audit-chain integration) but jettisons two structural mistakes:

1. **Stage 0 entanglement.** Plan 77 won. The "mvm-oci ALSO replaces the removed predecessor sandbox in Stage 0" coupling was Plan 75's load-bearing reason for existing; it no longer applies. Stage 0 is Plan 77's vendored-seed path, and mvm-oci is a user-facing primitive. They share `crates/mvm-oci/` as a library but no runtime coupling.
2. **Big-bang phasing.** Plan 75's W2 was one PR for the entire unpacker. Plan 85's Phase A is six sub-PRs (A.1–A.6) each with its own fixture suite + corpus. Each merge is reviewable in an afternoon; six small reviews beat one giant one.

The trust shift Plan 75 documented (registry pull as a new security surface, cosign as the trust establishment, audit-chain claim 10 as the non-repudiation hook) is correct and unchanged. The phasing is what's new.

## Open questions

1. **OCI image-index handling.** Multi-arch images. Phase A.1 picks the matching `architecture` exactly; refuses `variant` ambiguity (e.g. `linux/arm64` vs `linux/arm64/v8`). Recommended deferral to Phase A.2 if the fixture registry doesn't return an index manifest for the alpine pin.
2. **Cache GC policy.** Reference-counted layers — `mvmctl image rm <ref>` decrements; `mvmctl cache prune` GCs orphans. Phase C ships the `rm` verb; the prune side stacks on the existing `mvmctl cache prune`.
3. **Phase B's "boot the builder VM to run mkfs"** — does the builder VM need to be running already, or should Phase B spawn its own builder VM? Recommend: reuse the existing builder VM if one is up; spawn ephemerally if not. Either way the resulting rootfs.ext4 is content-addressed-cached so the builder VM round-trip is one-time per image.
4. **Should Phase A's unpack output live in `~/.cache/mvm/oci/unpacked/<digest>/`?** That's a per-image directory tree (gigabytes of small files for large images). Alternative: skip the directory-tree intermediate, stream directly into a partially-mounted ext4 image inside libkrun. Phase A's first cut targets the directory tree for testability; Phase B may refactor toward the streaming approach if Phase A's disk-use proves unacceptable.

## Why this plan is worth doing now

1. mvm-oci W1.1/W1.2 are already on `main` and being maintained. The Phase A unpack work is the next blocking dependency for any user-facing image-pull claim; it's the load-bearing piece nobody can route around.
2. The user-facing image runner is a category-defining feature for mvm. "I can build with our flakes" is the current promise; "I can also run any OCI image you give me as a hardware-isolated microvm with the same admission audit guarantees that apply to my Nix workloads" is the strategic promise. Plan 85 ships it.
3. The phasing structure means we get something useful at every PR boundary: Phase A.1 ships a usable layer-unpack primitive; Phase C ships `mvmctl image inspect/ls/rm` independent of unpack; Phase D ships the user-facing runner. Each ship is small, reviewable, reversible.
