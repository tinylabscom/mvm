# Architecture — composable pack builds

Decision: compose runtime layers at package-build time into one self-contained
application `.mvmpkg` per architecture. A closed runtime-layer descriptor
parser, publisher-authenticated metadata dispatch and exact-byte private
archive snapshot exist in source. Strict isolated tar staging and bounded,
dependency-first resolution of authenticated runtime metadata also exist,
as does bounded composition of authenticated runtime tar inputs into a private
filesystem tree. A producer-side signed base composition tar and
consumer-side authenticated fetch/base-plus-runtime composition are implemented
in source for future Linux sets. Application input, policy, archive installation,
authoring and final non-Nix `.mvmpkg` production are not integrated; no base
tar has been published or boot-witnessed. This decision does not authorize
publication or change existing signed pack versions.

## Problem and goals

An author describes one sandbox once. A development build is the default; an
explicit production build freezes and checks every input before it can produce
a signed, self-contained `.mvmpkg`. A `runtime/*` pack contributes reusable
software and policy, not another VM or another entrypoint. An application pack
contributes the single entrypoint. For example, composing `runtime/python` with
a Python application yields one VM with both programs and one application
entrypoint.

`mvm-images` owns the generic, signed Linux base. It does not grow per-runtime
roles. `mvm-packs` owns immutable versioned pack descriptors, signed layer
inputs and their policy. `mvm` owns authoring, resolution, composition, the
final workload archive and consumer admission. No package build publishes a
new Linux base.

The priorities are simple authoring, fast cold and repeat package builds,
small generic Linux bases, and no regression in offline verification or the
guest's isolation. "Small" describes unnecessary base and builder overhead;
a required Python or agent binary still occupies space in the final archive.

## Approaches considered

| Composition | Benefit | Cost |
| --- | --- | --- |
| **At package build (chosen)** | One existing-style sealed rootfs and one offline-bootable archive; runtime input resolution and assembly can be cached separately | Runtime bytes recur in distinct final application archives |
| At VM boot | Potential sharing of independently sealed runtime disks | New boot ABI, multi-disk integrity and mount ordering; embedding the disks still costs bytes in a self-contained archive |
| At install from external references | Smaller individual application downloads if runtimes are cached | No single self-contained file; offline use and trust depend on external installed layers |

Keep the builder implementation in Rust and use the current filesystem,
verity, bundle and admission code. Nix remains a compatible producer, not
the required resolver or default package-build path. The generic Linux base
continues to be produced and signed by `mvm-images` on its own cadence;
choosing Buildroot instead of Nix for that base is an independent experiment.

## Representations and ownership

1. The authored, versioned pack spec says what to include and what the workload
   requests. A small, strict TOML front end and the language SDKs produce the
   same neutral spec; TOML is not a second execution IR. Common fields are
   safe for both modes. Development-only configuration is never inherited by
   production. Production requires an explicit mode selection and refuses
   incomplete inputs. Keep `[production]` as the one spelled-out table name;
   avoid an equivalent `[prod]` alias. Existing `mvm.pack-spec/v1` and lock
   bytes retain their current meaning, including their current sealed build
   behavior; the new default requires a new versioned contract.
2. The existing Workload IR says what runs. It has one final command entrypoint
   and the resources and capabilities the workload requests. A runtime layer
   cannot introduce an entrypoint or a host grant.
3. A resolved build plan says which exact bytes to assemble. It binds the
   target architecture, accepted signed base-image-set root, an ordered list of
   version-and-manifest-digest-pinned runtime layers, the application input,
   every external source digest, and the compiler/producer versions. A
   versioned lock records this resolved plan; an unpinned input cannot enter
   production. The signed final artifact records the resolved inputs and
   hashes of its output bytes. A changed authoring file, selected layer,
   compiler or producer invalidates the relevant lock/cache key.

The neutral `mvm.pack-spec/v2` contract and Rust SDK TOML front end now parse
this narrow first slice without changing v1: one local application, an ordered
list of `runtime/*` requests, `/srv/app` copies, literal absolute argv and
resource requests. Development is the default; `[production]` is an explicit
opt-in, not a grant or a completed frozen lock. Unknown networking, host grants
and signing fields are rejected. For example:

```toml
schema = "mvm.pack-spec/v2"
target = "aarch64-linux"
runtimes = ["runtime/python"]
entrypoint = ["/usr/bin/python3", "/srv/app/main.py"]

[identity]
name = "agent/example"
version = "1.0.0"

[source]
kind = "local"
path = "."

[[copy]]
source = "main.py"
destination = "/srv/app/main.py"

[resources]
cpu_cores = 1
memory_mb = 256
```

Adding `[production]` at the end expresses intent but does not currently
make `mvmctl pack build` consume v2; that CLI still requires v1 and Nix.
Authenticated runtime requests can now be resolved in exact dependency order
and checked against candidate archives. The shared compiler snapshots only
declared application copies (or the full source when `.` is copied), then
rehashes those inputs without Nix; unrelated files do not invalidate the v2
snapshot. The Rust SDK can package that held tree as a deterministic gzip tar
and reverify both the staged files and archive bytes. The private composer
now requires each requested runtime's signed archive and policy-file snapshots
together; a raw verified tar without those policy bytes cannot create a
production-authored lock. It accepts one digest-bound application tar only
under `/srv/app` and emits an ext4+verity candidate. An explicitly
production-authored candidate can produce
a versioned input record binding the spec, supplied source/revision, selected
profile, signed base root, runtime pins and application archive. This is not
yet a CLI-frozen build: source and producer-revision custody, health boot and
signed archive remain required.

Separate the producer from the builder-VM backend. A producer may use Nix,
verified OCI content or pinned native payloads to make candidate filesystem
content, but it cannot sign, grant policy or publish. Reuse the existing
materialization, verity, exact-byte health boot, verifier and bundle signer
after all candidates pass the same output contract. Signing keys and
publication credentials never enter a builder or an authored spec.

## Layer, archive and trust boundaries

Prefer a new `runtime_layer` registry kind over widening the bootable
`.mvmpkg` parser to accept kernel-less inputs. A versioned registry-signed
manifest binds a deterministic, bounded external layer tar by canonical
HTTPS or digest-pinned OCI source, SHA-256 and size. Only the small policy
documents live under the registry's `files/` tree; a multi-GiB tar cannot
live in Git. The signed descriptor also binds the target architecture,
immutable pack identity and declared runtime dependencies. The tar carries
filesystem entries only: no kernel, initramfs, entrypoint, network setup,
whiteouts or executable install script.
Reuse the existing hardened OCI-layer unpacker as far as its safe subset fits,
and reject paths, file types or metadata it cannot faithfully represent.
The registry manifest signature covers the tar digest, so a second layer
signer is unnecessary. This new kind requires a producer and consumer
contract; existing policy and application manifest bytes keep their meaning.

The first descriptor parser accepts outer `schema_version = 3`, kind
`runtime_layer`, an exact `runtime/*@version` reference and description;
`runtime_layer` carries schema 1, guest architecture and an ordered list of
exact manifest-digest-pinned `runtime/*` dependencies and an `archive`
object with `source`, `archive_sha256` and `archive_size`. Its `files`
inventory contains at least one of `pack/group.toml` or
`pack/profile.toml`, each with a digest and positive size. It rejects
unknown fields, extra file paths, duplicate files, self-dependencies,
non-runtime dependencies, and more than 16 direct dependencies. The
external tar is bounded to 2 GiB; producer and consumer must also bound
its unpacked contents. Parsing alone does not authenticate a publisher;
the distinct registry dispatch does, and the snapshot checks the
descriptor-pinned external size and hash. A separate staging step refuses
unsupported tar entry types, duplicate paths, whiteouts, setid bits, xattrs
and over-budget contents, and protects host-owned guest paths such as
`/etc/mvm`, `/mvm`, `/dev` and `/etc/resolv.conf`. It does not merge a layer
with the Linux base or admit it as a runnable image. The `mvm-packs`
publisher owner has aligned its unpublished producer branch to this shape.
One architecture per version is sufficient for the first Python spike;
multi-architecture fan-out requires a separately versioned schema decision.

The package builder verifies each selected layer's registry publisher,
manifest signature, file digest, revocation and exact lock pin *before*
reading its files as build input. Signed `pack/group.toml` and
`pack/profile.toml` bytes must be snapshotted and verified as well as the
external tar; neither a catalog hash nor an unverified local policy file can
stand in for the publisher's signed manifest. Policy composition must keep
the signed layer origin and deny/ceiling semantics until host admission.
The protected final signer independently
checks the frozen input evidence and the output selected for health boot,
then signs a complete application `.mvmpkg`. The recipient authenticates
that final archive, its registry pin and current admission policy; it does
not need the original layer registry or source tree at boot. The signed
final manifest records the input layer manifests and output digests so a
later runtime-layer revocation can refuse derived application bundles.
An offline production consumer must preserve the existing freshness rules
for revocation evidence. The final publisher's signature is not proof that
an unverified upstream layer was safe or reproducible.

Keep the registry's keyless publisher identity and the bundle's independently
enrolled Ed25519 key as two separate trust roots. A versioned in-file keyless
signature, signed build-provenance statement and pack/policy trace identities
are proposed by `mvm-packs` ADR 004, not yet shipped by this candidate path.
Do not label a local resolved lock or host-signed archive as those statements.
The final format needs to bind the producer revision, exact runtime manifest
and policy hashes, base root, generated artifact hashes and health-boot subject
under the same independently verified provenance and admission rules; if the
consumer cannot verify them, it must refuse production.

## Composition and security rules

- Resolve runtime references to immutable, authenticated versions before
  composition; reject duplicates, cycles, architecture mismatches, revoked
  dependencies and a changed manifest digest. The resolution order is fixed
  and recorded in the lock.
- Materialize the signed Linux base, then each runtime layer in locked order,
  then the application. For the first format, reject overlapping file paths
  rather than allow a later layer to silently replace an earlier one. Refuse
  symlink escapes, special files, missing dynamic loaders, unbounded archives
  and unverified bytes. Keep build tools out of the final rootfs unless the
  workload explicitly needs them.
- Exactly one application owns the entrypoint. Runtime layers may contribute
  binaries, libraries and declared logical requirements. Compose policy by
  field using the existing policy rules: requested allows combine, denials
  prevail, resource ceilings take the minimum, and secret destinations may
  only narrow. Check the signed application ceiling and intersect the request
  with host-authorized grants at admission; a pack's request never grants itself
  access. The host remains the authority for actual grants and secret values.
- Neither development nor production has a guest NIC, SSH, port forwarding,
  guest NAT or a network fallback. Any permitted egress uses the authenticated
  host-mediated FlowMux path. Development may request a user-authorized
  writable workspace; production cannot inherit that request or install
  dependencies on first boot.
- The final `.mvmpkg` contains everything needed for offline verification and
  boot: the selected kernel and initramfs, the composed rootfs and verity
  material, its signed environment and provenance, and all required runtime
  bytes. A registry descriptor separately pins that exact archive. Runtime
  layers can be cached and reused while building, but the recipient need not
  have those layers in its cache to run the final archive.

## Missing pieces

The v2 authored contract accepts only a local source today; its TOML parser
does not lower to Workload IR or write/read a frozen lock in the CLI. Its
runtime requests can be bound to authenticated, ordered descriptors and
checked again before
base-plus-runtime candidate composition. The v1 pack lowering still
selects Nix packages. The frozen v1 lock pins a compiler revision, not a
graph of independently authenticated layers. `mvmctl pack build` currently
boots a Nix-built slot and its exported environment has no pack policy, secret
slots, volumes or capabilities. Authenticated runtime-layer metadata and
external archive and declared policy bytes can be verified in source, and
authenticated dependency pins can be ordered with cycle, architecture,
digest, duplicate-name and revocation checks. A build-only acquisition API now
accepts an exact caller-supplied pin, publisher-authenticates the descriptor,
requires fresh revocations, and holds the signed archive and policy bytes in
private snapshots. Its first remote transport accepts only mvm-packs HTTPS
GitHub release assets; the signed digest, not the release URL, makes their
contents immutable to the builder. OCI and other HTTPS origins fail closed until a
separately reviewed transport exists. For the first Python slice both local
and remote build-input acquisition refuse anything but a signed deny-all group
with `required = true`, no profile, network routes, secrets, shares, tools, environment overrides
or resource requests. This is a first-slice restriction, not the general
policy-intersection algorithm, and host admission must independently enforce
it before a package can run. It neither freezes a v2 CLI lock nor
installs an image: `pack registry pull` and the installed-pack reader still
refuse a runtime layer. A signed base tar can be fetched separately
from the boot artifacts and merged with runtime archives in order without
replacing base-owned files, retaining tar ownership under one aggregate size
and entry budget. A digest-bound application archive can be added under
`/srv/app` and emitted as an ext4+verity candidate. Its resolved input record
is not a cache install or a runnable bundle: source custody, symlink closure,
policy, release proof and health boot still require final checks.
The workload bundle needs a versioned, signed composition member that
binds runtime manifest pins for transitive revocation checks; old bundle
schemas remain unchanged. Coordinate its schema floor with the separate
universal-pack work in `mvm-packs` ADR 004 (builder version, policy and
keyless provenance members), rather than independently claiming the next
number. Carry one typed composition member, not reuse the v7 `other` role
as an implicit grant. Its Ed25519-signed manifest binds the authored
spec/source/producer lock, selected signed Linux root, ordered runtime manifest pins, policy
digests, output artifact hashes and health-tested entrypoint. Embed each
runtime's original keyless-signed descriptor, signature bundle and declared
policy document as small digest-bound bundle artifacts; a clean offline
recipient must verify both publisher and bundle trust roots and check
current revocations for every pinned layer before admission. The final
package carries the composed rootfs and CLI runtime itself, not an external
layer fetch dependency. Missing evidence, ambiguous policy, changed
bytes or an old-schema bundle claiming composition must refuse, never fall back
to an unsigned local cache or guest install script. This is a source
contract, not a completed exporter or consumer.
The CLI must not interpret any new source, mode or layer field as optional
and silently fall back to Nix. A local production-mode build is not an
official published release merely because it is sealed and host-signed.

The format owner is `mvm`, coordinated with the `mvm-packs` publisher owner.
The registry producer and consumer must learn the new layer kind together
before any layer is advertised as supported. Do not mutate existing
application or policy-only manifests to imitate it.

## Spike and decision rule

The first **unsigned** x86_64 Python source experiment is
[`scripts/build-python-runtime-layer.py`](../../scripts/build-python-runtime-layer.py).
It accepts only the SHA-256-pinned `cpython-3.13.18+20261026`
`x86_64-unknown-linux-musl-lto+static-full.tar.zst` from the Astral
python-build-standalone release (`e0bb0840e127aa95dbb1212202a29cde715711ae6826132e548f5eb04a958533`).
It repacks the static interpreter and runtime-only standard library as a
deterministic plain `layer.tar`; it does not run untrusted install scripts,
sign, publish, or grant policy. The interpreter has no ELF `PT_INTERP` loader.
Independent macOS and Linux runs produced SHA-256
`9f5dfaf983a54a62212184f08f5dfc36d1474052d71a799cdfd3f1a53dc970d4`
and 63,836,160 bytes; the signing smoke pins these output bytes.
The upstream GitHub asset digest establishes *byte identity*, not an
independent publisher-signature or reproduction claim. A production publisher
must accept that upstream trust choice explicitly, sign a new
`runtime/python@1.1.0` descriptor binding the actual output SHA-256 and size,
and pass the consumer and exact-archive boot gates. The historical revoked
policy-only `runtime/python@1.0.0` is not reusable.

Keep the Nix producer working unchanged. Resolve one authenticated Python
runtime input into a runtime layer, add a small Python application as a distinct
input and produce one candidate with one entrypoint without invoking Nix in the
package-build path. Compare against the current Nix path using the same
application and target: cold and warm elapsed build time, fetched bytes, cache
reuse, generated archive size, and guest boot. Report the input acquisition
time separately from filesystem assembly and signing time.

Choose this producer path for the next package class only if it boots the
exact self-contained archive, preserves all trust and isolation checks, and
improves measured end-to-end build time or complexity without an unacceptable
size regression. Otherwise retain Nix for that class and identify the costly
stage before adding a different producer. The accepted build-time composition
decision does not depend on Buildroot winning the separate base-image test.

Before calling the path production-ready, reproduce the unsigned payload
bytes in independent builds, verify the pinned base and every runtime input,
boot the composed image and execute Python from the final archive on both
supported architectures, then demonstrate refusal on tampered layers, missing
loaders, stale locks, conflicting paths, widened policy and a changed tested
artifact. Signing timestamps and externally supplied signatures are not
payload reproducibility evidence. Do not infer publication or a supported
release from source-only tests.

## Open questions

- Future Linux sets add a deterministic, signed `rootfs.tar.gz` artifact
  alongside each production default/rootless ext4 member. The producer makes
  both from the same fakeroot tree; the existing 17 members and historical ext4
  bytes are unchanged. The consumer selects the tar only through the verified
  set root and refuses missing bytes or changed digests. Reproduction of
  published bytes and signed-set admission still need native CI evidence;
  the ext4 tree-diff reader cannot substitute for this tar without losing
  ownership and xattr fidelity.
- Linux Docker builds produced both default and both rootless base tars
  (native aarch64, emulated x86_64) from the local Nix definitions.
  The default tars materialized in Rust on macOS to ext4+verity candidates
  with zero file, path or mode differences from their respective Nix ext4s.
  The rootless tar contains case-distinct paths that APFS cannot stage
  faithfully: Rust refuses it instead of signing a changed image. Route
  rootless (and any similarly colliding runtime) through a case-sensitive
  Linux execution boundary. The emulated x86_64 build needed Nix's inner
  syscall filter disabled for local validation; neither Docker build is
  release reproduction or boot evidence.
- Requested egress composition and host grant semantics have conflicting
  descriptions in the pack ADR, PRD and merge guide. The effective policy
  needs one tested, signed, fail-closed rule before production composition.
- The spike determines whether a pinned, signature-verified OCI Python
  userspace is both faster and smaller enough than the current Nix closure.
  Native Claude payload redistribution is a separate permission and
  loader-compatibility gate, not a prerequisite for the Python spike.
