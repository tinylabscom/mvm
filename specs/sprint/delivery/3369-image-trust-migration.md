# Image trust migration delivery (#3369)

## Published root

- Repository: `tinylabscom/mvm-images`
- Release: `image-set/v0.1.0`
- Root: `image-set.json`
- SHA-256: `9bb4f0bf01895b9ebda51f6f574cfa2902ae79e1bb4404c4665942aa4ecbf2ff`
- Certificate identity:
  `https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/image-set/v0.1.0`
- OIDC issuer: `https://token.actions.githubusercontent.com`
- Compatibility: guest-agent protocol `2..=2`, builder-cache contract `4`

The root is a complete schema-v2 train for both supported architectures plus
the architecture-independent QEMU-WASM pack. Offline `cosign verify-blob`
against the exact identity succeeds.

## Consumer migration

`crates/mvm-core/images.lock` is the single current-release selection. Its
schema binds the root repository/tag/digest/identity, compatibility declaration,
default image tag, and both Stage 0 artifacts to one release. Parse-time checks
refuse repository or tag drift among those routes. The previous `mvm`
boot-image release and signing identity remain in the explicit `legacy` entry;
they are not an implicit fallback.

The acquisition boundary verifies the raw root digest, exact publisher
identity, manifest structure, lock match, complete-train requirement and host
protocol overlap before requesting any member. It then verifies every member's
declared size and digest. Default workload metadata is derived locally from the
signed root because the published root does not declare the older standalone
metadata sidecar.

The same boundary serves release builder/default images and workload kernels.
Stage 0 uses its per-architecture member digest from the same lock and performs
the shared compatibility check before cache access or transport. Image update
accepts only the compiled pin, while image check compares the cache with that
pin rather than discovering a mutable latest release. CI and WebLinux read the
repository, tag, root digest, workflow and tag ref from the lock, verify the
root, check compatibility, then verify member digests.

`.github/workflows/update-image-pin.yml` discovers a candidate, verifies its
exact tag-bound signature and compatibility, updates the single lock, and opens
or refreshes a PR whose body records the root digest, source commit, protocol
contract and signature evidence. Tests forbid merge or auto-merge operations
in that workflow.

## Evidence and remaining acceptance

Locally achievable checks cover the signed-root digest and wrong-identity
refusals, incompatible-protocol refusal before transport, single-lock routing,
atomic cache preservation, workflow action linting, and the no-auto-merge
invariant. Full repository gates are recorded with the delivering change.

The declared revocation URL currently has no published producer document; its
first publication must occur in `mvm-images`. Physical Apple Silicon HVF and
Linux KVM/Firecracker boots are hardware-only acceptance and are not claimed by
the host-only test run.
