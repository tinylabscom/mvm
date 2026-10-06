# ADR-055: Workload packs use publisher namespaces and explicit trust

Backing: preview
Validation: none

## Status

Proposed, 2026-10-06. Design: `specs/plans/2026-10-06-mvm-packs.md`.
Delivery: [#3716](https://github.com/tinylabscom/mvm/issues/3716).

## Context

The public word “pack” currently describes the attested MVM artifact cache,
the extension protocol, and registry-delivered policy packs. The default
registry trust accepts one publish identity in every namespace. Registry
names such as `agent/claude` classify content rather than identify its
publisher. An image-source digest does not identify the built image. The
repository name is part of the keyless signing identity, so a repository
rename is a trust rotation.

## Decision

Use “pack” for an immutable, signed workload distribution with a prepared
environment, policy, and declared applications. Reserve `mvm/` for packs
verified under an MVM-controlled release identity and a current signed
revocation document. No wildcard may convey official status. Community
namespaces require their own explicit publisher trust. A signature proves
publisher and integrity, not safety.

Recommend renaming `tinylabscom/mvm-templates` to `tinylabscom/mvm-packs`:
the repository already publishes signed packs, while its remaining unsigned
templates become examples or pack-aware scaffolds. The repository rename and
production signing-identity change require a separate owner confirmation.
Until then, the old repository and identity remain the only production
authority. The CLI must accept both identities only through a time-bounded,
signed rotation rule, or re-sign existing artifacts; a URL redirect never
establishes signing authority.

The workload pack CLI becomes `mvmctl pack info|verify|pull|run|ls|rm|update`.
The attested builder/runtime/image-project cache moves under `pack system`,
with existing verbs retained temporarily as compatibility aliases. The
extension-pack protocol keeps its qualified name. Internal Rust modules may
migrate incrementally from `registry_pack` to `workload_pack` after public
behavior is stable.

Pack policy is a signed, versioned payload. Effective grants are bounded by
the pack, application, explicit invocation, user policy and host constraints.
Pack-authored secret bindings are requests, not authority: execution names
the stored binding and destination and requires an explicit invocation grant.
The signed plan records pack and application identity and digest; admission
re-verifies the artifact and audit records the decision. Verification fails
closed when any signature, digest, identity or current revocation status
cannot be established.

## Consequences

The new namespace and CLI verbs require migration guidance for existing
lockfiles, `run --policy` references and the current `pack registry` syntax.
Existing signatures remain bound to the old workflow identity until a
verified rotation or re-publication. Publication cannot precede the trust and
revocation implementation. ADR-054's pack producer is interpreted as this
repository's successor after an approved rename; its Linux-layer boundary is
unchanged.
