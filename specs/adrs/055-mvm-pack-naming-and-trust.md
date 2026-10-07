# ADR-055: Workload packs use publisher namespaces and explicit trust

Backing: preview
Validation: none

## Status

Accepted, 2026-10-06. Design: `specs/plans/2026-10-06-mvm-packs.md`.
Delivery: [#3716](https://github.com/tinylabscom/mvm/issues/3716).

## Context

The public word “pack” currently describes the attested MVM artifact cache,
the extension protocol, and registry-delivered policy packs. The current
registry default trusts the old publish identity only for `agent/` and
`runtime/`; it does not trust `mvm/`. Registry names such as `agent/claude`
classify content rather than identify its publisher. An image-source digest
does not identify the built image. The
repository name is part of the keyless signing identity, so a repository
rename is a trust rotation.

## Decision

Use “pack” for an immutable, signed workload distribution with a prepared
environment, policy, and declared applications. Reserve `mvm/` for packs
verified under an MVM-controlled release identity and a current signed
revocation document. Until that revocation check exists, the built-in policy
does not trust `mvm/` and no pack is labelled official. No wildcard may
convey official status. Community namespaces require their own explicit
publisher trust. A signature proves publisher and integrity, not safety.

The owner renamed `tinylabscom/mvm-templates` to `tinylabscom/mvm-packs` on
2026-10-06. The repository already publishes signed packs, while its
remaining unsigned templates become examples or pack-aware scaffolds. The
rename changes the publish workflow's keyless identity; it does not change
the identity in existing signature bundles. The old identity remains the
only built-in authority until an explicit trust migration is approved and
shipped. A transition may accept the new identity for legacy `agent/` and
`runtime/` references while retaining the old one only for a documented
cutoff period, or may re-sign existing artifacts first. Neither path grants
`mvm/` trust before revocation enforcement. A URL redirect never establishes
signing authority.

The workload pack CLI becomes `mvmctl pack info|verify|pull|run|ls|rm|update`.
The attested builder/runtime/image-project cache moves under `pack system`,
with existing verbs retained temporarily as compatibility aliases. The
extension-pack protocol keeps its qualified name. Internal Rust modules may
migrate incrementally from `registry_pack` to workload-pack naming after public
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
verified rotation or re-publication. A new-identity publish must not replace
the legacy registry before compatible client trust ships; official `mvm/`
publication also requires revocation enforcement. ADR-054's pack producer is
the renamed repository; its Linux-layer boundary is unchanged.
