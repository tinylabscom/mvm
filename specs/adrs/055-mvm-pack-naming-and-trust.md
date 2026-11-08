# ADR-055: Workload packs use publisher namespaces and explicit trust

Backing: preview
Validation: none

## Status

Accepted, 2026-10-06. Design: specs/plans/2026-10-06-mvm-packs.md (retired; recover from tag specs-archive-2026-11-02).
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
revocation document. The built-in check uses the distinct MVM release workflow
identity
`https://github.com/tinylabscom/mvm-packs/.github/workflows/registry-pack-revocations.yml@refs/heads/main`
under the GitHub OIDC issuer. It has a separate private cache and checkpoint
from operator-configured feeds. A fresh signed document is required at
installation and every execution; absence, expiry, invalid signature,
revocation, and rollback fail closed. The first release imports the signed
document explicitly rather than silently fetching it. Rotation of this
identity requires a deliberate client trust update. The official feed's signed
validity interval may be at most 30 days; the authenticated `not_after` remains
the exact expiration boundary. Operator-configured feeds retain their 48-hour
maximum. Publication should refresh the official feed before expiry rather
than rely on the full validity interval for routine availability. A release
identity rotation requires a client version that trusts both exact identities
and at least 14 days of overlapping publication: the same feed document and
sequence are signed by both identities, with independently verifiable bundles.
The overlap ends only after the new identity is accepted by supported clients;
compromise may require earlier revocation and fail-closed interruption. This
rotation protocol is a producer requirement, not a claim that a dual-signed
feed is published today. Rotate annually and on compromise. The dedicated
producer uses release tag `registry-pack-revocations` in `tinylabscom/mvm-packs`
and assets `revocations.json` and
`revocations.sigstore.json`. Its first sequence is 1; it does not inherit the
publisher-signed `packs/` feed as a revocation checkpoint. The earlier draft
`tinylabscom/mvm` revocation workflow is retired, not a second trusted root.
This client trust change does not establish a live feed: the dedicated producer
and matching client must still be released. No wildcard may
convey official status. Community namespaces require their own explicit
publisher trust. A valid signature authenticates publisher identity and
artifact integrity; it says nothing about safety.

The owner renamed `tinylabscom/mvm-templates` to `tinylabscom/mvm-packs` on
2026-10-06. The repository already publishes signed packs, while its
remaining unsigned templates become examples or pack-aware scaffolds. The
rename changes the publish workflow's keyless identity; it does not change
the identity in existing signature bundles. On 2026-10-07 the owner approved
built-in trust in both exact workflow identities for legacy `agent/` and
`runtime/` references. The former identity expires at 2026-11-06 00:00 UTC;
verification after that instant accepts only the renamed workflow identity.
An operator policy file still replaces built-in trust wholesale. The client
release also pins the official bundle-author Ed25519 public keys
(`OFFICIAL_BUNDLE_AUTHOR_KEYS` in `mvm-core`). Under the built-in publisher
policy an application bundle whose signed `bundle.key_id` equals a pinned key
verifies against it with no `mvmctl trust add`; the key set is chosen by the
client release, not by the descriptor, so a descriptor naming an unpinned
`key_id` is still refused and the author key remains a second root independent
of the keyless publish identity. Operator enrollment stays additive, an
operator policy file drops the pinned author keys with the rest of built-in
trust, and a host-signed bundle is never in the list. A compromised author key
is disabled by a client release that lists its `key_id` in
`REVOKED_OFFICIAL_BUNDLE_AUTHOR_KEY_IDS` (empty today); that check runs first,
so a hand-enrolled copy of a revoked pinned key is refused too. The pinned keys
apply only to an application bundle: sites that do not already know the bundle
is an application (admission, launch, canonical-plan and installed-bundle
verification) ask `trust_for_installed_bundle`, which grants them only when the
bundle digest is the archive of an installed application whose descriptor
authenticates under the built-in policy and is not revoked, with the digest computed from the archive bytes being verified, and otherwise returns the raw store. `xtask check-bundle-trust-sites` fails when a production file builds the raw store outside an allow-list, or when a listed application path stops composing.
This
transition does not grant `mvm/` trust without revocation enforcement. A URL
redirect is not signing authority.

The workload pack CLI becomes `mvmctl pack info|verify|pull|run|ls|rm|update`.
The attested builder/runtime/image-project cache moves under `pack system`,
with existing verbs retained temporarily as compatibility aliases. The
extension-pack protocol keeps its qualified name. Internal Rust modules may
migrate incrementally from `registry_pack` to workload-pack naming after public
behavior is stable.

A pack exists so a user can run official, expected software: a publisher
signs the exact bits together with the policy those bits are meant to run
under, and the user runs them knowing both are what the publisher released. The
signature authenticates who published it and that nothing changed; it says
nothing about whether the software is safe (above). The pack's policy is the
publisher's statement of what the software needs and what it must never do. It
is one layer among several, and it composes with the user's and other
policies rather than replacing them.

Pack policy is a signed, versioned payload. It takes part in the single
precedence rule set of the product requirements document (Composable), not a
pack-specific one:

- **A pack's ceilings and denies bind the user.** A signed ceiling cannot be
  widened locally, and a deny from any layer beats an allow from any other.
- **A pack's grants are requests.** Allowed hosts, secret bindings, shares,
  environment names and tools take effect only when a host-owner layer (host,
  organization, user, invocation) grants them. The effective permission is the
  grant intersected with every layer's ceiling, the pack's and application's
  included.
- **Layers compose in a fixed order**: host constraints, organization policy,
  user policy, the signed pack and application, then the invocation's flags.
  Where layers conflict on a non-security choice the last peer wins; on a
  security limit the narrowest wins.
- **A pack never carries an escape hatch.** Host-directory mounts and other
  hatches exist only in user-authored layers.
- **Pinning a version is the user's choice.** Versions are immutable and
  signed, so an older version stays runnable for as long as its signature
  verifies and it is not revoked. Revocation is for a pack that must stop
  running (compromise, a defective release), not a way to retire superseded
  versions.

Effective grants are bounded by
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
the legacy registry before compatible client trust ships. After the cutoff,
legacy-only bundles fail built-in verification unless re-signed under the new
identity; explicit operator trust remains a separate decision. Official
`mvm/` publication also requires revocation enforcement. ADR-054's pack
producer is the renamed repository; its Linux-layer boundary is unchanged.
