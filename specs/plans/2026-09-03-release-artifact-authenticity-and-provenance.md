# Claim the release-artifact authenticity we already ship, then decide on provenance

Backing: shipped-source
Validation: check-sprint-append

**Status: NOT STARTED — design only.**

Follows the `SECURITY.md` correction. That change deleted three advertised
supply-chain controls that no workflow produces. This plan is the other half of
the same audit: a shipped, tested control that no claim covers.

## The asymmetry

`SECURITY.md` advertised in-toto attestation, SLSA provenance and SHA-512
checksums. None is produced by any workflow, and they were removed.

Meanwhile the ledger has **no row for release-artifact authenticity at all**.
Claim 6 covers the checksum on a fetched dev image; claim 7 covers dependency
auditing. Nothing claims that a published release artifact is signed, or that
the signature is checked against this workflow's identity before the bytes are
used — even though that is implemented, tested, and enforced in CI today.

So the same file overclaimed three controls and under-claimed a real one. The
second error is the more expensive: an unclaimed control has no gate, so it can
be deleted without anything going red.

## What actually ships

Verified on `ecb0da691e`.

- **Signing.** `release.yml` signs every release blob keyless via GitHub OIDC — the `mvmctl` tarballs, boot-image artefacts, checksum manifests, and `sbom.cdx.json` — each with a `--new-bundle-format` bundle carrying the Fulcio certificate and the Rekor inclusion proof.
- **Post-publish verification in CI.** The `verify-release` job downloads the published assets and runs `nix/packaging/release/verify-release-assets.sh` with the identity regexp pinned to `release.yml@refs/tags/*`.
- **Build-side enforcement, fail-closed.** `crates/mvm-build/src/release_signature.rs` refuses a missing or malformed bundle and names the asset.
- **Fetch-side enforcement.** `crates/mvm-cli/src/commands/env/artifact_verify.rs` refuses an unsigned manifest before parsing it, and the hash-skip escape hatch does not waive the manifest signature.

### The limit that has to be stated

The two enforcement paths do **not** have the same posture, and a claim that
glosses this would overclaim.

The build and fetch paths refuse. The **self-update path does not**:
`verify_signature` in `crates/mvm-cli/src/update.rs` returns `Ok` with a warning
when `cosign` is not on `PATH`. On that path signature verification is
best-effort, and the SHA-256 pin is what still holds. There is also a documented
emergency hatch that admits the manifest while keeping the hash pin.

Any claim wording has to carry that split, in the shape claim 13 and the
`Preview` rows already use.

## WS-A — Add the claim for what already ships

No new product code. The witnesses exist.

- [ ] Add `MVM-SEC-20` to `model/claims.toml` — `level = "build"`, `witness_kinds = ["fn", "ci"]`, `suite = "supply_chain"`
- [ ] Statement, carrying the split rather than hiding it: *every published release artifact is signed under the release workflow's OIDC identity, and the build and fetch paths refuse an unsigned or mis-signed artifact; the self-update path warns and falls back to the SHA-256 pin when cosign is absent*
- [ ] Witnesses — these resolve under the gate's rules today:
  - `ci:verify-release`
  - `fn:accepted_identities_are_the_versioned_release_workflow`
  - `fn:a_missing_bundle_refuses_and_names_the_asset`
  - `fn:a_malformed_bundle_is_refused`
  - `fn:fetch_expected_hashes_refuses_an_unsigned_manifest_before_parsing`
  - `fn:skip_hash_verify_does_not_waive_the_manifest_signature`

### The two best witnesses are not citable, and that is a gate defect

The most on-point evidence for this claim is the pair that asserts the release
*workflow* structure — that every signed blob uses the one bundle format, and
that the release attaches the bundle the verifier later fetches. Both live in
`tests/release_assets.rs`, at the workspace root.

`check-claim-catalog` cannot see them. `resolve_fn_needles`
(`xtask/src/check_claim_catalog.rs`) resolves `fn:` needles against
`workspace.join("crates")` and nothing else, so a witness in a root-level
integration test is unciteable — it fails as a dangling name even though the
test exists and runs.

That scoping looks like an artefact of layout rather than a decision: nothing in
the gate's own comments argues that root tests are unsuitable witnesses. Widening
it to cover the workspace's root `tests/` is a small change, and it would make
the strongest evidence for claim 20 citable.

- [ ] Decide: widen `resolve_fn_needles` to include root `tests/`, or accept a claim witnessed only from `crates/` plus the CI lane

Land the claim either way; do not block WS-A on the gate change.
- [ ] Add a `@MVM-SEC-20 @build` scenario to `features/suites/s19_supply_chain/supply_chain.feature`
- [ ] Add ledger row 20 to ADR-001 with the same witnesses and a limits note naming the self-update fallback
- [ ] Regenerate `CONFORMANCE.md` (`check-conformance --write`)
- [ ] Add claim 20 to `CLAUDE.md` §"Security model"

Cost: one afternoon, no product change. Value: the control stops being deletable
in silence.

## WS-B — SLSA provenance

Decide after WS-A, because WS-A changes what provenance is worth.

The concrete gap: `publish-npm.yml` publishes with `--provenance`, so **the npm
package carries provenance today and the binaries most people install do not.**
No workflow uses `actions/attest-build-provenance`, and no workflow requests the
`attestations` permission.

- [ ] Decide whether to adopt (recommendation: yes, narrowly — to close the npm-vs-binaries asymmetry)
- [ ] Add `attestations: write` to `release.yml` permissions — `id-token: write` is already there
- [ ] Attest the published binary artefacts with `actions/attest-build-provenance`
- [ ] Add a structural test in `tests/release_assets.rs` asserting every published binary artefact is attested, so the lane cannot silently drop one — note this lands in the same root-level file the claim gate cannot cite, so it is only usable as a witness if the WS-A scoping decision goes the widening way
- [ ] Extend claim 20's witnesses rather than opening claim 21 — this is more evidence for the same property, not a new property
- [ ] State the level honestly wherever it is described

**What it buys, stated plainly.** Keyless cosign already binds each artifact to
this repo, this workflow file, and a tag ref through the certificate identity.
Provenance adds the commit SHA, the build inputs, and a machine-readable
structure a downstream policy engine can consume. That is real but incremental.

**What it does not buy.** `actions/attest-build-provenance` on hosted runners is
SLSA Build **L2**: the provenance is produced by the same workflow that produces
the artifact, so a compromised release job forges both. It defends against
later tampering and mis-attribution, not against a compromised build. L3 needs
an isolated builder that the build cannot influence, and is a materially larger
change than adding the action.

Note also that the existing reproducibility double-build (already a claim 7
witness, `ci:reproducibility`) answers *did this source produce these bytes*
without requiring trust in the builder at all. On that specific question it is
the stronger control, and provenance does not replace it.

## WS-C — Decline SHA-512, and stop tracking in-toto separately

Recorded so neither is re-proposed from a checklist.

- [ ] **SHA-512: do not add.** SHA-256 is unbroken. Every checksum manifest is itself a signed artefact, so a second manifest adds another file to the signing set that must stay in lockstep, to defend against nothing. The only driver would be an external regime that names the algorithm — a compliance-checklist driver, not a security one, and it belongs to the control-mapping work in `mvm-assurance`.
- [ ] **in-toto is not a separate item.** SLSA provenance *is* an in-toto attestation: in-toto defines the envelope, SLSA provenance is a predicate carried inside it. Listing them separately was a category error in the old `SECURITY.md`. WS-B delivers both or neither.

## Why this order

WS-A documents a control that exists. WS-B adds one that does not. Doing them in
that order means the ledger is honest at every point, and it makes the provenance
decision cheaper to judge, because after WS-A the gap that provenance fills is
visible in the ledger rather than argued from a diagram.

Doing WS-B first would put a `Shipped` provenance row above a still-unclaimed
signing control — advertising the weaker, newer mechanism while the stronger,
older one stays invisible. That is the shape of the defect this plan exists to
correct.

## Out of scope

- Any change to how artifacts are signed. The keyless-with-bundle format is settled and gated.
- Reworking the self-update fallback. WS-A states that limit; changing it is a separate decision with its own trade-off — a hard refusal there strands users who have no cosign installed.
- `SECURITY.md` prose. It now points at the ledger and `CONFORMANCE.md`, so WS-A propagates without editing it.

## Open questions

1. **Should the self-update path fail closed when cosign is absent?** Today it warns and falls back to the hash pin. Fail-closed is a stronger claim and a worse first-run experience on a host without cosign. WS-A only requires stating the current behaviour; changing it is a separate call.
2. **One claim or two?** This plan folds provenance into claim 20 as additional evidence. The alternative is a distinct claim for build provenance. Folding keeps the ledger smaller and matches how claim 7 already carries `ci:reproducibility` alongside the dependency-audit witnesses.
3. **Do the boot-image and SDK-sidecar trains need their own rows?** They are signed by the same machinery but published on separate tag trains, and `verify-release` covers the main release only.
