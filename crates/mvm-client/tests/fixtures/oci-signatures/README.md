# Public OCI signature fixtures

These are real production Fulcio/Rekor artifacts, acquired over public HTTPS.
The adjacent `modern-provenance.json` and `legacy-provenance.json` record
immutable source URLs, digests, signing identities, and inclusion-proof origin.
No test accesses the public registry or Rekor service.

The modern artifact is a signed OCI **attestation**, not a blob signature.
Its predicate is intentionally not restricted to `cosign/sign/v1`: upstream
Cosign's new-bundle `verify` path verifies in-toto subject digest binding
without that predicate restriction.

The legacy signature manifest and simple-signing payload are byte-exact
copies. HTTP tests insert the independently acquired Rekor inclusion proof
into the unsigned bundle annotation in memory; the original signed payload,
signature, certificate, canonical log body, and checkpoint remain unchanged.
Separate normalization tests cover in-process proof retrieval and missing-bundle
Rekor search.

Repository names inside signed claims are not enforced as cryptographic
repository bindings. This matches upstream `SimpleClaimVerifier` and the
new-bundle `WithArtifactDigest` path. Registry allowlisting, credential
confinement, selected-platform digest verification, and preparation receipts
remain enforced independently.
