# Release-artifact authenticity claim

The shipped release signature chain now has a machine-checked ledger entry:
`MVM-SEC-20`. The claim describes the actual two forms of coverage. Release
archives carry their own Sigstore bundles; raw kernels, root filesystems, and
metadata are authenticated through digests in signed checksum manifests.

The claim cites the post-publish `verify-release` lane and the build/fetch
refusal tests that CI executes. It deliberately excludes the malformed-bundle
test whose feature-gated test target no CI lane currently runs, and records
that self-update warns and relies on the SHA-256 pin when cosign is absent.

The active plan's WS-A checklist, the generated conformance table, ADR ledger,
security-model summary, and mutation surface now agree. Provenance adoption and
the SHA-512/in-toto decisions remain in WS-B and WS-C.
