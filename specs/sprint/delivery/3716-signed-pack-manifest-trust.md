# Issue 3716: signed pack manifest trust

Status: complete foundation slice

This slice adds the signed product-pack manifest and publisher-authority layer
on top of the digest lockfile. A namespace maps to one explicit keyless issuer
and a non-empty set of accepted identities. Duplicate namespace authorities,
unknown namespaces, malformed identities, unknown fields, and unsupported
schemas fail closed.

Verification deliberately performs trust decisions in this order:

1. hash the raw manifest bytes and compare them with the exact lock pin;
2. resolve the operator-owned publisher authority for the locked namespace;
3. verify the detached signature over those same raw bytes;
4. parse the strict manifest and bind its versioned reference to the lock;
5. validate that every declared file path is relative, safe, and unique.

The implementation reuses the existing keyless signature verifier and the
existing pack path-safety predicate. It does not add registry transport,
publication automation, profile composition, or admission wiring; those remain
separate reviewable slices.

Focused coverage now includes fourteen portable registry-pack tests plus a
feature-gated production-verifier wiring test. They cover lock and signature
ordering, untrusted and duplicate publisher authorities, strict serde/schema
handling, malformed signature bundles, manifest identity mismatch, and unsafe
or duplicate file paths.
