# Issue 3716: atomic product-pack installation

Status: complete foundation slice

Authenticated registry packs now install beneath the SHA-256 digest of their
exact signed manifest. Each installed directory contains a private payload
tree plus the original manifest and Sigstore bundle, keeping the evidence used
at pull time beside the bytes it authenticated.

Installation verifies staging before touching the cache, copies only declared
files into a private same-filesystem quarantine, verifies the copied payload,
and publishes the complete directory with one rename. Reusing an existing
digest rechecks its exact sidecars and payload; malformed or tampered entries
are replaced rather than served.

The implementation shares the established atomic directory-promotion primitive
with the internal attested-pack cache. Focused tests cover the content-addressed
layout, exact sidecars, fail-before-write behavior, `MVM_HOME` isolation, and
poisoned-entry repair, while the existing promotion suite protects the reused
path.

Registry transport and the user-facing search, pull, list, remove, and update
commands remain separate slices.
