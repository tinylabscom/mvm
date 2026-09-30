# Issue 3716: product-pack payload verification

Status: complete foundation slice

This slice closes the gap between authenticating a signed product-pack
manifest and trusting the unpacked files it describes. Callers can now verify
an unpacked payload against an authenticated manifest before any installation
or profile parsing occurs.

Verification requires every declared path to be a regular file with the exact
signed byte length and SHA-256 digest. It also walks the complete payload tree
and refuses symbolic links, special files, and undeclared files so unsigned
content cannot ride beside an otherwise valid manifest.

The implementation reuses the existing pack path rules and streaming SHA-256
helper. Registry transport, atomic installation, CLI lifecycle verbs, profile
composition, and admission binding remain separate reviewable slices.

Focused coverage includes exact payload acceptance and refusals for missing,
wrong-size, same-size tampered, undeclared, and symlinked files.
