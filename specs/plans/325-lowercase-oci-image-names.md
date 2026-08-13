# Lowercase OCI image names

OCI registries require repository paths to be lowercase, but users commonly
capitalize familiar image names when typing them. Normalize registry and
repository components before validation so those references resolve to the
same canonical image. Preserve tag case because OCI tags are case-sensitive,
and preserve strict digest validation.

- [x] Normalize ASCII capitalization in OCI repository paths.
- [x] Prove canonical references contain the lowercase repository.
- [x] Prove case-sensitive tags and digest validation remain unchanged.
- [x] Cover capitalized CLI input at the pre-network production-policy gate.
- [x] Pass formatting, tests, workspace check, and Clippy.
- [x] Prepare the change for the required CI merge queue.
