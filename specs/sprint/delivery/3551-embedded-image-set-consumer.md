# #3551 embedded image-set consumer slice

The `.mvmpkg` schema now has a backend-neutral `embedded_image_set` member. Its
image-set JSON and every member artifact remain ordinary signed bundle files;
the typed member only binds them to the existing `mvm_core::image_set`
contract. Fetch, install, admission re-verification, and
`machine check-artifact` therefore share one structural/completeness/hash
decision instead of implementing a second image validator.

Bundle installation additionally publishes the verified image bytes under an
image-manifest-SHA-256 cache key. Cache hits are byte-reverified before use.
Backend preview calls the image-set selector, so an unsupported architecture,
boot protocol, artifact format, or guest device is a named pre-boot refusal.
Schema-v1/v2 manifests cannot smuggle typed members into a v3-aware reader,
and the member wire shape has an explicit serde round-trip regression.

Validation on the rebased consumer slice: all 57 focused bundle tests and both
`machine_check_artifact_cli` integration tests pass. The full host workspace
run reaches 840 passing `mvm-agentd` tests before the known slow-sink regression
fails; its isolated fix is tracked in PR #3835.

This is intentionally not issue completion. The sealed checkpoint member is
owned by #3384, and physical Firecracker/HVF/libkrun/QEMU boot witnesses plus
cross-host checkpoint re-admission remain outstanding.
