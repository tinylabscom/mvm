# `main` did not compile with the release feature set

Backing: shipped-source
Validation: cargo check -p mvm-cli --features release-artifact-bootstrap,manifest-verify,builder-vm --lib

Found by the first W7.2 release-train attempt (`v0.18.0-rc.2`, run
36073659591), whose macOS documented-surface lane stopped at compile:

```
error[E0432]: unresolved import `super::builder_vm_artifact_names`
   --> crates/mvm-cli/src/commands/env/builder_vm/bootstrap.rs:634:9
```

W6 (#3633) gated `BuilderVmArtifactNames` and `builder_vm_artifact_names` on
`cfg(test)` when the builder image download moved to the image set. The signed
builder-pack fetch (`fetch_release_builder_pack_staging`, `manifest-verify`)
still names its assets through them, so every build combining
`release-artifact-bootstrap` with `manifest-verify` — every release build, and
the documented-surface lanes — failed. CI's only release-feature check compiled
`release-artifact-bootstrap` alone, which does not reach that code. The run was
cancelled before any job could publish.

The two items are now gated on `any(test, feature = "manifest-verify")`, and
`ci.yml`'s "release artifact acquisition contract" step also compiles
`release-artifact-bootstrap,manifest-verify,builder-vm`.
