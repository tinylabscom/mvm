# Delivery: Signed bundles through image registries (#3386)

`mvmctl bundle push <file> <ref>` publishes a `.mvmpkg` archive to an image
registry, and `bundle fetch` / `bundle install` accept `oci://` tag and digest
references alongside paths and `https://` URLs.

- The registry client in `mvm-fs` gained blob existence checks, the two-request
  monolithic blob upload, and manifest put. Every request shares one
  bearer-challenge path, and a redeemed token is reused so the upload carrying
  the archive is not first refused and replayed. The challenge parser no longer
  splits a quoted `pull,push` scope. Upload session locations must stay on the
  registry's own origin, because the request that closes the session carries
  the credentials.
- `mvm_fs::oci::artifact` pushes and pulls a single-layer artifact: an image
  manifest with `artifactType`, the empty config descriptor, and one layer. A
  pull holds the manifest to the pinned and advertised digests under a 64 KiB
  cap, and the layer to its descriptor digest and exact size under a
  caller-chosen cap (4 GiB for bundles). The signature is inside the archive,
  so a bundle is one layer.
- Media types: `application/vnd.mvm.bundle.v1` and
  `application/vnd.mvm.bundle.v1.tar`, in `mvm_contract::plan::bundle`.
  Alignment with #3365 is still open (W9.6).
- Push refuses a bundle that does not verify against the local trust store.
  Fetch hands pulled bytes to `read_and_verify_bundle`, so trust is unchanged.
- Source precedence is prefix-only: `oci://` is a registry, `https://` and
  `http://` are URLs, anything else is a path — including strings shaped like
  `host/name:tag`.
- `--prod` on `fetch` and `install` refuses a tag reference before any network
  access. A pull by tag prints the digest it resolved to.
- `bundle push` emits the new `LocalAuditKind::BundlePush`.
- Tests: an in-process registry (`mvm_fs::oci::test_registry`, behind
  `test-support`) that accepts uploads and can serve tampered bytes. Covered:
  round trips by tag and digest, blob skip on re-push, token reuse,
  cross-origin upload refusal, tampered layer, tampered manifest, manifest bytes
  not matching the pinned or advertised digest, oversize manifest and layer,
  descriptor size drift, a tag under `--prod` with zero requests made, and
  unsigned and untrusted bundles refused after a clean pull. The binary itself
  pushes and then fetches under `--prod` in `tests/audit_emissions_live.rs`.
