# Delivery: Signed bundles through image registries (#3386)

`mvmctl bundle push <file> <ref>` publishes a `.mvmpkg` archive to an image
registry, and `bundle fetch` / `bundle install` accept `oci://` tag and digest
references alongside paths and `https://` URLs.

- The registry client in `mvm-fs` gained blob existence checks, the two-request
  monolithic blob upload, and manifest put, all through one auth path.
  - Configured credentials belong to the first registry origin the client
    talks to and are never attached to another. Tokens a challenge issues are
    cached per (origin, repository) and never sent elsewhere.
  - A configured bearer token the registry refuses fails the request with an
    error naming the realm; it is not exchanged for an anonymous token.
  - Challenges are read from every `WWW-Authenticate` header, with
    case-insensitive schemes, escaped quotes and quoted commas. A realm must be
    HTTPS, or the registry's own origin when the registry is plain HTTP. Basic
    credentials still go to a realm on another host, as a token service
    conventionally is.
  - Blob redirects are followed to any origin without credentials, at most
    five times, never from HTTPS to HTTP. This also affects `image pull`.
  - Upload session locations must stay on the registry's origin.
  - Bodies of 1 MiB or more are streamed from the caller's buffer in chunks
    instead of copied whole; pulls grow their buffer as bytes arrive.
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
- `--prod` on `fetch` and `install` refuses `--allow-http` for every source.
  For an `oci://` source it also refuses a tag and a registry the OCI registry
  policy does not allow, reusing `image pull --prod`'s digest-pin and policy
  code, before any network access. Paths and `https://` URLs are not further
  restricted: they have no mutable name to pin and pass the same signature
  check. `MVM_OCI_BEARER_TOKEN`, which is not host-specific, is never sent over
  plain HTTP.
- `bundle push` emits the new `LocalAuditKind::BundlePush`; `BundleInstall`
  now records the source (the resolved `oci://…@sha256:` reference, or a
  credential-free URL or path).
- Tests use an in-process registry (`mvm_fs::oci::test_registry`, behind
  `test-support`). Only that fixture was exercised; no hosted registry was.
- Documented `bundle push` examples are classified at the parse verification
  tier: the documentation harness proves their CLI shape while the in-process
  registry tests cover execution without requiring a live registry in the
  documentation suite.
