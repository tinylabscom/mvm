# SDK registry release evidence

The SDK package train and signed CLI guest-runtime train are independent.
`sdks/release.toml` declares SDK `version` and compatible `runtime_version`.
The latter must exactly equal the workspace version compiled into the host
library; it is not inferred from the SDK tag. Currently SDK 0.15.2 requires
runtime 0.23.1.

`publish-sdk.yml` accepts real publication only on a published `sdk-vVERSION`
release. Before either registry publishes, the preflight:

1. Checks both package manifests, release tag and runtime compatibility.
2. Queries exact PyPI, npm main and all five platform-package versions. Existing
   versions are resumable, not a reason to force a version bump. Only HTTP 404
   means absent; authentication, network and parse errors fail closed.
3. Downloads the complete `mvm-guest-bins-vRUNTIME.tar.gz` CLI-release archive,
   its checksum, both Sigstore bundles, and signed `checksums-sha256.txt`.
4. Verifies all three signatures against the exact CLI `release.yml` tag
   identity, compares both checksum records to the archive hash, and verifies
   GitHub build provenance with the same signer workflow and source tag.

Runtime archive completeness remains the Rust guest-runtime validator's
responsibility and is exercised by the CLI release boot gate; this orchestration
does not maintain a second guest-member catalog.

Branch dry runs remain local build/package smokes and require no pre-existing
runtime release. They are **not release acceptance**. Tag signing rehearsals
and real macOS publication inherit the signing secrets from the orchestrator.

After both publication jobs succeed, `sdk-registry-smoke.yml` installs exact
versions from public PyPI and npm into new environments/projects. It never
downloads build artifacts or installs repository packages. Python requires a
binary wheel; npm must resolve its matching optional platform package itself.
The existing installed smokes load the packaged host library, negotiate the ABI
and call the real approval-callback API. The matrix covers darwin-arm64 and
Linux x64/arm64 with glibc and musl; Python glibc runs at the manylinux2014
baseline and musl runs in Alpine. Library overrides and source import paths are
cleared. Logs are retained per target, including failed attempts.

The registry workflow can also be dispatched on the SDK release tag to retry
installed evidence without rebuilding or republishing. A partially published
train must be resumed at the **same SDK version**, completing missing registry
assets before collecting this evidence.

**Install/load is not guest-boot evidence.** This workflow deliberately reports
guest boot as not witnessed. No installed-SDK boot harness is wired here, and
neither a successful registry workflow nor a local rehearsal establishes SDK
end-to-end release acceptance. An actual supported HVF/KVM SDK boot, API
operation and teardown witness is still required in an authorized capable
environment. Do not substitute CLI boot evidence for installed-SDK evidence.

Hermetic preflight tests (no registry or GitHub access):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-sdk-release-preflight.py
SDK_EVENT_NAME=workflow_dispatch SDK_DRY_RUN=true python3 scripts/sdk-release-preflight.py
```
