# macOS release signing

`sign_macos.py` is the shared CLI archive, Python wheel and npm native-library
signing boundary. Run it on a macOS runner with Xcode command-line tools,
**after staging every shipped executable and dylib, before tar/wheel/npm
packing or checksum generation**:

```sh
python3 scripts/release/sign_macos.py \
  --payload "$STAGING_DIR" \
  --report "$RUNNER_TEMP/macos-notarization.json"
```

The staging directory is modified in place. Do not strip, modify install names,
re-sign, or otherwise change native files afterwards. Packaging must preserve
the exact signed bytes. Upload the JSON report alongside CI evidence: it records
the accepted submission ID, team, relative native paths and signed-file SHA-256.
It contains no credentials.

## Provisioning (release administrator)

An Apple Developer Program team with Developer ID distribution access is
required. Create a **Developer ID Application** certificate and export its
certificate **and private key** from Keychain Access as a password-protected
PKCS#12 file. A Developer ID Installer, Apple Development, Mac Distribution,
self-signed, or ad-hoc identity is not a substitute.

Provision these GitHub Actions secrets through the repository/environment secret
settings; never put their values in source, workflow YAML, reports or chat:

| Secret | Value |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12_BASE64` | Base64-encoded PKCS#12 export containing certificate and private key |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | Password protecting that export |
| `APPLE_DEVELOPER_ID_IDENTITY` | Full `Developer ID Application:` identity shown by `security find-identity -v -p codesigning`, including parenthesized team ID |
| `APPLE_TEAM_ID` | The ten-character Apple Developer team identifier matching the certificate |
| `APPLE_ID` | Apple Account authorized for that team and notarization |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password generated for that Apple Account at account.apple.com |

Enable two-factor authentication and accept pending Developer Program agreements.
Restrict credentials to trusted release workflows/runners, not pull-request code.
If using environment-scoped secrets, attach that environment to the signing job,
not only the later registry-publish job. Reusable SDK callers must forward
secrets with `secrets: inherit`. Revoke/rotate the certificate and app-specific
password after exposure; Apple's tickets also support revocation.

The helper imports the identity into a temporary password-protected keychain,
sets noninteractive codesign access, uses that explicit keychain (does not replace
the user's default keychain), and deletes it in a `finally` block. PKCS#12 and
entitlements are confined to a private temporary directory. Commands and
credential-bearing error output are not echoed. Use ephemeral CI runners:
forced termination cannot guarantee cleanup.

## Signing and notarization contract

Every thin or universal Mach-O executable, dylib and loadable bundle in the
staging tree is signed with Developer ID, secure timestamp and hardened runtime.
Extensionless helpers are discovered by file headers, not a fixed list.
`mvmctl` receives `com.apple.security.virtualization`; HVF and libkrun
supervisors receive `com.apple.security.hypervisor`. Libraries have no process
entitlements: those belong to the hosting executable, not the dylib. There are
no blanket JIT or library-validation exceptions.

All signatures must verify against Apple's Developer ID Application certificate
OID and the provisioned team. The helper wraps the payload in a temporary ZIP,
submits it with `notarytool submit --wait`, requires an explicit `Accepted`
result, then verifies every native file again with
`codesign --verify --strict --all-architectures --check-notarization`.
Rejected, pending, timed-out, missing-credential and failed-verification runs
fail closed. The helper has **no unsigned-success mode**.

Apple accepts ZIP, UDIF disk images and flat installer packages for notary
submission, not tarballs. ZIP is a submission container here; wheel/npm/tar
distribution reuses the exact signed files whose tickets Apple publishes online.
**Do not staple** standalone executables, dylibs, ZIPs, wheels or tarballs:
stapling supports app bundles, disk images and installer packages instead.
First use of these unstapled distributions can require network access to Apple's
ticket service. Offline-first Gatekeeper distribution would require a separately
designed signed/stapled installer or disk image; this helper does not claim it.
`spctl --assess --type execute` is not an appropriate acceptance test for dylibs.

CLI tag builds (including tag dispatch rehearsals) must call this boundary before
packing. A separate explicitly unsigned branch build is not release acceptance.
SDK PyPI/npm builds invoke it for every actual publication and tag-ref dry run:
tag rehearsals skip publication, not notarization. Branch-only dry runs omit the
signing step, print an unsigned-build notice, and require no Apple credentials.
The generic `build-hostlib` action remains a compilation tool;
both registry workflows sign its final staged output before any distribution.
No real signing or notarization acceptance is established by mock tests.

References:
- [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple: Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- Installed macOS `man codesign`, `--check-notarization`.

## Credential-free regression tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/release -p 'test_sign_macos.py' -v
```

Tests mock the Apple tool boundary. They check complete native-file discovery,
role entitlements, hardened runtime/timestamp, accepted-only notarization,
online verification, cleanup and missing-credential failures. They do not
generate a development identity or fake notarization evidence for a release.
