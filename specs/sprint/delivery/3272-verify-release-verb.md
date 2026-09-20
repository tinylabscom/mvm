# `mvmctl env verify-release`, and `install.sh` uses it

Issue #3272, the installer half.

`install.sh` verified the release signature only when `cosign` happened to be
installed, and otherwise warned. Now:

- `mvmctl env verify-release <ARCHIVE> --tag <TAG> [--bundle <PATH>]` checks a
  downloaded archive against its Sigstore bundle offline. It uses the same
  verifier and trust root as `mvmctl env update`, and accepts only the release
  workflow at that tag. Unlike `env update`, it ignores
  `MVM_SKIP_COSIGN_VERIFY`, because verifying is the only thing it does.
- `install.sh` prefers an installed `mvmctl` that has the verb: first the one
  in the install directory, then whatever is on `PATH`. It detects the verb from
  the help text, because an older `mvmctl` can exit 0 on a subcommand it does
  not know. If there is no such `mvmctl`, it falls back to `cosign`.
- A later epic #3277 closure removed the remaining fresh-host warning path. If
  neither verifier exists, the installer authenticates the archive against an
  installer-carried or independently supplied SHA-256 before using only its
  `mvmctl` as a temporary verifier. Every path requires the bundle.
- The `cosign` fallback now pins `refs/tags/$VERSION` exactly, instead of
  matching any tag.

So both upgrades and first installs are verified on every host. A fresh host
with no verifier must authenticate the temporary one or refuse.

## Witnesses

- `a_missing_bundle_is_refused`, `a_garbage_bundle_is_refused_and_names_the_asset`,
  `the_update_skip_variable_does_not_skip_verification`,
  `a_real_release_bundle_verifies_only_under_its_own_tag` (the last runs under
  `manifest-verify`)
- `install_sh_verifies_the_signature_with_the_installed_mvmctl`
- `install_sh_refuses_an_archive_the_installed_mvmctl_rejects`
- `install_sh_refuses_a_missing_bundle_once_it_can_verify`
- `fresh_install_bootstraps_signature_verification_from_a_trusted_archive_hash`
- `fresh_install_refuses_without_a_verifier_or_trusted_archive_hash`
