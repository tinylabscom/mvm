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
  not know. If there is no such `mvmctl`, it falls back to `cosign`, and if
  there is neither, it warns as before.
- Once either verifier is present, a missing bundle refuses the install. It
  used to warn and carry on.
- The `cosign` fallback now pins `refs/tags/$VERSION` exactly, instead of
  matching any tag.

So an upgrade (the only way an `install.sh` install is upgraded, since
`env update` refuses one) is verified on every host. A first install on a host
with neither `mvmctl` nor `cosign` still has nothing to verify with.

## Witnesses

- `a_missing_bundle_is_refused`, `a_garbage_bundle_is_refused_and_names_the_asset`,
  `the_update_skip_variable_does_not_skip_verification`,
  `a_real_release_bundle_verifies_only_under_its_own_tag` (the last runs under
  `manifest-verify`)
- `install_sh_verifies_the_signature_with_the_installed_mvmctl`
- `install_sh_refuses_an_archive_the_installed_mvmctl_rejects`
- `install_sh_refuses_a_missing_bundle_once_it_can_verify`
