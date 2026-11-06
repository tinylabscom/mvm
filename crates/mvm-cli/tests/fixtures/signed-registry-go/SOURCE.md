These files are the published `runtime/go@1.0.0` pack from `tinylabscom/mvm-packs`,
as committed by the publish workflow in commit
`b4ad28e46ea0b77651c134eb6b3f9af610952ae0` (`packs/runtime/go/1.0.0/`).
The Sigstore bundle is signed by
`https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main`,
the current official publisher identity. It is a byte-for-byte copy.
The manifest and `pack/group.toml` are byte-identical to the same pack on
`mvm-packs` main, which still carries a bundle signed under the former
`mvm-templates` identity.

The manifest SHA-256 is
`ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50`.
The signed group payload SHA-256 is
`28a7326193e031cd853ac325fd5808f6b8a30bb4c1f77d10f9b50a2412bb6c54`.
The integration test reconstructs the registry index in a temporary directory;
the index is discovery data, not signed policy.
