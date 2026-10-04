These files come from `tinylabscom/mvm-templates` commit
`d60f4ea5a34aab5b3e7dac54ed8bf8e1f66fe76c`, under
`packs/runtime/go/1.0.0/`. The public publish workflow signed the manifest.

The manifest SHA-256 is
`ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50`.
The signed group payload SHA-256 is
`28a7326193e031cd853ac325fd5808f6b8a30bb4c1f77d10f9b50a2412bb6c54`.
The integration test reconstructs the registry index in a temporary directory;
the index is discovery data, not signed policy.
