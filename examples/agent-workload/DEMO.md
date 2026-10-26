# Claude application candidate

`environment.json` declares `agent/claude@2.0.0`, the baked
`/etc/mvm/entrypoint`, a required `ANTHROPIC_API_KEY` slot, and only
`api.anthropic.com:443` egress. The old `agent/claude@1.0.1` is policy-only.
Source definitions and a locally signed archive are not registry publication.

The example registers only WebFetch with strict MCP configuration and bakes
three-turn and $0.50 limits into its entrypoint. The shared wrapper retains
`--bare` unless a caller explicitly supplies a tool list. Provider-side budget
limits remain necessary.

## Source-only export witness

The ignored Rust selector is
`portable_boot_assets::tests::signed_release_exports_real_canonical_workload`.
The operator supplies:

- `MVM_TEST_SIGNED_RUNTIME_ARCHIVE`: genuine release runtime archive, with
  adjacent `.tar.gz.sha256` and `.tar.gz.bundle` evidence.
- `MVM_TEST_SIGNED_RUNTIME_VERSION`: the genuine runtime release version,
  matching the exporting binary's version.
- `MVM_TEST_CANONICAL_ROOTFS`: existing sealed `rootfs.ext4`, beside its
  original `mvm-meta.json`, `rootfs.verity`, and raw signed `rootfs.roothash`.
- `MVM_TEST_CANONICAL_OUTPUT`: a fresh, nonexistent output directory.
- `MVM_TEST_CANONICAL_ENVIRONMENT`: this example's `environment.json`.

The witness validates the descriptor against the built entrypoint, authenticates
the published Linux and release runtime closure, and exports the existing image
without resealing it. Linux acquisition is workload-only; it neither requires
unrelated builder boot helpers nor authorizes a builder boot.
Current bundler `.verity(...)` retains the original raw
signed root-hash member automatically. `.local_build()` stamps the signed local
origin; no legacy local-build module or trust bypass is used.

The witness uses `PreparedPortableBootAssets::stage`, the current
`HostBundleSigner`, and staged `.publish()`. It needs independently prepared
host state and genuine publisher evidence. Running it may create a host signing
key. Do not run it as a source inspection check or disclose credentials.

## Eventual registry demo

Only after a real signed application release is discoverable:

```bash
mvmctl search agent/claude
mvmctl pull agent/claude
printf '%s\n' 'tell me a joke' | mvmctl run agent/claude
```

Require the runnable version, verified archive identity, effective Anthropic-only
policy, actual response and exit status, and correlated audit evidence. Never
substitute a prior response or describe a local candidate as published.
`enforcement-environment.json` is a separate rehearsal descriptor without this
embedded allowlist; it must not replace the application descriptor in the demo.
