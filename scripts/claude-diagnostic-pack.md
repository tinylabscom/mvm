# Private diagnostic pack preparation

This is preparation, not a signed pack or a production witness. Do not run the
ignored producer until the genuine signed CLI `0.26.0` runtime and its archive
and checksum signature bundles are available. No Source runtime, fake proof,
reseal, production relabel, native caller enrollment, model call, release
dispatch, public asset, or final-v2 candidate is authorized by this runbook.
The production capability contract remains separate; the request-budget fold
alone does not authorize a production pack.

## Inputs and approval

Use a canonical absolute private input directory owned by the current user,
with no symlink ancestors or member symlinks. Small metadata members must be
single-link mode `0600`; large archive/rootfs members may be `0400` or `0600`.
The adapter reads the six approved payloads through `CaptureDirectory` and
copies those exact bytes into private staging. It does not modify input files.

The retained parent preparation set is read-only mode `0400`. Do not change
those originals or pass that directory directly to the adapter. Make a new
owned mode-`0700` input directory, copy the seven files (the manifest plus its
six named payloads) into it, and set only these new copies to `0600`. Recheck
the manifest digest below and every copied payload's manifest digest and byte
length before approving the request. Changing a copy's mode does not change
its content hash. Never relax `CaptureDirectory`'s metadata permission rule.
The original rootfs, runtime archive and other large immutable inputs can be
copied separately under their approved names; do not hard-link them.

Retain `input-manifest.json` with SHA-256
`4d2c82dc2a0e57fbc2412f087ed650aacbc0afcd2edc5d345b2b647fad62dc70`
and all six files it names. The script must also equal the checked-in
`crates/mvm-client/src/entrypoint/foreground_diagnostic.sh`, SHA-256
`6b2a07c140cd25dc58fd80844b767d22083a6e5f9296073c4108ac9f5603a684`.
The immutable input pin records operator-approved vendor-original, GPG signer,
patchelf transformation and baked identities. It is not independent GPG
verification, and does not claim that the vendor signed the transformed ELF.

In that directory supply a mode-`0600` `diagnostic-request.json` with exactly
these fields:

- `runtime_version`: `0.26.0`.
- `rootfs`, `guest_sidecar`, `verity`, `roothash`, `environment`,
  `runtime_archive`, `runtime_checksum`, `runtime_bundle`,
  `runtime_checksum_bundle`: each an object containing `name` (one basename),
  `sha256` (approved exact lowercase content digest), and `bytes` (exact length).

Retain the original sealed rootfs and sidecar beside each other under the
sidecar filename expected by `mvm_bundler::guest_sidecar_path`. Preserve the
original verity bytes and canonical raw root hash (64 lowercase hex bytes plus
one LF). The adapter will not repair or reseal them. Runtime checksum bundle
naming must match the existing runtime verifier. All bindings, including the
sealed workload identities, need operator review; computing a digest does not
approve its content.

The verity sidecar has its own bounded read limit of 64 MiB, accommodating the
retained 12,357,632-byte sidecar. Other small metadata reads remain bounded to
1 MiB. Declared oversized inputs are rejected before opening or allocating
their payload.

The environment uses the actual `EnvironmentDescriptor` schema:
`descriptor_version: 1`, pack name `agent/claude-wire-diagnostic`, version
`2.1.273`, target `aarch64-linux`, resources `cpu_cores: 1`, `memory_mb: 4096`,
`policy.allow_hosts: []`, no volumes, services or capabilities, and exactly
one required secret slot `ANTHROPIC_API_KEY`. Its root entrypoint argv must
equal the unchanged sealed guest sidecar. Do not replace it with diagnosticExec:
the foreground test's explicit dev exec is not an entrypoint witness.

Set `MVM_DIAGNOSTIC_INPUT_ROOT` to this canonical input directory and
`MVM_DIAGNOSTIC_APPROVED_REQUEST_SHA256` to the separately approved digest of
the exact request bytes. Missing inputs, aliases, bad permissions/digests,
wrong identity/resources/extras or runtime versions fail before signing keys.

## One producer invocation, only after genuine proofs arrive

Prepare a new canonical owned fixture directory outside the input directory.
Set `MVM_DIAGNOSTIC_FIXTURE_ROOT` to it. Inside it create private `mvm` and
`home` directories, and a mode-`0600` file `diagnostic-owned` containing exactly
`disposable-diagnostic-publisher-v1` followed by LF. Do not create
`diagnostic-publisher-keys` or `diagnostic-output` in advance.

Before replacing `HOME`, resolve the existing development toolchain root:

```sh
export RUSTUP_HOME="${RUSTUP_HOME:-"$HOME/.rustup"}"
test -d "$RUSTUP_HOME/toolchains"
```

Then source `scripts/dev-env.sh` in the normal development shell and explicitly
set `MVM_HOME` to the fixture's `mvm` directory and `HOME` to its `home`
directory. Preserve `RUSTUP_HOME` and the development Cargo cache/target
settings. Toolchain access is host-side build access, not application state or
a guest mount. Check `cargo --version` under those isolated-home settings
before the producer. These pinned payloads require an ARM64 host and runtime;
x86 hosts are refused before acquisition or key/output creation.

The single adapter invocation is:

```sh
cargo test --offline -p mvm-client --lib \
  portable_boot_assets::diagnostic::signed_release_exports_diagnostic_pack \
  -- --exact --ignored --nocapture
```

This command has **not** been executed during preparation. Actual invocation
may acquire authenticated published Linux image-set evidence over the network.
It calls the unchanged `PreparedPortableBootAssets::from_set`; runtime
authentication and preparation precede output and disposable publisher-key
creation. It never boots a VM or executes the vendor client or script.
Successful output is only
`$MVM_DIAGNOSTIC_FIXTURE_ROOT/diagnostic-output/claude-wire-diagnostic.mvmpkg`.
Every supplemental member is signed/hash-checked through the standard stage.
The key is created only under the new `diagnostic-publisher-keys` directory.
Directory locks assume cooperating lifecycle operations and exclusive operator
ownership of the private fixture; path rechecks are not race-proof against a
non-cooperating same-UID writer. If a failure occurs after output/key creation,
retain that private state for diagnosis. Do not delete or reuse it based on a
vanished PID; a retry requires a new fixture.

## Later consumer sequence, not executed here

1. Inspect the new disposable publisher public key (`host-signer.pub`), derive
   its normal bundle key ID, and trust only that key in this fixture's private
   `MVM_HOME` trusted-publishers store. Never use official/shared keys.
2. Use ordinary `mvmctl bundle fetch` against the diagnostic archive to verify
   its signature and every payload; then `mvmctl bundle install` the same
   archive in the same private home. The verification subcommand is `fetch`,
   not `verify`. Record the returned installed bundle identity and archive/key
   digests in the foreground harness's separately approved provenance record.
3. Select `MVM_SECRET_STORE_BACKEND=file` in that private home. Prepare only
   the `foreground-diagnostic-anthropic` binding targeting `ANTHROPIC_API_KEY`,
   with value `synthetic-foreground-diagnostic-not-a-credential`; do not consult
   a native credential store or use a real credential.
4. Prepare the existing foreground harness's owned isolated fixture and its
   explicitly approved `foreground-provenance.json`, using the newly verified
   archive and publisher identities. Only then run the existing ignored
   `native_claude_foreground_request_refusal` test under its normal native-HVF
   authorization. Preserve its start gate, admission, timeout and cleanup
   requirements. This is request/refusal observation only, not a production
   entrypoint, provider response, model, tool, workspace or billing witness.

No verify/install, trust mutation, synthetic binding, foreground test, or
runtime execution is part of source/hermetic preparation.
