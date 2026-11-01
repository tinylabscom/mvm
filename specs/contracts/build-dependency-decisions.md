# Build dependency decisions

Backing: preview
Validation: none — this records decisions taken on measurements; it is not a claim of enforcement.

Several issues asked for a smaller or faster release build. Each was measured and
declined; the reasons are recorded so they are not re-derived.

## Decisions

| Issue | Decision | Evidence | What would reopen it |
|---|---|---|---|
| [#4538](https://github.com/tinylabscom/mvm/issues/4538), [#4543](https://github.com/tinylabscom/mvm/issues/4543) — narrow or remove `gix` | Keep `gix` as the vendored umbrella crate | The `mvmctl` closure is 545 crates (`cargo tree -p mvmctl -e normal,build --prefix none \| sort -u \| wc -l`), 81 of them `gix-*`. `image_source/git_rules.rs` uses repository open with isolated options, commit/tree/blob lookup, config snapshots, the index and its entry flags, the worktree attribute and ignore stack, glob case handling and object ids. Keeping every sub-crate that needs removes about 12 of 545 crates, roughly 2%: diff, filter, protocol, transport, url, refspec, pathspec, revision, shallow, submodule, packetline, macros and `encoding_rs`. | A replacement for the identity code that does not need a repository implementation, or a measured build-time budget that 12 crates would meet. |
| [#4541](https://github.com/tinylabscom/mvm/issues/4541) — build every shipped binary under one profile | Keep `mvmctl` on `release-min` and the daemons and SDK library on `--release` | `mvm-hostd`, the GPU shim core and `mvm-hostlib` rely on `catch_unwind`, which needs panic=unwind. Under `release-min` (panic=abort) a panic inside the SDK library kills the host Python or Node process. Moving `mvmctl` to `--release` loses the size profile (opt-level z, fat LTO, abort) that its size budget and `tests/release_assets.rs` pin. Panic strategy is profile-wide, so the shared dependencies compile twice. | A decision that the daemons and SDK library may abort on panic, with tests for the new crash behaviour. |
| [#4560](https://github.com/tinylabscom/mvm/issues/4560) — narrow features in the `mvm-builder-guest` closure | Drop `url` from `mvm-core`; refuse non-ASCII hosts in application locators | The musl guest closure (`cargo tree -p mvm-builder-guest --target aarch64-unknown-linux-musl -e normal,build --prefix none`, repeat-marker `(*)` stripped before `sort -u`) went from 134 to 106 unique crates (`idna`, the `icu_*` family, `zerovec`, `yoke`, `form_urlencoded`, `percent-encoding` and their proc-macros). The `mvmctl` closure stays at 375 because `mvm-http` and `mvm-hostd` keep `url`. `registry_pack/application.rs` now validates locators with a hand-written grammar: lowercase ASCII DNS, canonical IPv4 or shortest-form bracketed IPv6 hosts, an optional port in 1..=65535 that is neither zero-padded nor the default 443, and a path with no query, fragment, dot segment or character a URL parser would percent-encode. A 700,000-locator differential run against the previous `url`-based validator agreed everywhere except the intentional refusals: any host that needs IDNA, meaning non-ASCII hosts and every `xn--` label, is refused for HTTPS and OCI alike. `chrono` without `clock` and `regex` without `perf` stay out: one crate each. | A requirement to accept internationalized application hosts. |
| [#4561](https://github.com/tinylabscom/mvm/issues/4561) — unify the workspace on one `rand` | Nothing to unify in this tree; the remaining duplicate is third-party | Every workspace crate, `mvm-agentd` and `hickory-proto` included, is already on `rand` 0.10.2 / `rand_core` 0.10.1; the issue's premise of a 0.8 pin is out of date. `cargo tree -d -i rand` shows one other copy, `rand` 0.9.4 with `rand_core` 0.9.5, reached only through `sigstore-tsa` 0.11.0 (`sigstore-verify`, behind `manifest-verify`). Collapsing it means forking or downgrading a signature-verification dependency, which is not done. `deny.toml` already lists `rand` and `rand_core` in the audited skip baseline with that reason. | `sigstore-verify` releasing on the `rand` 0.10 generation. |
| [#4670](https://github.com/tinylabscom/mvm/issues/4670) — match `[profile.release.build-override]` to the target profile | Keep the build-override (`strip = false` only); do not dedupe the 26 packages compiled twice | Unifying host and target settings so the 26 crates that are both build and normal dependencies compile once drops the release unit count from 488 to 473 only. The override cannot adopt the target profile's `strip = true`: host build scripts and proc-macros must stay loadable by the compiler, and older LLVM stripping misaligns Mach-O LINKEDIT entries that macOS dyld rejects. Matching in the other direction — leaving shipped target binaries unstripped — is rejected by the release size budget. | A macOS toolchain floor new enough that LLVM's Mach-O stripping no longer corrupts LINKEDIT, letting the override be deleted and the host units merge with the target units. |
| [#4663](https://github.com/tinylabscom/mvm/issues/4663) — remove unused direct dependencies | Remove nine unused declarations from four workspace manifests and one detached fuzz manifest | `cargo machete` findings were confirmed by source search, then by scoped compilation. `anyhow` and `tracing` left `mvm-capture`; `serde` and `serde_json` left `mvm-gpu-shim-core`; `etherparse` left `mvm-hostd`; `serde`, `serde_json` and `thiserror` left `mvm-gpu`; and `tempfile` left `mvm-runtime/fuzz-backend`. Only `etherparse` was the graph's final edge to a package: the exact target-specific `mvmctl` package/version budgets fell from 378 to 377 on Linux and 375 to 374 on macOS. The requested host-line measurement fell from 546 to 545; `mvm-builder-guest` stayed at 158. The individual host-line closures changed `mvm-capture` 152 to 151, `mvm-gpu-shim-core` 44 to 43, `mvm-hostd` 422 to 421 and `mvm-gpu` 248 to 248. | A new source consumer of one of these APIs; add the dependency back only to that crate. |
| [#4663](https://github.com/tinylabscom/mvm/issues/4663) — keep fleet-only S3 support out of general releases | Remove `template-registry-s3` from the release and reproducibility feature sets; retain it as an explicit fleet feature | The feature is documented in the manifests and ADR-011 as optional and fleet-only, but the general release workflow enabled it. Removing it drops the exact release package/version closure from 405 to 396 on `aarch64-apple-darwin` and from 403 to 393 on `x86_64-unknown-linux-gnu`. Both targets lose `object_store` and eight shared transitive packages; Linux also loses `quick-xml`. The independently built `mvm-builder-guest` closure is unchanged. A release-workflow contract test prevents the feature from returning accidentally. | A standalone release workflow that requires S3 template-registry access; measure and document that product requirement before restoring it. |
| [#4663](https://github.com/tinylabscom/mvm/issues/4663) — remove `mvm-hostd`'s authoring-SDK edge | Import runtime IR directly from its existing `mvm-contract` dependency | Every `mvm-sdk` use in `mvm-hostd` named an IR type which `mvm-sdk::ir` re-exports unchanged from `mvm-contract::ir`; `mvm-hostd` already depended directly on `mvm-contract`. The host-line closure falls from 421 to 417 and loses `mvm-sdk`, `tree-sitter-nix`, and `mvm-host-services` as unique package/version entries. The overall `mvmctl` closure remains 545 and `mvm-builder-guest` remains 158 because other product paths legitimately retain those crates. A manifest contract test prevents the broad edge from returning. | Hostd begins authoring workloads rather than consuming admitted contract IR; put authoring in a higher-level crate instead of restoring the edge if possible. |
| [#4542](https://github.com/tinylabscom/mvm/issues/4542) — fold `mvm-observability` into `mvm-cli` | Merged; the subscriber assembly is now `mvm-cli`'s `observability` module and the crate is gone | `mvm-cli` was the crate's only consumer — the `mvm-hostd` role binaries install `tracing_subscriber::fmt()` directly and never linked it. Every dependency it carried (`mvm-core`, `mvm-http`, `percent-encoding`, `rand`, `serde`, `serde_json`, `tracing`, `tracing-subscriber`) was already in `mvm-cli`'s closure, so a `cargo tree -p mvmctl -e no-dev --prefix none --locked --target <triple>` set diff shows the folded crate as the only removed node: 377 → 376 on `x86_64-unknown-linux-gnu` and 374 → 373 on `aarch64-apple-darwin`, with the all-features workspace tree at 548 → 547. The sealed trees are untouched: `mvm-agentd`, `mvm-builder-guest` and `mvm-host-services` measure identical crate sets before and after (105, 106 and 106 on `aarch64-unknown-linux-musl`, `-e normal,build`). The original split reason — keep `tracing-subscriber` out of `mvm-core`, the sealed agent and the musl bins — still holds because the assembly lives in the host-only CLI. | A second crate needing the subscriber assembly — for example the `mvm-hostd` role binaries moving onto the shared init — which would justify re-extracting a leaf crate. |
| [#4663](https://github.com/tinylabscom/mvm/issues/4663) — keep OS-native key storage out of guest binaries | Make `keyring` optional behind `mvm-core/os-keyring`; enable it explicitly for `mvm-client` and `mvm-runtime` | The `x86_64-unknown-linux-musl` `mvm-builder-guest` package/version closure falls from 140 to 138 unique entries by losing `keyring` and its otherwise-unused `log` edge. The Linux `mvmctl` closure remains 544 because host clients retain the feature. The encrypted file and environment key providers remain available without the feature. A private file-store keyring path was deleted because its sole constructor always disabled it. | A guest requirement to read an OS-native host keyring, which would require a new cross-boundary protocol rather than linking a host credential backend into the guest. |
| [#4663](https://github.com/tinylabscom/mvm/issues/4663) — Sigstore network clients in the verifier closure | Patch `sigstore-rekor` and `sigstore-tsa` locally so their `reqwest` clients are optional, stop enabling `sigstore-verify`'s TLS feature, and add an off-by-default `mvm-core` feature `sigstore-network` to bring the clients back | The release feature set (`host,user,release-artifact-bootstrap,release-channel`) closure goes from 395 to 378 unique crates (`cargo tree -p mvmctl --features ... -e normal,build --prefix none \| sed 's/ (\*)//' \| sort -u \| wc -l`): `reqwest`, `hyper`, `hyper-util`, `hyper-rustls`, `tower`, `tower-http`, `tower-layer`, `tower-service`, `http-body`, `http-body-util`, `sync_wrapper`, `atomic-waker`, `try-lock`, `want`, `serde_urlencoded`, `ryu` and `sigstore-tuf`. The default-feature closure budgets ratchet from 376 to 354 (Linux) and 373 to 351 (macOS). `mvm` only calls `TrustedRoot::from_json` on an embedded root and verifies bundles offline; nothing in the verifier, bundle or trust-root code uses the clients. The patch changes four files and no verification logic. `mvm-core` passes 2695 tests with `manifest-verify` and compiles with `sigstore-network`; `check-forbidden-deps` now bans the client stack from the `host,user` closure. `mvm-builder-guest` stays at 106. The `rand` 0.9 duplicate stays, because `sigstore-tsa` also uses it for timestamp nonces (the #4561 decision stands). Owner decision 2026-10-24: keep the patch local to `mvm`, configurable. | The upstream crates making the client optional (then delete the patch), or a requirement to fetch Sigstore trust material or transparency-log entries online from `mvmctl`. |
| [#4713](https://github.com/tinylabscom/mvm/issues/4713) phase 1 — gate host-only `mvm-core` modules out of guest binaries | Add an off-by-default `mvm-core/host-state` feature owning `bs58`, `unicode-normalization`, `aho-corasick` and `tar` as optional deps; gate `did_key`, `workload_address`, `crypto::{command_gate, threat_classifier, secret_store}` (all of `keystore` except the pure `validate_shell_id`), `pii`, `receipt`/`receipt_archive`, `stream_client`, the `registry_pack*` family, `policy::toml_loader`, `image_set::train_lock` and the tar half of `plan::bundle` behind it; host crates opt in | The musl guest closure (`cargo tree -p mvm-builder-guest --target aarch64-unknown-linux-musl -e normal,build --prefix none`, repeat-marker `(*)` stripped before `sort -u`) goes from 104 to 100 unique crates: `bs58`, `unicode-normalization`, `tinyvec` and `tinyvec_macros` leave, and the direct `mvm-core` edges to `aho-corasick` and `tar` are gone. The issue's 96 target is not reachable by gating alone on this base: `aho-corasick` still enters through `regex`'s `perf-literal` feature (`regex` stays because guest-referenced `config` uses it), and `tar`/`filetime`/`xattr` stay because `mvm-builder-guest` declares its own `tar` edge for `builder_disk_transport`, used by the `stage0-init` guest binary — neither is an `mvm-core` edge, so no `mvm-core` feature can remove them. `keyring` and `log` were already out via `os-keyring`. The `mvmctl` host closure is byte-identical at 351 crates; `toml` and `regex` stay (guest-referenced `domain::manifest`/`user_config`/`config`). `xtask check-guest-agent-runtime-free` now scans all three guest packages, bans `bs58`/`unicode-normalization`/`keyring` by name, and fails if any non-dev feature edge enables `mvm-core/host-state` in a guest package's graph. | A guest-side replacement for `builder_disk_transport`'s tar use, or a decision to narrow `regex`'s `perf-literal` feature workspace-wide; either removes the last four crates the issue counted. |
| [#4713](https://github.com/tinylabscom/mvm/issues/4713) phase 2 — gate `toml` and `regex` out of the guest closure | Make `toml` and `regex` optional `mvm-core` deps owned by `host-state`; gate `domain::manifest`, `user_config` and `config::{normalize_fc_version, fc_version}` behind it (`FC_VERSION_DEFAULT`, `FC_CI_ASSETS_VERSION` and `ARCH` stay ungated; the version normalizer is not rewritten) | No guest crate names the gated modules, and `regex` enters every guest closure only through `mvm-core`. The musl guest closure (same command as phase 1) goes from 100 to 91 with the `toml` gate — `toml`, `toml_edit`, `toml_datetime`, `toml_write`, `serde_spanned`, `winnow` and their now-exclusive `equivalent`/`hashbrown`/`indexmap` edges leave — and from 91 to 87 with the `regex` gate: `regex`, `regex-automata`, `regex-syntax` and `aho-corasick` leave, the last because its only remaining guest edge was `regex`'s `perf-literal`. Phase 1 kept `regex` because the guest-referenced `config` module used it; gating just the two host-only functions leaves the guest-referenced path helpers in place. The `mvmctl` host closure is byte-identical at 351: all twelve host crates enable `host-state`. The `manifest_fixtures` integration test gains a `required-features` entry. `check-guest-agent-runtime-free` name-bans the `toml` and `regex` stacks and its module inventory names `domain::manifest`, `user_config` and `config::fc_version`; `tar` and `aho-corasick` stay unbanned because a direct guest edge to either remains legitimate. | A guest-side consumer of the workload manifest, the operator config or Firecracker version normalization — each would be a new host↔guest protocol surface, not a linked module. |
| [#4839](https://github.com/tinylabscom/mvm/issues/4839) — consumerless `mvm-hostlib` workspace-dependency row | Delete the `mvm-hostlib` entry from `[workspace.dependencies]`; the crate stays a workspace member | No manifest in the workspace names `mvm-hostlib` as a dependency (`rg 'mvm-hostlib' --glob Cargo.toml` finds only the member list, the unused row and the crate's own manifest), and `mvm-hostlib` is a leaf that nothing links. `cargo tree -p mvmctl -e normal,build --prefix none --locked \| sed 's/ (\*)//' \| sort -u \| wc -l` is 350 before and after, and the same for `-p mvm-hostlib` is 337 before and after; `Cargo.lock` is unchanged. It removes no package: it deletes a declaration that could only mislead a reader into thinking the library has a Rust consumer. | A Rust crate that links `libmvm_hostlib` in-process; add the dependency to that crate then. |

## Unused test dependencies

Remove `wait-timeout` from `mvm-vmm` and `assert_cmd` from
`mvm-conformance`. Source inspection confirms neither crate uses those APIs.
Keep conformance's `mvmctl` dependency: generated documentation examples use
the library facade, so the dependency scanner's finding is not sufficient
evidence for removal.

On `aarch64-apple-darwin`, the normal/build closures are unchanged before
and after: `mvmctl` has 509 distinct `cargo tree --prefix none` lines
(351 entries after stripping repeat markers), and `mvm-builder-guest` has
137 lines (105 entries). Commands:

```sh
cargo tree --locked -p mvmctl -e normal,build --prefix none | sort -u | wc -l
cargo tree --locked -p mvm-builder-guest -e normal,build --prefix none | sort -u | wc -l
```

This removes two unused direct test edges, not two packages from the shipped
binary. Both packages remain in the workspace lockfile for other consumers.
No release-build speed or binary-size reduction is attributed to this change.

## MCP package consolidation

For #4839 and #4542, fold the unpublished `mvm-mcp` package into a private
`mvm-cli::mcp` module. The CLI is its only production consumer and already
requires its third-party closure. Retain the adapter, its protocol/error/gate
tests, and the byte-identical tool-contract fixture; remove the separate manifest,
redundant standalone example, and public package boundary. No machine operation,
policy gate, drive grant, or protocol contract is removed.

`cargo tree --locked -p mvmctl --target TRIPLE -e normal,build --prefix none`,
counting unique package/version pairs, measures 351 → 350 on
`aarch64-apple-darwin` and 354 → 353 on `x86_64-unknown-linux-gnu`.
The only removed node is `mvm-mcp`; there are no added nodes. The separately
measured `mvm-agentd` musl closure is identical before/after at 83 nodes.

The post-change `mvm-builder-guest` and `mvm-host-services` closures on
`aarch64-unknown-linux-musl` contain 87 and 84 nodes respectively. Their
pre-change measurements were interrupted, so these are not before/after claims.
The all-features Linux workspace closure measures 534 nodes; ratchet its
previous 547-node ceiling to that measurement, without attributing the entire
13-node difference to this one-package consolidation.

No cold-build, release-size, or runtime speed improvement is claimed from these
graph measurements. Re-extract a package only if a real non-CLI consumer needs
this adapter without the CLI dependency closure.

## Firecracker lifecycle prototype retirement

For #4839, remove the unpublished `mvm-fc-lifecycle` manual-registration
prototype rather than transplanting its privileged code. It had no workspace
reverse dependency, default launch/cleanup integration, installer, service unit,
embedded-helper entry or release-package entry. Source, tests, scripts, dynamic
names and the attached ecosystem repositories supplied no consumer. The PS-06
owner confirmed no consumer, reservation or funded use case in its
client/runtime/backend work; its current-UID birth-in-owner proposal is not
this root-operated preexisting-process registration design. Read-only comparison
with public `main` at `330abfa19ee30c33d444f14918669362f0d51f93` found no
consumer in its 35 changed files relative to the inherited base
`592c0b8280d5b4d343269708ed70d237353fa4f9`.

The removal deletes one first-party package, its library and executable,
prototype-only tests and README, and its telemetry inventory entry. Cargo
metadata workspace members fall from 33 to 32 (including the root package);
explicit member paths fall from 32 to 31. Physical Rust lines fall by 2,123
across 14 files: 1,983 in `src/` including inline tests, plus 140 in dedicated
tests. Counting every repository `*.rs` outside `.git`, `.mvm-test`, `target`
and `node_modules`, including vendored/generated code and tests, the isolated
source snapshot falls from 2,807 files / 1,227,574 lines to 2,793 files /
1,225,451 lines. These are physical lines (`bytes.splitlines()`), not executable
SLOC or a release baseline; unrelated inherited cleanup is excluded from the
delta.

The lockfile loses only this package (729 → 728 entries). Its six normal
third-party edges (`hex`, `libc`, `serde`, `serde_json`, `socket2`, `thiserror`),
Linux-only `mvm-vmm` edge and test-only `tempfile` edge disappear with it;
every dependency remains required by other packages. No third-party package,
version, feature setting or dependency budget is removed or changed.
`cargo metadata --offline --locked --no-deps --format-version 1` supplies the
membership and declared-edge evidence. A feature-resolved
`cargo tree --offline --locked -p mvm-fc-lifecycle -e normal,build --prefix none`
measurement was unavailable because the isolated Cargo registry lacked
`anyhow`; no parent cache was borrowed. Standalone prototype closure size is
not a shipped-artifact saving. No clean/no-change build time, release size,
compilation-unit count or runtime-speed improvement is claimed.

The prototype emitted only two stderr diagnostics (disabled invocation and
startup/termination refusal), with no tracing subscriber or tracing events.
Those diagnostics and their uncertified runtime-gap inventory entry disappear
with the executable, not through tracing suppression in retained code. Normal
Firecracker and other backends, held-process identity checks, signed audit,
host-held secrets, no-NIC/vsock enforcement and active lifecycle-owner work
remain unchanged. The original plan stays as explicitly historical design.
Any future privileged service needs its own demonstrated consumer and reviewed
authority/deployment contract, not restoration of this unused prototype.

## Duplicate hashing and hex helpers (#4839 section 2)

`mvm_contract::hash::sha256_hex` is the shared sha256-to-lowercase-hex helper, and
the `hex` crate is the shared byte encoder. The premise that `mvm-fs`, `mvm-client`,
`mvm-runtime` and `mvm-vmm` do not depend on `mvm-contract` does not hold:
`cargo metadata --offline --no-deps` shows a direct `mvm-contract` edge from
`mvm-build`, `mvm-cli`, `mvm-client`, `mvm-compiler`, `mvm-core`, `mvm-fs`,
`mvm-hostd`, `mvm-runtime` and `mvm-vmm`, and a dev-dependency edge from
`mvm-conformance` and the root `mvmctl` package. The workspace packages with none
are `mvm-builder-guest`, `mvm-bundler`, `mvm-host-services`, `mvm-http`,
`mvm-macho-sign`, `mvm-setpriv`, `runmvm-client`, `libkrun-sys` and `xtask`.

Deleted onto `mvm_contract::hash::sha256_hex` (test-module copies, each crate
already depends on it): `mvm-fs` `sdk_sidecar`, `mvm-client` `launch::runtime_source`
(two), `mvm-runtime` `sdk_sidecar`, `mvm-vmm` `host::restore_image`, `mvm-build` `sdk_sidecar`, `initramfs` (which
already imported it in production code) and `runtime_overlay`, `mvm-cli`
`published_fetch_tests`, `mvm-conformance` `steps/{sdk_sidecar,initramfs}` and the root
`tests/install_sh.rs`.

Deleted onto `hex::encode` (the crate already depends on `hex`): `mvm-core`
`snapshot_hmac` (with its `hex_nibble`), `snapshot_sign`, `signed_config`,
`attestation::header` and `trace_context`; `mvm-hostd` `binary_integrity`; `mvm-cli`
`commands::pool`. All emit lowercase hex, which is what `hex::encode` emits.

Kept, with the reason:

| Copy | Why it stays |
|---|---|
| `mvm-builder-guest` `builder_boot::payload::sha256_hex` | Cannot without adding a dependency edge: the crate has no `mvm-contract` edge, and `mvm-core` does not re-export the helper. The edge would add a crate to the musl guest closure's direct dependencies for a three-line function. |
| `mvm-fs` `ext4::verity::to_hex` | Takes a fixed-size verity digest and is public API of the ext4 writer; `mvm-build`, `mvm-client` tests and `mvm-conformance` call it. Not a sha256 helper. |
| `mvm-runtime` `vm::template::lifecycle::artifacts::sha256_hex(path)` and `mvm-vmm` `restore_image::sha256_of` | Hash a file by streaming it, not a byte slice, and return typed errors. A different contract. |
| `mvm-cli/build.rs` `sha256_hex(path)` | A build script; it cannot use the crate's own dependencies. |
| `mvm-compiler` `pack::python::sha256_hex(&str)` and `mvm-cli` `image::cache::sha256_hex(&str)` | Parse a `sha256:` reference, not hash bytes; the name is a coincidence. |
| `mvm-hostd` `reversible_replacement::digest_hex` | An HMAC, not a plain digest. |
| About 170 inline `hex::encode(Sha256::digest(..))` expressions in 80 files (`grep -rnE 'hex::encode\((sha2::)?Sha256::digest' crates src tests xtask`) | Not a helper but the idiom itself, one expression each, with streaming and domain-prefixed variants mixed in. Folding them onto `sha256_hex` is a mechanical sweep with no closure effect and is not done here. |
| `mvm-build/examples/mvm-app-deps-fixture-tool.rs` | An example binary with its own minimal dependency set. |

## Dependency usage map (#4839 section 3)

Measured at `8201aee9` on `aarch64-apple-darwin`, `--offline --locked`, unique
`name version` entries with `(*)` and `(proc-macro)` markers stripped
(`cargo tree -p <pkg> -e normal,build --prefix none | sed ... | sort -u | wc -l`).

| Artifact | Closure |
|---|---|
| `mvmctl` | 350 |
| `mvm-hostlib` (SDK library) | 337 |
| `mvm-hostd` | 282 |
| `mvm-host-services` (guest cdylib) | 102 |
| `mvm-agentd` (guest agent) | 101 |
| `mvm-builder-guest` (`aarch64-unknown-linux-musl`) | 87 |

Workspace shape: 32 packages and 91 distinct non-`mvm` direct normal/build
dependencies. The most widely declared are `serde` and `serde_json` (22
packages each), `libc` (19), `anyhow`, `sha2` and `thiserror` (15 each), `hex`
(14), `base64`, `ed25519-dalek`, `tempfile` and `tracing` (12 each). Those are
the trust-boundary dependencies (serialization, hashing, signatures); they are
kept on purpose and are not candidates for replacement.

Duplicate versions inside the `mvmctl` closure (`cargo tree -p mvmctl -d`):
`bitflags`, `block-buffer`, `const-oid`, `cpufeatures`, `crypto-common`,
`digest`, `getrandom`, `rand`, `rand_core`, `ryu-js`, `sha2`, `signature` and
`untrusted`. They come from the RustCrypto 0.10/0.11 generation split between
`sigstore-verify` (behind `manifest-verify`) and the workspace's own
primitives, plus `rand` 0.9 (see the #4561 decision); none is unifiable without
forking or downgrading a signature dependency.

Unused-declaration scan: `cargo machete` over the whole tree reports no unused
dependency in any first-party crate except `mvm-conformance`'s `mvmctl`, which
is kept (generated doc examples link the library facade). Its remaining
findings are all in vendored `third_party/` crates (`gix`: `async-std`;
`gix-object`: `gix-hashtable`; `sigstore-tsa`: `cmpv2`, `rustls-webpki`,
`x509-tsp`; `sigstore-rekor`: `hex`, `sigstore-crypto`, `url`; `am-fs-ext4`:
`am-fs-core`). Those are feature-gated optional dependencies the scanner cannot
resolve, and editing vendored manifests would widen the patch against upstream
for no closure change, so none is removed. The `mvm-hostlib` entry in
`[workspace.dependencies]` had no consumer and has since been deleted, which
removed no package.

### Per-dependency detail: native code, features, API use

Same commands and `8201aee9`-era lock as the closure table (`cargo tree ... -f
'{p}|{f}'`, host target; the `mvm-builder-guest` row uses
`--target aarch64-unknown-linux-musl`). "Files" counts source files that name
the crate path, not call sites.

Native code (a C or assembly build step) reaches only the host closures:

| Crate | Pulled in by | Features on | API used in this tree |
|---|---|---|---|
| `ring` 0.17 | `rustls` (`ring` provider), `rcgen` | `alloc`, `dev_urandom_fallback` | none directly; via `rustls` (`mvm-hostd`, `mvm-http`, `mvm-cli`, `mvm-core`) and `rcgen` (`mvm-core`, `mvm-http`) |
| `aws-lc-sys` 0.45 | `aws-lc-rs`, from `rustls-webpki` and `sigstore-crypto`/`sigstore-verify` | `prebuilt-nasm` | none directly; `sigstore_verify` is named in one `mvm-core` file (behind `manifest-verify`) |
| `tree-sitter` 0.26 and the JavaScript, Python, TypeScript and Nix grammars | `mvm-compiler`, `mvm-sdk` | `std` | `tree_sitter` in 5 `mvm-compiler` files and 1 `mvm-sdk` file: the source analysis behind decorator compilation |
| `blake3` 1.8 | `mvm-cli`, `mvm-runtime`, `mvm-sdk` | `default`, `std` | one file in each of those crates |

The two guest closures that ship inside every VM, `mvm-host-services` (102) and
`mvm-agentd` (101), contain none of these: their only crate with a build-time C
interaction is `libc`. `mvm-builder-guest` (87) reaches `libc` and
`mvm-core` and no C-compiling crate. `cc` and `cmake` appear only in the
`mvmctl` closure, as build tools of the crates above.

Feature sets worth a later look, recorded here rather than changed because no
measurement shows a closure or time win yet:

- `chrono` is declared with its default features, so `mvmctl` enables `oldtime`,
  `wasmbind`, `winapi` and `iana-time-zone` alongside `serde` and `clock`. It is
  the most widely used time type (about 215 `Utc`, 108 `Duration` and 64
  `DateTime` uses across 10 crates), so any feature trim must keep `clock` and
  `serde`; the `mvm-contract` entry already trims to `serde` and `alloc`.
- `serde_json` gains `preserve_order` (and `indexmap`) in the `mvmctl` build
  because the `tree-sitter` build script depends on it; that is why two
  `serde_json` feature lines appear in the tree.
- `tokio` in `mvmctl` carries `fs`, `process` and `signal` beyond the
  workspace's `io-util`, `macros`, `net`, `rt`, `rt-multi-thread`, `sync` and
  `time`: `process` and `signal` come from the `mvm-hostd` manifest, `fs` from
  `mvm-runtime` and `mvm-contract`.

Result: no first-party dependency is provably unused after the #4663 sweep, so
this slice removes nothing and the closures above are unchanged. Remaining
reduction is in the retained-by-decision rows above, not in unused
declarations.

## Dependency closure map: build scripts, proc-macros, native code, direct dependencies (#4839 section 3)

Measured at `c77e696350` (origin/main, 2026-10-31), `--offline --locked`, default
features, `-e normal,build`; target `aarch64-apple-darwin` for every artifact
except `mvm-builder-guest`, which is `aarch64-unknown-linux-musl`. Counts are
unique `name version` entries. This section supersedes the earlier "91 distinct
direct dependencies" figure: under the definition below the workspace has 90
(the old figure was not reproducible).

Rerun (a `cargo tree` per artifact, joined to `cargo metadata`; no tool beyond cargo):

```sh
cargo metadata --offline --locked --format-version 1        # targets[].kind, dependencies[].kind, workspace_members
cargo tree --offline --locked -p <pkg> --target <triple> -e normal,build --prefix depth -f '{p}|{f}'
cargo tree --offline --locked -p <pkg> --target <triple> -e normal,build -d --prefix depth   # depth-0 lines = duplicates
```

Definitions. **Build-script package**: has a `custom-build` target (first-party
included). **Proc-macro package**: has a `proc-macro` target. **Native-code
package**: in the closure and has a build-dependency on `cc`, `cmake`, `bindgen`
or `nasm-rs` that is itself in the closure. **Duplicate**: one package name at
more than one version. **Direct dependency**: a normal or build dependency of a
workspace member, excluding workspace members and vendored `third_party/` crates.

| Artifact | Target | Closure | Build-script pkgs | Proc-macro pkgs | Native-code pkgs | Duplicate names |
|---|---|---:|---:|---:|---:|---:|
| `mvmctl` | `aarch64-apple-darwin` | 350 | 38 | 15 | 8 | 13 |
| `mvm-hostlib` | `aarch64-apple-darwin` | 337 | 35 | 14 | 8 | 13 |
| `mvm-hostd` | `aarch64-apple-darwin` | 282 | 26 | 12 | 2 | 6 |
| `mvm-host-services` | `aarch64-apple-darwin` | 102 | 14 | 4 | 0 | 4 |
| `mvm-agentd` | `aarch64-apple-darwin` | 101 | 14 | 4 | 0 | 4 |
| `mvm-builder-guest` | `aarch64-unknown-linux-musl` | 87 | 15 | 4 | 0 | 0 |

`mvm-hostlib` has the same 13 duplicates as `mvmctl`.

| Artifact | Native-code packages | Proc-macro packages | Duplicate names |
|---|---|---|---|
| `mvmctl` | aws-lc-sys, blake3, ring, tree-sitter, tree-sitter-javascript, tree-sitter-nix, tree-sitter-python, tree-sitter-typescript | async-trait, clap_derive, der_derive, displaydoc, gix-macros, rustversion, serde_derive, thiserror-impl, tls_codec_derive, tokio-macros, tracing-attributes, yoke-derive, zerofrom-derive, zeroize_derive, zerovec-derive | bitflags, block-buffer, const-oid, cpufeatures, crypto-common, digest, getrandom, rand, rand_core, ryu-js, sha2, signature, untrusted |
| `mvm-hostlib` | aws-lc-sys, blake3, ring, tree-sitter, tree-sitter-javascript, tree-sitter-nix, tree-sitter-python, tree-sitter-typescript | async-trait, der_derive, displaydoc, gix-macros, rustversion, serde_derive, thiserror-impl, tls_codec_derive, tokio-macros, tracing-attributes, yoke-derive, zerofrom-derive, zeroize_derive, zerovec-derive | as `mvmctl` |
| `mvm-hostd` | blake3, ring | async-trait, displaydoc, gix-macros, rustversion, serde_derive, thiserror-impl, tokio-macros, tracing-attributes, yoke-derive, zerofrom-derive, zeroize_derive, zerovec-derive | bitflags, block-buffer, cpufeatures, crypto-common, digest, getrandom |
| `mvm-host-services` | none | serde_derive, thiserror-impl, tracing-attributes, zeroize_derive | block-buffer, cpufeatures, crypto-common, digest |
| `mvm-agentd` | none | serde_derive, thiserror-impl, tracing-attributes, zeroize_derive | block-buffer, cpufeatures, crypto-common, digest |
| `mvm-builder-guest` | none | serde_derive, thiserror-impl, tracing-attributes, zeroize_derive | none |

Build-script packages, by artifact:

- `mvmctl`: anyhow, aws-lc-rs, aws-lc-sys, blake3, crc32fast, curve25519-dalek, faster-hex, generic-array, getrandom, heapless, httparse, icu_normalizer_data, icu_properties_data, libc, libkrun-sys, mvm-cli, mvmctl, num-traits, objc2, parking_lot_core, proc-macro2, quote, ring, rustix, rustls, rustversion, serde, serde_core, serde_json, thiserror, tree-sitter, tree-sitter-javascript, tree-sitter-language, tree-sitter-nix, tree-sitter-python, tree-sitter-typescript, zerocopy, zmij
- `mvm-hostlib`: anyhow, aws-lc-rs, aws-lc-sys, blake3, crc32fast, curve25519-dalek, faster-hex, generic-array, getrandom, heapless, httparse, icu_normalizer_data, icu_properties_data, libc, libkrun-sys, num-traits, parking_lot_core, proc-macro2, quote, ring, rustix, rustls, rustversion, serde, serde_core, serde_json, thiserror, tree-sitter, tree-sitter-javascript, tree-sitter-language, tree-sitter-nix, tree-sitter-python, tree-sitter-typescript, zerocopy, zmij
- `mvm-hostd`: anyhow, blake3, crc32fast, curve25519-dalek, faster-hex, generic-array, getrandom, heapless, httparse, icu_normalizer_data, icu_properties_data, libc, libkrun-sys, num-traits, parking_lot_core, proc-macro2, quote, ring, rustix, rustls, rustversion, serde, serde_core, serde_json, thiserror, zmij
- `mvm-host-services`: anyhow, curve25519-dalek, generic-array, getrandom, libc, num-traits, proc-macro2, quote, rustix, serde, serde_core, serde_json, thiserror, zmij
- `mvm-agentd`: anyhow, curve25519-dalek, generic-array, getrandom, libc, num-traits, proc-macro2, quote, rustix, serde, serde_core, serde_json, thiserror, zmij
- `mvm-builder-guest`: anyhow, curve25519-dalek, getrandom, libc, memoffset, nix, num-traits, proc-macro2, quote, rustix, serde, serde_core, serde_json, thiserror, zmij

All 90 direct dependencies. Artifact letters: C `mvmctl`, L `mvm-hostlib`, D
`mvm-hostd`, S `mvm-host-services`, A `mvm-agentd`, G `mvm-builder-guest`;
"none" means no workspace crate in those six closures at these targets and
flags uses it (target-specific, feature-gated or tooling-only). Features are the
cargo-resolved set as enabled on the dependency node, unioned over the artifacts
in that row; `default` is shown only when it is the sole feature.

| Direct dependency | In closure of | Enabled features |
|---|---|---|
| `aes-gcm` | CLDSAG | aes, alloc, getrandom |
| `aho-corasick` | CLD | perf-literal, std |
| `anyhow` | CLDSAG | std |
| `async-trait` | CLD | - |
| `aya` | none | - |
| `base64` | CLDSAG | alloc, std |
| `blake3` | CLD | std |
| `bs58` | CLD | alloc, std |
| `bytes` | CLDSAG | std |
| `chrono` | CLDSAG | alloc, clock, iana-time-zone, js-sys, now, oldtime, serde, std, wasm-bindgen, wasmbind, winapi, windows-link |
| `clap` | C | derive, error-context, help, std, usage |
| `clap_mangen` | none | - |
| `core-foundation` | CLDSA | link |
| `ed25519-dalek` | CLDSAG | fast, rand_core, signature, zeroize |
| `ext4-view` | CLD | std |
| `flate2` | CLD | any_impl, miniz_oxide, rust_backend |
| `gix` | CLD | attributes, command, excludes, index, sha1 |
| `globset` | CL | log |
| `hex` | CLDSAG | alloc, std |
| `hickory-proto` | none | - |
| `hickory-resolver` | none | - |
| `hmac` | CLDSAG | - |
| `http` | CLD | std |
| `httparse` | CLD | std |
| `ipnet` | CLDSAG | serde, std |
| `keyring` | CLD | - |
| `landlock` | none | - |
| `leakguard` | CLD | - |
| `libc` | CLDSAG | extra_traits, std |
| `libloading` | none | - |
| `lzma-rs` | CLD | - |
| `mio` | CLD | log, net, os-ext, os-poll |
| `nextest-metadata` | none | - |
| `nix` | G | fs, ioctl, memoffset, mount, process, reboot, signal, socket, uio |
| `notify` | none | - |
| `notify-debouncer-mini` | none | - |
| `objc2-foundation` | C | FoundationErrors, FoundationLegacySwiftCompatibility, NSAffineTransform, NSAppleEventDescriptor, NSAppleEventManager, NSAppleScript, NSArchiver, NSArray, NSAttributedString, NSAutoreleasePool, NSBackgroundActivityScheduler, NSBundle, NSByteCountFormatter, NSByteOrder, NSCache, NSCalendar, NSCalendarDate, NSCharacterSet, NSClassDescription, NSCoder, NSComparisonPredicate, NSCompoundPredicate, NSConnection, NSData, NSDate, NSDateComponentsFormatter, NSDateFormatter, NSDateInterval, NSDateIntervalFormatter, NSDebug, NSDecimal, NSDecimalNumber, NSDictionary, NSDistantObject, NSDistributedLock, NSDistributedNotificationCenter, NSEnergyFormatter, NSEnumerator, NSError, NSException, NSExpression, NSExtensionContext, NSExtensionItem, NSExtensionRequestHandling, NSFileCoordinator, NSFileHandle, NSFileManager, NSFilePresenter, NSFileVersion, NSFileWrapper, NSFormatter, NSGarbageCollector, NSGeometry, NSHFSFileTypes, NSHTTPCookie, NSHTTPCookieStorage, NSHashTable, NSHost, NSISO8601DateFormatter, NSIndexPath, NSIndexSet, NSInflectionRule, NSInvocation, NSItemProvider, NSJSONSerialization, NSKeyValueCoding, NSKeyValueObserving, NSKeyValueSharedObservers, NSKeyedArchiver, NSLengthFormatter, NSLinguisticTagger, NSListFormatter, NSLocale, NSLocalizedNumberFormatRule, NSLock, NSMapTable, NSMassFormatter, NSMeasurement, NSMeasurementFormatter, NSMetadata, NSMetadataAttributes, NSMethodSignature, NSMorphology, NSNetServices, NSNotification, NSNotificationQueue, NSNull, NSNumberFormatter, NSObjCRuntime, NSObject, NSObjectScripting, NSOperation, NSOrderedCollectionChange, NSOrderedCollectionDifference, NSOrderedSet, NSOrthography, NSPathUtilities, NSPersonNameComponents, NSPersonNameComponentsFormatter, NSPointerArray, NSPointerFunctions, NSPort, NSPortCoder, NSPortMessage, NSPortNameServer, NSPredicate, NSProcessInfo, NSProgress, NSPropertyList, NSProtocolChecker, NSProxy, NSRange, NSRegularExpression, NSRelativeDateTimeFormatter, NSRunLoop, NSScanner, NSScriptClassDescription, NSScriptCoercionHandler, NSScriptCommand, NSScriptCommandDescription, NSScriptExecutionContext, NSScriptKeyValueCoding, NSScriptObjectSpecifiers, NSScriptStandardSuiteCommands, NSScriptSuiteRegistry, NSScriptWhoseTests, NSSet, NSSortDescriptor, NSSpellServer, NSStream, NSString, NSTask, NSTermOfAddress, NSTextCheckingResult, NSThread, NSTimeZone, NSTimer, NSURL, NSURLAuthenticationChallenge, NSURLCache, NSURLConnection, NSURLCredential, NSURLCredentialStorage, NSURLDownload, NSURLError, NSURLHandle, NSURLProtectionSpace, NSURLProtocol, NSURLRequest, NSURLResponse, NSURLSession, NSUUID, NSUbiquitousKeyValueStore, NSUndoManager, NSUnit, NSUserActivity, NSUserDefaults, NSUserNotification, NSUserScriptTask, NSValue, NSValueTransformer, NSXMLDTD, NSXMLDTDNode, NSXMLDocument, NSXMLElement, NSXMLNode, NSXMLNodeOptions, NSXMLParser, NSXPCConnection, NSZone, alloc, bitflags, block2, libc, objc2-core-foundation, std |
| `object_store` | none | - |
| `percent-encoding` | C | alloc, std |
| `plist` | CLDSA | serde |
| `rand` | CLDSAG | alloc, std, std_rng, sys_rng, thread_rng |
| `rcgen` | CLD | crypto, pem, ring |
| `regex` | CLD | perf, perf-backtrack, perf-cache, perf-dfa, perf-inline, perf-literal, perf-onepass, std, unicode, unicode-age, unicode-bool, unicode-case, unicode-gencat, unicode-perl, unicode-script, unicode-segment |
| `rustix` | CLDSAG | alloc, event, fs, process, std |
| `rustls` | CLD | ring, std, tls12 |
| `rustls-pki-types` | CLD | alloc, std |
| `rustls-platform-verifier` | CLD | - |
| `schemars` | none | - |
| `seccompiler` | G | - |
| `secrecy` | CLDSAG | serde |
| `security-framework` | CLDSA | OSX_10_14, alpn, session-tickets |
| `serde` | CLDSAG | alloc, derive, serde_derive, std |
| `serde_jcs` | CLDSAG | - |
| `serde_json` | CLDSAG | alloc, float_roundtrip, std |
| `sha1` | CLDSA | compress, std |
| `sha2` | CLDSAG | alloc, oid |
| `sigstore-trust-root` | CL | - |
| `sigstore-types` | CL | - |
| `sigstore-verify` | CL | - |
| `socket2` | CLDSAG | all |
| `syn` | none | - |
| `sysinfo` | CLD | - |
| `tar` | CLDG | xattr |
| `tempfile` | CLDSAG | getrandom |
| `thiserror` | CLDSAG | std |
| `tokio` | CLD | bytes, fs, io-util, libc, macros, mio, net, process, rt, rt-multi-thread, signal, signal-hook-registry, socket2, sync, time, tokio-macros |
| `tokio-rustls` | CLD | ring |
| `tokio-vsock` | none | - |
| `toml` | CLD | display, parse |
| `toml_edit` | C | display, parse, serde |
| `tracing` | CLDSAG | attributes, std, tracing-attributes |
| `tracing-subscriber` | CLD | alloc, ansi, env-filter, fmt, json, matchers, nu-ansi-term, once_cell, registry, serde, serde_json, sharded-slab, smallvec, std, thread_local, tracing, tracing-log, tracing-serde |
| `tree-sitter` | CL | std |
| `tree-sitter-javascript` | CL | - |
| `tree-sitter-nix` | CL | - |
| `tree-sitter-python` | CL | - |
| `tree-sitter-typescript` | CL | - |
| `tss-esapi` | none | - |
| `unicode-normalization` | CLD | std |
| `url` | CLD | std |
| `uuid` | CLDSAG | rng, serde, sha1, std, v4, v5 |
| `virtio-queue` | CLD | - |
| `virtio-vsock` | CLD | - |
| `vm-memory` | CLD | backend-mmap, rawfd |
| `wasmtime` | none | - |
| `wasmtime-wasi` | none | - |
| `which` | CLD | - |
| `x25519-dalek` | CLDSAG | precomputed-tables, static_secrets, zeroize |
| `xattr` | CLD | unsupported |
| `zeroize` | CLDSAG | alloc, zeroize_derive |

## Dependency reduction ranking (#4839 section 3)

Measured at `152ed1cebf` (origin/main, 2026-10-31), `--offline`, default features,
unique `name version` entries. Every candidate below is judged with the same
commands; a candidate with no measured change is recorded as such and not applied.

```sh
cargo tree --offline -p <pkg> --target <triple> -e normal,build --prefix none \
  | sed 's/ (\*)//;s/ (proc-macro)//;s/ (\/.*//' | sort -u | wc -l
grep -c '^name = ' Cargo.lock
```

Baseline: `mvmctl` 350 (`aarch64-apple-darwin`) and 353 (`x86_64-unknown-linux-gnu`);
`mvm-hostlib` 337; `mvm-hostd` 282; `mvm-agentd` 83, `mvm-host-services` 84 and
`mvm-builder-guest` 87 on `aarch64-unknown-linux-musl`; `Cargo.lock` 728 packages.

| Rank | Candidate | Measured | Risk | Effort | Status |
|---|---|---|---|---|---|
| 1 | `tracing-subscriber` without its default `tracing-log` feature | -1 on every host closure: `mvmctl` 350 to 349 and 353 to 352, `mvm-hostlib` 337 to 336, `mvm-hostd` 282 to 281; guests unchanged; lock 728 to 727 (`tracing-log` leaves) | Low. Records emitted through the `log` crate by third-party code (rustls, mio) are no longer forwarded to the tracing subscriber; no first-party crate uses `log::` macros | One line in `[workspace.dependencies]` plus the two closure budgets | Applied |
| 2 | `chrono` without default features (`serde`, `clock`, `std` kept; `oldtime`, `wasmbind` dropped) | 0. Every closure above is identical. The only lock change is that `chrono` stops listing `js-sys` and `wasm-bindgen`, which stay for other packages. Needs the `mvm-contract` dev-dependency's own `chrono` row trimmed too, or the defaults return | Low | Two lines | Not applied: removes no package |
| 3 | `serde_jcs` replaced by `serde_json_canonicalizer` | Host closures -2 (`serde_jcs`, `ryu-js` 0.2.2); guest closures swap two crates for two, so 0, because `serde_json_canonicalizer` is reached today only through `sigstore-verify`, which guests do not link | High: it produces signed canonical bytes for plans, audit entries and bundles; floating-point and escape handling must agree byte for byte | Four crates plus a differential test | Not applied: a signing-format change for 2 host crates |
| 4 | `tokio` `signal` dropped from `mvm-hostd` | 0. No `mvm-hostd` source names `tokio::signal`, but its `process` feature already depends on `signal-hook-registry`, so the package stays | None | One word | Not applied: removes no package |
| 5 | `serde_json` `preserve_order` | Not removable: enabled by the `tree-sitter` build script, and `indexmap` stays through `plist` and `toml_edit` | n/a | n/a | Retained |
| 6 | `tempfile` out of the guest agent and host-services closures | Would remove `tempfile` and its otherwise unused `fastrand`/`getrandom` 0.4 edges from `mvm-agentd` and `mvm-host-services`, but `mvm-core::canonical_linux` (production, host-side) uses it and `protocol::vm_backend` and `plan::bundle` name that module ungated | Medium: gating a module reached from two ungated ones | A `host-state` gate plus the two callers | Not applied: not measured, the gate is a separate change |

The 16 direct dependencies the closure map lists under "none" are not unused. Each
is outside the six default closures for a stated reason, and `cargo machete` finds
none of them unused:

| Reason | Dependencies |
|---|---|
| Off-by-default feature | `aya` (`mvm-hostd`), `hickory-resolver` (`mvm-hostd`), `object_store` (`mvm-runtime`, `template-registry-s3`), `schemars` (six crates), `tokio-vsock` (`mvm-agentd`), `tss-esapi` (`mvm-core`, `attestation-tpm2`), `wasmtime` and `wasmtime-wasi` (`mvm-runtime`, `wasm-backend`), `notify` and `notify-debouncer-mini` (`mvm-cli`, `dev-watch`) |
| Linux target only, present in the Linux `mvmctl` closure | `landlock`, `hickory-proto` (`mvm-hostd`) |
| Tooling, not shipped | `clap_mangen`, `nextest-metadata`, `syn` (`xtask`) |
| Separately installed client | `libloading` (`runmvm-client`, which `mvmctl` does not link) |

No removal follows from them. The "CLDSA" letters the map gives `plist`,
`security-framework` and `core-foundation` for the guest artifacts come from the
`aarch64-apple-darwin` tree, which is not a guest target: on the musl guest targets
all three are absent, because `mvm-core` declares them under
`cfg(target_os = "macos")`.

### Duplicate version pairs in the `mvmctl` closure

Commands: `cargo tree --offline -p mvmctl --target aarch64-apple-darwin -e normal,build -d --prefix depth`
for the names, then `cargo tree ... -i <name>@<version> --depth 1` for the parents of
the older version. `hashbrown`, `memchr`, `serde`, `serde_core`, `serde_json` and
`toml_edit` also print under `-d`; they differ in features, not version, so they are not pairs.

| Name | Older version, pinned by | Newer version, used by | Compatible bump? |
|---|---|---|---|
| `bitflags` | 1.3.2: `vmm-sys-util` 0.15.0, from `virtio-queue` 0.18.0 (`mvm-vmm`) | 2.13.0: everything else | Not offline-verifiable; needs a rust-vmm release of `vmm-sys-util` on `bitflags` 2 |
| `digest`, `block-buffer`, `crypto-common`, `cpufeatures` | 0.10.7, 0.10.4, 0.1.7, 0.2.17: `sha1` 0.10.6 (workspace pin `=0.10.6`, used by `mvm-build`, `mvm-macho-sign`, `gix`, `x509-cert`), `sha1-checked` (`gix`), `sha2` 0.10.9 and `sigstore-crypto` | 0.11.3, 0.12.1, 0.2.2, 0.3.0: `sha2` 0.11, `hmac` 0.13, `curve25519-dalek` 5, `ed25519-dalek` 3 | No. Dropping the generation needs `gix`, `x509-cert` and `sigstore-crypto` to move together; the workspace's own crates are already on the new one |
| `sha2` | 0.10.9: `sigstore-crypto` only | 0.11.0: 14 workspace crates | No (signature-verification dependency) |
| `signature` | 2.2.0: `sigstore-crypto`, `x509-cert` 0.2.5 | 3.0.0: `ed25519` 3, `ed25519-dalek` 3 | No |
| `const-oid` | 0.9.6: `der` 0.7.10, `x509-cert`, `cms`, `sigstore-*` | 0.10.2: `digest` 0.11 | No (same RustCrypto formats generation) |
| `rand`, `rand_core`, `getrandom` | `rand` 0.9.4 and `rand_core` 0.9.5: `sigstore-tsa`; `rand_core` 0.6.4: `signature` 2.2.0; `getrandom` 0.2.17: `ring` 0.17.14; 0.3.4: `rand_core` 0.9.5 | `rand` 0.10.2, `rand_core` 0.10.1, `getrandom` 0.4.1: workspace, `tempfile`, `uuid`, `gix-utils` | No; see the #4561 decision |
| `ryu-js` | 0.2.2: `serde_jcs` 0.1.0 (direct: `mvm-build`, `mvm-client`, `mvm-core`, `mvm-hostd`) | 1.0.2: `serde_json_canonicalizer` 0.3.2 (`sigstore-verify`) | Only by swapping the canonicalizer; ranked 3 above |
| `untrusted` | 0.7.1: `aws-lc-rs` 1.18.1 | 0.9.0: `ring` 0.17.14, `rustls-webpki` | No (native crypto crates) |

Only two pins are first-party choices: `serde_jcs` (`ryu-js`) and the `sha1 =0.10.6`
workspace pin, and the latter shares its generation with `gix` and `x509-cert`, so
moving it alone removes nothing. The rest are held by `sigstore-*`, `x509-cert`,
`gix`, `ring`/`aws-lc-rs` or `vmm-sys-util`.

## Dependency evidence matrix (#4839 section 3)

Measured at `80a11312e3` (origin/main, 2026-11-01), `--offline`, on a host with a load average of about 58 (`uptime`),
which is why nothing below is a timing. Section 3 asks for the candidates to be ranked on
supply-chain exposure, trust boundary, API usage, maintenance, advisory and licence
evidence, closure, build cost and binary contribution. The ranking above covers closure,
risk and effort; this section supplies the rest, for the six ranked candidates and for
all 90 direct dependencies (definition in the closure map).

### What each column is, and how it was produced

| Column | Source | Limits |
|---|---|---|
| Exposure, trust boundary | Read from each crate's role and the closure map's artifact letters; groups A to F below | A classification by role, not an audit. `cargo geiger` is not installed, so unsafe-block counts were not measured |
| API usage | `rg -l '\bname(::|\s*;)|use name\b|extern crate name' crates src xtask tests` over `*.rs`, excluding `third_party/` and `target/`: files / distinct top-level directories | Counts files that mention the crate, tests and benches included, not call expressions. A re-export or a macro-only use can be undercounted |
| Latest release, releases in 12 months | `https://crates.io/api/v1/crates/<name>` (public, no credentials), `max_stable_version`, the newest `created_at` over all versions, and the number with `created_at >= 2025-10-31` | Publish cadence only. It says nothing about whether the maintainer answers security reports |
| Advisories | `cargo audit --no-fetch --db ~/.cargo/advisory-dbs/advisory-db-3157b0e258782691` (cargo-audit 0.22.2; RustSec database commit `2295466c`, 2026-10-30, 1,395 advisories, 727 lock entries) and `cargo deny --offline check advisories` (cargo-deny 0.19.4, `deny.toml` `db-path` database commit `a78282a1`, 2026-10-26) | Both scan `Cargo.lock`, so the 10 off-by-default dependencies that are not in the lock (`aya`, `clap_mangen`, `hickory-resolver`, `notify`, `notify-debouncer-mini`, `object_store`, `schemars`, `tss-esapi`, `wasmtime`, `wasmtime-wasi`) are unscanned. The two databases are four days apart |
| Licence | `cargo deny --offline check licenses` and the `license` field of `cargo metadata --offline` | SPDX expression as published, not a legal review |
| Units | Cargo's unit graph for the `mvmctl` release command in the section below (`--profile release-min --target aarch64-apple-darwin`): 497 units at this commit (498 at `4270e14d`; the difference is `tracing-log`, ranked 1). `own` is units of that package; `excl` is units that disappear from the graph when every unit of the package is removed, so it counts the dependency's private subtree | One host target and one feature set. Guests and `mvm-hostd` have their own graphs. `own` and `excl` are unit counts, not seconds |
| Binary contribution | The only measurement is whole-binary: 19,206,160 bytes for `mvmctl` `release-min` on `aarch64-apple-darwin` (2026-08-20, `public/docs/investigations/binary-size-baseline.md`, budget 25,165,824) | Per-dependency contribution is **not measured: needs a quiet host** and a release build with `cargo bloat --crates` (`cargo-bloat` is installed). It was not run at load 58 |
| Build cost in seconds | `cargo build --timings` | **Not measured: needs a quiet host**; the unit counts stand in for it |

### Advisory and licence results (exact)

- `cargo deny --offline check advisories` printed `advisories ok`. `cargo deny --offline check licenses` printed
  `licenses ok` with one warning, `Unicode-DFS-2016` allowed but unmatched (an unused allowance in `deny.toml`).
  `cargo deny --offline check bans sources` printed `bans ok, sources ok`.
- `cargo audit` (newer database) reported no vulnerability and one allowed warning:
  `proc-macro-error2` 2.0.1, RUSTSEC-2026-0173, unmaintained (2026-06-07). It is a `Cargo.lock` entry reached only
  through `defmt-macros` (optional `defmt` feature of `jiff`); `cargo tree --offline -i proc-macro-error2 --target all -e all`
  prints nothing, so no build in any closure compiles it. `deny` did not flag it; why was not investigated (the entry is in no resolved graph). It is the one unresolved evidence item: the lock entry is
  inert but not removed.
- Last green CI run of the gating jobs (`deny`, `audit`) was not looked up; the results above are local runs.

### Groups

| Group | Members | Exposure | Trust boundary | Units when the whole group is removed (of 497) | Closure artifacts |
|---|---:|---|---|---:|---|
| A: Signing, verification, crypto | 17 | Parses signatures, certificates and trust roots; holds key material; sigstore-verify, rcgen and keyring touch certificates and the OS keychain. No network in the verify path (Rekor and TSA clients are off for `mvm`, 2026-10-24 decision). Native code: blake3. | Signing and verification path: the host key, plan, audit chain, bundle and release-artifact checks (claims 8, 9, 20), plus guest-side envelope crypto | 95 | ACDGLS |
| B: Network, TLS, async runtime | 17 | Opens sockets or parses wire input (httparse, http, url, hickory-proto). rustls pulls ring and aws-lc-sys (native). tokio and mio carry unsafe OS polling. | Host-only; the guest closures carry only socket2, bytes, ipnet and tokio-free subsets. Egress policy is enforced by the host endpoint (claim 10) | 74 | ACDGLS |
| C: Parsers and formatters for external input | 26 | Parse untrusted bytes: tar, flate2, lzma-rs and ext4-view (image and layer content), gix (repository content), toml/serde_json/plist (config and wire), tree-sitter (source, native C grammars), wasmtime (guest code, off by default). | Host-side for archives, images, source; serde, serde_json, chrono, uuid, base64, hex are in every closure including the guests (wire and plan DTOs) | 156 | ACDGLS |
| D: OS, FFI and unsafe-heavy | 17 | Direct syscalls and FFI: libc, rustix, nix, objc2-foundation, core-foundation, security-framework, landlock, seccompiler, xattr, libloading, aya (eBPF), tss-esapi (TPM, native). Mostly unsafe by construction. | Host and guest. nix and seccompiler are guest-only (`mvm-builder-guest`); landlock and seccompiler are confinement controls, so a defect weakens a claim-1 mechanism | 27 | ACDGLS |
| E: VMM device model | 3 | Parse guest-controlled virtqueue and vsock descriptors from guest memory (the untrusted side of the device boundary); vm-memory is unsafe mmap access. | Host-only; the guest-to-host device boundary (`mvm-vmm`) | 6 | CDL |
| F: Error handling, logging, CLI, tooling | 10 | No network or untrusted parsing. proc-macro and build-time code (async-trait, thiserror, clap derive, syn). tracing-subscriber formats log output only. | Host and guest (logging and errors); clap/clap_mangen/syn/nextest-metadata/schemars are CLI or tooling | 25 | ACDGLS |

Units removed counts packages in the `mvmctl` graph that vanish with the whole group, so a group
that other groups depend on (tokio under rustls users, `serde` under everything) is
understated or overlaps another. Binary contribution for every group: not measured, needs a quiet host.

### Ranked candidates against the same columns

| Rank | Candidate | Exposure and boundary | API usage (files / dirs) | Maintenance | Advisory, licence | Closure delta | Units own / excl | Binary |
|---|---|---|---|---|---|---|---|---|
| 1 | `tracing-subscriber` | Formats logs only; host and `mvm-hostd`, not in guest closures; `tracing-log` forwards third-party `log` records, no parsing of untrusted input | 20 / 5 | 0.3.23, 2026-03-13, 3 releases in 12 months | No advisory in either run; MIT | -1 (applied) | 1 / 7 | Not measured |
| 2 | `chrono` | Parses and formats timestamps, including audit and plan validity windows (claims 8, 9); all six closures | 192 / 11 | 0.4.45, 2026-06-04, 3 | No advisory; MIT/Apache-2.0 | 0 | 1 / 2 | Not measured |
| 3 | `serde_jcs` | Produces the canonical bytes that are signed (plans, audit entries, bundles); signing path; all six closures | 15 / 4 | Locked 0.1.0; crates.io latest 0.2.0 on 2026-03-25, 1 release in 12 months | No advisory; MIT/Apache-2.0 | -2 host, 0 guest | 1 / 2 | Not measured |
| 4 | `tokio` `signal` | Async runtime, signal handling; host only | 222 / 13 | 1.54.1, 2026-10-21, 24 (locked 1.53.3) | No advisory; MIT | 0 | 1 / 3 | Not measured |
| 5 | `serde_json` `preserve_order` | Parses every wire and config document, untrusted input in the guest agent and host; all six closures | 940 / 25 | 1.0.154, 2026-10-11, 9 (locked 1.0.151) | No advisory; MIT/Apache-2.0 | n/a, retained | 6 / 13 | Not measured |
| 6 | `tempfile` | Creates files under `/tmp`, unsafe-free API over `rustix`; host and guest | 942 / 22 | 3.27.0, 2026-03-11, 4 | No advisory; MIT/Apache-2.0 | Not measured | 1 / 1 | Not measured |

The evidence changes nothing in the ranking: no candidate has an advisory, a licence concern or a stale
maintainer, so the order stays decided by closure delta and risk. Two observations the earlier
columns could not show. `serde_jcs` is the only ranked candidate with a signing-path role and a
newer release (0.2.0) than the one locked, which supports leaving it alone until a
differential test exists rather than replacing it. `tempfile` and `serde_json` are used in
more than 900 files, so a removal there is a workspace-wide change whatever the closure says.

### All 90 direct dependencies

Group letters are those above. Column "Latest, 12 mo" is the newest crates.io release, its date, and the
number of releases since 2025-10-31. "Files / dirs" is the API-usage count. "Units" is own/excl.
Advisory result for every row in the lock: none in either database run; the 10 rows marked `not in Cargo.lock` were not scanned.

| Dependency | Grp | Closure of | Locked | Licence | Latest, 12 mo | Files / dirs | Units |
|---|---|---|---|---|---|---|---|
| `aes-gcm` | A | CLDSAG | 0.11.1 | Apache/MIT | 0.11.1 on 2026-08-21, 5 | 2 / 1 | 1/10 |
| `aho-corasick` | C | CLD | 1.1.4 | Unlicense/MIT | 1.1.5 on 2026-08-03, 1 | 2 / 1 | 1/1 |
| `anyhow` | F | CLDSAG | 1.0.103 | MIT/Apache | 1.0.104 on 2026-07-18, 4 | 910 / 17 | 3/3 |
| `async-trait` | F | CLD | 0.1.89 | MIT/Apache | 0.1.92 on 2026-08-08, 3 | 52 / 6 | 1/1 |
| `aya` | D | none | - | not in Cargo.lock | 0.16.0 on 2026-10-28, 4 | 1 / 1 | not in graph |
| `base64` | C | CLDSAG | 0.22.1 | MIT/Apache | 0.23.1 on 2026-08-04, 2 | 91 / 13 | 1/1 |
| `blake3` | A | CLD | 1.8.5 | CC0-1.0/Apache/Apache+LLVM | 1.8.7 on 2026-08-20, 5 | 4 / 4 | 3/6 |
| `bs58` | C | CLD | 0.5.1 | MIT/Apache | 0.5.1 on 2024-03-19, 0 | 1 / 1 | 1/1 |
| `bytes` | B | CLDSAG | 1.12.0 | MIT | 1.12.1 on 2026-07-08, 4 | 109 / 19 | 1/1 |
| `chrono` | C | CLDSAG | 0.4.45 | MIT/Apache | 0.4.45 on 2026-06-04, 3 | 192 / 11 | 1/2 |
| `clap` | F | C | 4.6.1 | MIT/Apache | 4.6.7 on 2026-09-14, 18 | 153 / 5 | 1/6 |
| `clap_mangen` | F | none | - | not in Cargo.lock | 0.3.3 on 2026-08-12, 6 | 1 / 1 | not in graph |
| `core-foundation` | D | CLDSA | 0.10.1 | MIT/Apache | 0.10.1 on 2025-05-26, 0 | 4 / 3 | 2/2 |
| `ed25519-dalek` | A | CLDSAG | 3.0.0 | BSD-3-Clause | 3.0.0 on 2026-07-06, 9 | 252 / 14 | 1/3 |
| `ext4-view` | C | CLD | 0.9.3 | MIT/Apache | 1.0.0 on 2026-09-14, 2 | 15 / 5 | 1/1 |
| `flate2` | C | CLD | 1.1.9 | MIT/Apache | 1.1.10 on 2026-08-28, 5 | 27 / 10 | 1/4 |
| `gix` | C | CLD | 0.87.1 | MIT/Apache | 0.90.0 on 2026-10-22, 17 | 3 / 1 | 1/66 |
| `globset` | C | CL | 0.4.18 | Unlicense/MIT | 0.4.21 on 2026-10-27, 3 | 2 / 2 | 1/1 |
| `hex` | C | CLDSAG | 0.4.3 | MIT/Apache | 0.4.3 on 2021-03-03, 0 | 203 / 16 | 2/2 |
| `hickory-proto` | B | none | 0.26.1 | MIT/Apache | 0.26.3 on 2026-09-10, 8 | 2 / 2 | 1/2 |
| `hickory-resolver` | B | none | - | not in Cargo.lock | 0.26.3 on 2026-09-10, 8 | 1 / 1 | 1/27 |
| `hmac` | A | CLDSAG | 0.13.0 | MIT/Apache | 0.13.0 on 2026-03-29, 5 | 6 / 3 | 1/1 |
| `http` | B | CLD | 1.4.2 | MIT/Apache | 1.5.0 on 2026-07-29, 4 | 9 / 2 | 1/1 |
| `httparse` | B | CLD | 1.10.1 | MIT/Apache | 1.10.1 on 2025-03-03, 0 | 2 / 2 | 3/3 |
| `ipnet` | B | CLDSAG | 2.12.0 | MIT/Apache | 2.12.2 on 2026-09-06, 3 | 9 / 4 | 1/1 |
| `keyring` | A | CLD | 3.6.3 | MIT/Apache | 4.2.0 on 2026-08-29, 17 | 3 / 2 | 1/1 |
| `landlock` | D | none | 0.4.5 | MIT/Apache | 0.4.7 on 2026-07-27, 4 | 3 / 1 | not in graph |
| `leakguard` | A | CLD | 0.8.0 | MIT/Apache | 1.0.0 on 2026-10-06, 15 | 1 / 1 | 1/1 |
| `libc` | D | CLDSAG | 0.2.186 | MIT/Apache | 0.2.191 on 2026-10-16, 18 | 218 / 21 | 5/5 |
| `libloading` | D | none | 0.8.9 | ISC | 0.9.0 on 2025-11-05, 1 | 2 / 1 | not in graph |
| `lzma-rs` | C | CLD | 0.3.0 | MIT | 0.3.0 on 2023-01-04, 0 | 1 / 1 | 1/1 |
| `mio` | B | CLD | 1.2.1 | MIT | 1.2.4 on 2026-10-03, 6 | 4 / 2 | 1/1 |
| `nextest-metadata` | F | none | 0.14.1 | MIT/Apache | 0.15.0 on 2026-08-04, 7 | 1 / 1 | not in graph |
| `nix` | D | G | 0.29.0 | MIT | 0.31.3 on 2026-05-11, 4 | 21 / 9 | not in graph |
| `notify` | D | none | - | not in Cargo.lock | 8.2.1 on 2026-10-27, 8 | 2 / 1 | 1/2 |
| `notify-debouncer-mini` | D | none | - | not in Cargo.lock | 0.7.0 on 2025-08-03, 0 | 2 / 1 | 1/1 |
| `objc2-foundation` | D | C | 0.3.2 | MIT | 0.3.2 on 2025-10-04, 0 | 1 / 1 | 1/7 |
| `object_store` | B | none | - | not in Cargo.lock | 0.14.2 on 2026-09-15, 7 | 1 / 1 | not in graph |
| `percent-encoding` | B | C | 2.3.2 | MIT/Apache | 2.3.2 on 2025-08-21, 0 | 1 / 1 | 1/1 |
| `plist` | C | CLDSA | 1.10.0 | MIT | 1.10.3 on 2026-10-21, 5 | 7 / 3 | 1/2 |
| `rand` | A | CLDSAG | 0.9.4/0.10.2 | MIT/Apache | 0.10.3 on 2026-09-20, 16 | 93 / 8 | 2/8 |
| `rcgen` | A | CLD | 0.14.7 | MIT/Apache | 0.14.10 on 2026-08-28, 5 | 2 / 2 | 1/2 |
| `regex` | C | CLD | 1.12.4 | MIT/Apache | 1.13.1 on 2026-07-15, 4 | 24 / 3 | 1/1 |
| `rustix` | D | CLDSAG | 1.1.4 | Apache+LLVM/Apache/MIT | 1.1.6 on 2026-10-27, 4 | 21 / 4 | 3/3 |
| `rustls` | B | CLD | 0.23.46 | Apache/ISC/MIT | 0.23.46 on 2026-10-14, 15 | 17 / 4 | 3/3 |
| `rustls-pki-types` | B | CLD | 1.15.0 | MIT/Apache | 1.15.1 on 2026-07-23, 7 | 2 / 1 | 1/1 |
| `rustls-platform-verifier` | B | CLD | 0.7.0 | MIT/Apache | 0.7.1 on 2026-09-24, 2 | 1 / 1 | 1/1 |
| `schemars` | F | none | - | not in Cargo.lock | 1.2.3 on 2026-10-12, 6 | 87 / 6 | not in graph |
| `seccompiler` | D | G | 0.5.0 | Apache/BSD-3-Clause | 0.5.0 on 2025-03-07, 0 | 3 / 2 | not in graph |
| `secrecy` | A | CLDSAG | 0.10.3 | Apache/MIT | 0.10.3 on 2024-10-09, 0 | 41 / 8 | 1/1 |
| `security-framework` | D | CLDSA | 3.7.0 | MIT/Apache | 3.7.0 on 2026-02-20, 2 | 3 / 3 | 1/1 |
| `serde` | C | CLDSAG | 1.0.228 | MIT/Apache | 1.0.229 on 2026-07-18, 1 | 528 / 23 | 6/7 |
| `serde_jcs` | A | CLDSAG | 0.1.0 | MIT/Apache | 0.2.0 on 2026-03-25, 1 | 15 / 4 | 1/2 |
| `serde_json` | C | CLDSAG | 1.0.151 | MIT/Apache | 1.0.154 on 2026-10-11, 9 | 940 / 25 | 6/13 |
| `sha1` | A | CLDSA | 0.10.6 | MIT/Apache | 0.11.0 on 2026-07-10, 5 | 5 / 2 | 1/1 |
| `sha2` | A | CLDSAG | 0.10.9/0.11.0 | MIT/Apache | 0.11.1 on 2026-10-12, 5 | 193 / 16 | 3/11 |
| `sigstore-trust-root` | A | CL | 0.11.0 | Apache | 0.15.1 on 2026-10-23, 23 | 1 / 1 | 1/1 |
| `sigstore-types` | A | CL | 0.11.0 | Apache | 0.15.1 on 2026-10-23, 23 | 1 / 1 | 1/1 |
| `sigstore-verify` | A | CL | 0.11.0 | Apache | 0.15.1 on 2026-10-23, 22 | 1 / 1 | 1/17 |
| `socket2` | B | CLDSAG | 0.6.4 | MIT/Apache | 0.6.5 on 2026-07-13, 4 | 2 / 2 | 1/1 |
| `syn` | F | none | 2.0.118 | MIT/Apache | 3.0.9 on 2026-10-12, 21 | 3 / 1 | 1/1 |
| `sysinfo` | D | CLD | 0.30.13 | MIT | 0.40.1 on 2026-10-30, 14 | 3 / 1 | 1/1 |
| `tar` | C | CLDG | 0.4.46 | MIT/Apache | 0.4.46 on 2026-05-18, 2 | 48 / 12 | 1/1 |
| `tempfile` | D | CLDSAG | 3.27.0 | MIT/Apache | 3.27.0 on 2026-03-11, 4 | 942 / 22 | 1/1 |
| `thiserror` | F | CLDSAG | 2.0.18 | MIT/Apache | 2.0.21 on 2026-09-23, 4 | 284 / 15 | 3/4 |
| `tokio` | B | CLD | 1.53.3 | MIT | 1.54.1 on 2026-10-21, 24 | 222 / 13 | 1/3 |
| `tokio-rustls` | B | CLD | 0.26.4 | MIT/Apache | 0.26.6 on 2026-09-28, 2 | 3 / 1 | 1/1 |
| `tokio-vsock` | B | none | 0.7.2 | Apache | 0.7.2 on 2025-08-16, 0 | 1 / 1 | not in graph |
| `toml` | C | CLD | 0.8.23 | MIT/Apache | 1.1.8+spec-1.1.0 on 2026-10-09, 21 | 52 / 11 | 2/10 |
| `toml_edit` | C | C | 0.22.27 | MIT/Apache | 0.25.17+spec-1.1.0 on 2026-10-09, 23 | 1 / 1 | 2/6 |
| `tracing` | F | CLDSAG | 0.1.44 | MIT | 0.1.44 on 2025-12-18, 3 | 282 / 14 | 1/2 |
| `tracing-subscriber` | F | CLD | 0.3.23 | MIT | 0.3.23 on 2026-03-13, 3 | 20 / 5 | 1/7 |
| `tree-sitter` | C | CL | 0.26.10 | MIT | 0.27.1 on 2026-10-08, 13 | 6 / 2 | 3/11 |
| `tree-sitter-javascript` | C | CL | 0.25.0 | MIT | 0.25.0 on 2025-09-01, 0 | 2 / 1 | 3/3 |
| `tree-sitter-nix` | C | CL | 0.0.2 | MIT | 0.3.0 on 2025-07-18, 0 | 1 / 1 | 3/3 |
| `tree-sitter-python` | C | CL | 0.25.0 | MIT | 0.25.0 on 2025-09-11, 0 | 4 / 1 | 3/3 |
| `tree-sitter-typescript` | C | CL | 0.23.2 | MIT | 0.23.2 on 2024-11-11, 0 | 4 / 1 | 3/3 |
| `tss-esapi` | D | none | - | not in Cargo.lock | 7.7.0 on 2026-10-09, 4 | 1 / 1 | not in graph |
| `unicode-normalization` | C | CLD | 0.1.25 | MIT/Apache | 0.1.26 on 2026-10-16, 1 | 1 / 1 | 1/1 |
| `url` | B | CLD | 2.5.8 | MIT/Apache | 2.5.8 on 2026-01-05, 1 | 15 / 4 | 1/2 |
| `uuid` | C | CLDSAG | 1.21.0 | Apache/MIT | 1.29.0 on 2026-10-23, 18 | 35 / 8 | 1/2 |
| `virtio-queue` | E | CLD | 0.18.0 | Apache AND BSD-3-Clause | 0.18.0 on 2026-07-07, 2 | 5 / 1 | 1/3 |
| `virtio-vsock` | E | CLD | 0.12.0 | Apache/BSD-3-Clause | 0.12.0 on 2026-07-09, 2 | 1 / 1 | 1/1 |
| `vm-memory` | E | CLD | 0.18.0 | Apache/BSD-3-Clause | 0.18.0 on 2025-12-11, 2 | 1 / 1 | 1/1 |
| `wasmtime` | C | none | - | not in Cargo.lock | 50.0.1 on 2026-10-29, 84 | 1 / 1 | not in graph |
| `wasmtime-wasi` | C | none | - | not in Cargo.lock | 50.0.1 on 2026-10-29, 84 | 1 / 1 | not in graph |
| `which` | D | CLD | 7.0.3 | MIT | 8.0.6 on 2026-08-26, 6 | 23 / 5 | 1/2 |
| `x25519-dalek` | A | CLDSAG | 3.0.0 | BSD-3-Clause | 3.0.0 on 2026-07-06, 8 | 2 / 2 | 1/1 |
| `xattr` | D | CLD | 1.6.1 | MIT/Apache | 1.7.0 on 2026-10-28, 1 | 7 / 2 | 1/1 |
| `zeroize` | A | CLDSAG | 1.9.0 | Apache/MIT | 1.9.1 on 2026-10-06, 2 | 49 / 6 | 1/2 |

### Does this meet the section 3 box?

Met: exposure, trust boundary, API usage, maintenance (publish cadence), advisory, licence, closure delta
and build cost as unit counts, each with its source. Not met: **binary contribution per dependency**
(needs `cargo bloat --crates` on a release build) and **build cost in seconds** (needs `cargo build --timings`
on a host with a load below 8); unsafe-block counts (`cargo geiger`) are not installed or run.

## Release-build compilation count (#4839 section 4)

Measured at `4270e14d` on `aarch64-apple-darwin`, Rust 1.97.1, `--offline
--locked`. Counts come from Cargo's unit graph, which is what a build would
compile, so they do not depend on machine load:

```sh
RUSTC_BOOTSTRAP=1 cargo build --offline --locked --unit-graph -Z unstable-options <args> > graph.json
```

with `<args>` the arguments of each `cargo` invocation in `release.yml` for
`aarch64-apple-darwin` (the three guest rows are the nested `cargo zigbuild`
runs in `crates/mvm-cli/build.rs`, which share one nested target directory):

| Graph | Arguments | Units | Unique packages |
|---|---|---|---|
| `mvmctl` | `--profile release-min --target aarch64-apple-darwin --features host,user,release-artifact-bootstrap,release-channel,embed-host-bins` | 498 | 377 |
| daemons | `--release --target aarch64-apple-darwin -p mvm-hostd -p mvm-gpu` | 344 | 283 |
| `mvm-hostlib` | `--release --target aarch64-apple-darwin -p mvm-hostlib --features mvm-client/release-channel` | 424 | 337 |
| guest `mvm-host-vm-init` | `--release --target aarch64-unknown-linux-musl -p mvm-builder-guest --bin mvm-host-vm-init` | 118 | 87 |
| guest `mvm-builderd` | same, `--bin mvm-builderd` | 118 | 87 |
| guest `mvm-setpriv` | `-p mvm-setpriv --bin mvm-setpriv` | 5 | 2 |

What the "~1,017 entries" are: units, not packages. Summing every graph gives
1,507. Cargo shares a unit between invocations that hash identically, so the
distinct count is 942 on the host side (1,266 listed) plus 123 on the guest
side (241 listed), 1,065 together, over 384 unique packages (82 appear on both
sides because the musl and Darwin targets are separate builds). The 1,017
figure was not reproduced exactly; it falls inside the 942 to 1,065 range, and
the earlier note's 545 + 374 crates counted something other than units.

Where the repeated work is:

- `mvm-hostd` and `mvm-hostlib` share 324 identical units, so they are built
  once. Ten packages differ in resolved features (`mvm-client/release-channel`
  pulls in more of `mvm-core`, `regex` and `jiff`).
- `mvmctl` (`release-min`: opt-level `z`, `panic = "abort"`, fat LTO,
  one codegen unit) and the two `--release` builds (opt-level 3, unwind, thin
  LTO) share only 3 and 6 units (with the daemons and `mvm-hostlib`), so the target-side closure compiles twice. That is
  the documented panic-strategy split in `release.yml`, not an accident.
- Build scripts and proc-macros (host platform) are 110 distinct units, but 185
  as hashed: 75 are compiled again only because they inherit `lto` from the
  parent profile (`true` under `release-min`, `"thin"` under `release`).
  Cargo rejects the obvious fix, `lto = false` under
  `[profile.release.build-override]` (`lto` may not be specified in a
  `build-override` profile), and aligning the two parent profiles' `lto` would
  change the shipped binary size. No cheap fix exists, so none is made.
- The nested guest builds do not repeat each other: three invocations list 241
  units, 123 distinct.

No-change rebuilds: `cargo build --release -v` prints `Fresh <pkg>` for each
unit it reuses and `Dirty`/`Compiling` for each it rebuilds; on
`-p mvm-setpriv` the second run printed only `Fresh` lines (2 units). The
whole-tree no-change run, cold wall-clock times and final binary sizes were not
taken: the host's load average was about 390 on 16 cores, which makes timings
meaningless, and a full embedded cross build was not run. The embedded guest
payload is restored from the content store at `~/.cache/mvm/embed` when its
key matches, so a warm local build does not show the nested compile.

## Unused-dependency and duplicate-version re-scan (#4839 section 3)

Measured at `2d226a3b91` (origin/main, 2026-11-01). This pass removes nothing; the
evidence is recorded so the next sweep does not repeat it.

- `cargo machete` (workspace root): findings only in vendored `third_party/` crates
  (`gix`: `async-std`; `gix-object`: `gix-hashtable`; `sigstore-tsa`: `cmpv2`,
  `rustls-webpki`, `x509-tsp`; `sigstore-rekor`: `hex`, `sigstore-crypto`, `url`;
  `am-fs-ext4`: `am-fs-core`). No first-party crate has a finding. These are the same
  feature-gated optional declarations as above, so they stay. `cargo-udeps` is not
  installed. `--with-metadata` cannot run here: it fails on the detached fixture and
  `web/*` manifests and rewrites their `Cargo.lock` files, so it was not used.
- Distinct versions of one name in `Cargo.lock`
  (`awk '/^name = /{n=$3} /^version = /{print n,$3}' Cargo.lock`): 34 names. Thirteen are the
  `mvmctl`-closure pairs already decided above. The rest are reached only through
  optional or dev dependencies, each held by a third party:
  `base64` 0.21 and `target-lexicon` 0.12 (`tss-esapi`), `core-foundation` 0.9
  (`system-configuration`, `hickory-resolver`), `thiserror` 1, `object` 0.36,
  `hashbrown` 0.15 and `foldhash` 0.1 (`aya`, `aya-obj`), `nom` 7 (`asn1-rs`,
  `x509-parser`), `windows-sys` 0.52 and `io-lifetimes` 2 (`cap-primitives`,
  `ring`), `itertools` 0.14 (`cucumber`, `wasmtime`), the `wasm*`/`wit-*`/`wast`
  generations (`wasmtime`), `defmt`, `embedded-io`, `windows-core`
  (`cargo tree --workspace --all-features --target all -e normal,build,dev -i <name>@<version> --depth 2`).
- The one first-party choice among them is `criterion` 0.5.1 in `mvm-fs` (dev-dependency,
  benches) which brings `itertools` 0.10.5. Tried `criterion = "0.8"` with
  `cargo update -p criterion`: `itertools` moves 0.10.5 to 0.13.0, still a distinct
  third version beside 0.14 and 0.15, so no duplicate is removed; it also drops
  `hermit-abi` and `is-terminal` but adds `alloca` and `page_size` and needs Rust 1.86.
  Not applied.

## Owner decisions

- 2026-10-24, #4663: patch the Sigstore Rekor and timestamp crates locally so
  the network clients are optional and off for `mvm`, with a `sigstore-network`
  feature to turn them back on. Not a fork of the verification logic.
- 2026-10-20, #4561: leave the `rand` 0.9 copy in place. It is pulled in by
  the signature-verification dependency and is already in the audited skip
  baseline in `deny.toml`; unifying it would mean forking or downgrading a
  signature dependency.

## Limits

- The 12-crate figure comes from the package metadata closure, not a
  feature-resolved build.
- The #4560 figures are for the musl target; the host-target closure is 149 unique crates.
- No wall-clock measurement of the double compile was taken.


## Rust line-count record

[#4839](https://github.com/tinylabscom/mvm/issues/4839) asks for the Rust footprint under 1,000,000 lines on a declared, reproducible measurement. This section declares it and records the count at `f8aa6b12fa`. Nothing is excluded: every tracked `*.rs` file (`git ls-files '*.rs'`) is counted once, in the first category that matches.

- **Physical lines** are `wc -l` style line counts of the file.
- **SLOC** is physical lines minus blank lines and lines whose first token starts `//`. Block comments are not stripped, so it overstates executable code slightly; it is not a parser-grade figure.
- **vendored**: under `third_party/`. **generated**: one of `@generated`, `do not edit`, `automatically generated`, `auto-generated` (any case) in the first 10 lines. **tests-benches**: under a `tests/` or `benches/` directory. **first-party**: everything else, and it *includes inline `#[cfg(test)]` modules*, which are not separable by path.

| Category | Files | Physical lines | SLOC |
|---|---:|---:|---:|
| first-party | 2,247 | 1,066,996 | 833,993 |
| tests-benches | 281 | 93,230 | 77,031 |
| generated | 1 | 378 | 377 |
| vendored | 285 | 76,259 | 55,629 |
| total | 2,814 | 1,236,863 | 967,030 |

Run from a clean checkout; the numbers move with every merge, so re-run rather than trust this table.

```sh
git ls-files '*.rs' | while IFS= read -r f; do
  case "$f" in third_party/*) c=vendored;;
    *) if head -n 10 "$f" | grep -qiE '@generated|do not edit|automatically generated|auto-generated'; then c=generated
       elif printf '%s' "$f" | grep -qE '(^|/)(tests|benches)/'; then c=tests-benches
       else c=first-party; fi;; esac
  awk -v c="$c" -v f="$f" '{n++} NF && $1 !~ /^\/\//{s++} END{printf "%s\t%d\t%d\t%s\n", c, n, s, f}' "$f"
done | awk -F'\t' '{k[$1]; files[$1]++; p[$1]+=$2; s[$1]+=$3; P+=$2; S+=$3; F++}
  END{for(c in k) printf "%-14s files=%-5d physical=%-8d sloc=%d\n", c, files[c], p[c], s[c]; printf "%-14s files=%-5d physical=%-8d sloc=%d\n","total",F,P,S}' | sort
```

By area (same method, grouped by `crates/<name>`, `crates/deps/<name>`, `third_party/<name>` or top-level directory):

| Area | Physical lines | SLOC |
|---|---:|---:|
| `crates/mvm-cli` | 164,384 | 132,527 |
| `crates/mvm-hostd` | 163,938 | 127,841 |
| `crates/mvm-core` | 132,150 | 103,644 |
| `crates/mvm-runtime` | 91,060 | 70,707 |
| `crates/mvm-client` | 86,341 | 71,130 |
| `crates/mvm-build` | 85,571 | 66,535 |
| `crates/mvm-agentd` | 79,352 | 59,796 |
| `crates/mvm-contract` | 58,149 | 42,794 |
| `crates/mvm-vmm` | 53,860 | 41,562 |
| `xtask` | 46,941 | 37,606 |
| `crates/mvm-fs` | 38,430 | 29,782 |
| `third_party/gix-0.87.1` | 33,391 | 24,973 |
| `tests` | 29,061 | 24,158 |
| `crates/mvm-conformance` | 24,910 | 19,866 |
| `third_party/am-fs-ext4` | 24,723 | 17,385 |
| `crates/mvm-backends` | 23,114 | 17,807 |
| `crates/mvm-builder-guest` | 19,299 | 13,571 |
| `crates/mvm-compiler` | 13,978 | 11,685 |
| `crates/mvm-hostlib` | 10,161 | 8,525 |
| `crates/mvm-sdk` | 10,000 | 7,812 |
| `third_party/gix-object-0.64.1` | 6,410 | 4,843 |
| `crates/mvm-http` | 5,046 | 4,034 |
| `crates/deps/libkrun-sys` | 4,146 | 2,815 |
| `third_party/notify-8.2.0` | 4,125 | 2,943 |
| `third_party/io-extras-0.19.0` | 4,079 | 3,070 |
| `crates/mvm-gpu` | 4,042 | 3,433 |
| `crates/mvm-bundler` | 3,386 | 2,926 |
| `crates/mvm-capture` | 3,074 | 2,631 |
| `crates/deps/mvm-macho-sign` | 1,594 | 1,525 |
| `third_party/sigstore-tsa-0.11.0` | 1,535 | 1,045 |
| `crates/mvm-gpu-shim-core` | 1,504 | 1,234 |
| `third_party/sigstore-rekor-0.11.0` | 1,492 | 1,043 |
| `web` | 1,451 | 1,196 |
| `crates/mvm-gpu-cuda-shim` | 1,444 | 1,110 |
| `crates/mvm-gpu-cudart-shim` | 854 | 676 |
| `crates/mvm-host-services` | 780 | 566 |
| `crates/mvm-setpriv` | 755 | 611 |
| `crates/runmvm-client` | 617 | 562 |
| `crates/mvm-net` | 575 | 347 |
| `third_party/arrayref` | 504 | 327 |
| `crates/mvm-gpu-nvml-shim` | 448 | 324 |
| `src` | 169 | 54 |
| `build.rs` | 17 | 6 |
| `examples` | 3 | 3 |

```sh
git ls-files '*.rs' | while IFS= read -r f; do
  a=$(printf '%s' "$f" | awk -F/ '$1=="crates"&&$2=="deps"{print $1"/"$2"/"$3;next} $1=="crates"||$1=="third_party"{print $1"/"$2;next} {print $1}')
  awk -v a="$a" '{n++} NF && $1 !~ /^\/\//{s++} END{printf "%s\t%d\t%d\n", a, n, s}' "$f"
done | awk -F'\t' '{p[$1]+=$2; s[$1]+=$3} END{for(a in p) printf "%-40s physical=%-8d sloc=%d\n", a, p[a], s[a]}' | sort -t= -k2 -rn
```

The total is 1,236,863 physical lines, so the strict under-1,000,000 target is still open; this record measures it and does not meet it.
