# Verification

Which axis of the normative acceptance gate discharges which class of claim.
`AGENTS.md` and the conformance model are the source of truth; this file maps
rules onto the commands that enforce them and records the planted defects that
prove each gate can fail.

## The rules

| Rule | What it says | Enforced by |
| --- | --- | --- |
| R1 | The model is the single source. Every claim lives in `model/*.toml`, and `docs/CONFORMANCE.md` is generated from it. | `cargo run -p xtask -- check-conformance` |
| R2 | Levels are load-bearing. A claim is `some-true`, `build`, or `open`, and the two registers are never blurred. | `cargo run -p xtask -- check-honesty` |
| R3 | A capability begins as a register row, then a scenario, then a witness. | `cargo test -p mvm-conformance --test meta` |
| R4 | Nothing is deferred. No deferral marker, no stub, no capability behind a flag that turns it off. | `cargo run -p xtask -- check-deferrals` |

## Falsifiability

A gate nobody has seen fail is indistinguishable from a gate that cannot. Each
row below records a defect that was planted to prove the gate fires.

| Gate | Planted defect | Reported |
| --- | --- | --- |
| `check-build-egress-callers` | Add a `NetworkPolicy::trusted_build_egress()` call to `workload_runner/runner.rs` — the shape of a future workload path reaching the unrestricted-egress constructor and turning off claim 10's default-deny | yes — named the file and line, refused |
| `check-build-egress-callers` (vacuity) | Point the gate at a tree with no allow-listed call site, i.e. the state it would reach if the constructor were renamed and the gate silently stopped checking anything | yes — refused rather than passing empty |
| `check-verified-kernel-reads` | Add a boot path that takes `cached_kernel_path` and accepts it on `is_file()` — the shape of the Firecracker arm and the kernel-less-image fallback that both booted an unverified kernel | yes — named the file and line, refused |
| `check-verified-kernel-reads` (vacuity) | Point the gate at a tree where no file pairs the location helper with `resolve_kernel`, i.e. the state it would reach if either were renamed | yes — refused rather than passing empty |
| `check-conformance` (R1) | Edit `docs/CONFORMANCE.md` so it disagrees with `model/claims.toml` | yes |
| `check-honesty` (R2) | Add "MVM-SEC-07 proves cargo deps are audited" to `README.md` | yes |
| `meta` (R3) | Register `MVM-SEC-99` with no scenario, or remove a scenario's ID tag | yes |
| `check-deferrals` (R4) | Add `// TODO example` to a production source file outside an exemption | yes |
| `check-abi-layout` | Add a `#[repr(C)]` struct with no `size_of`/`align_of` assertion | yes |
| `check-abi-layout` | Mention `size_of::<T>()` in a comment instead of asserting it | yes |
| `check-claim-catalog` | Name a witness in the ADR-001 ledger that `model/claims.toml` does not list | yes |
| `check-workflow-paths` | Point a fuzz step's `working-directory` at `crates/mvm-oci` (the pre-consolidation path that made the fuzz lane dead for ten nightlies) | yes |
| `check-mvm-host-binaries-sync` | Drop `--bin mvm-builderd` from the builder-VM cross-compile step, reproducing the "path does not exist" image-build failure | yes |
| `check-claim-witness-freshness` | Change `security.yml`'s cron to hourly so its real last scheduled run exceeds the allowance, or feed the classifier a completed `cancelled` run; reports the stale or unhealthy scheduled evidence and names every claim it backs | yes |
| `a_modified_kernel_is_rejected_and_both_files_evicted` etc. | Make `verify_cached_kernel` return the path unchecked, i.e. restore the path-trust `resolve_kernel` shipped with — a cached kernel served because the file exists | yes — 3 of the read-path tests fired |
| `resolve_cached_when_present_and_pinned` | The pre-existing version of this test staged a kernel with **no** pin and asserted a cache hit, encoding "existence is evidence". It had to be rewritten for the new contract, which is the clearest single sign of what changed | n/a — the old test was the defect |
| `no_std_verifier_accepts_the_same_corpus_the_host_verifier_does` | Drop `skip_serializing_if = "Option::is_none"` from the `no_std` mirror's `bundle_id`, so it reconstructs different signed bytes than the host emitted. The two implementations now disagree about the wire form of an *absent* field | yes — `SignatureInvalid { line: 0 }` over the shared corpus |
| `frozen_chain_matches_what_the_signer_produces_and_the_host_verifier_accepts` | Change what the host signer emits without regenerating the corpus, i.e. the case where every chain already written becomes unverifiable | yes — committed corpus no longer matches the signer |
| `ProtocolDigest` compile-fail doctest | Add `impl From<ProtocolDigest> for StorageAddress`, giving σ and κ the bridge the doctest asserts cannot exist. The first version of this test was **vacuous** — it used a bare `let kappa: StorageAddress = sigma;`, which never compiles whatever impls exist, so it passed with the bridge present; rewritten to `sigma.into()`, which compiles exactly when a bridge exists | yes — doctest FAILED once the bridge existed |
| `a_non_collision_resistant_digest_cannot_become_an_address` | Feed MD5 (32 hex), CRC32C (8), CRC64 (16) and a right-width non-hex string to both σ and κ constructors | yes — each refused |
| `ir_hash_vectors_are_frozen` | Hash the canonical form with a trailing newline appended, so every address moves consistently. All four existing `ir::hash` tests still passed — stable-for-identical, key-order-independent, different-values-differ, 64-hex — because each is relational and none pins a value | yes — `ir_hash/empty-object: address moved` |
| `base_plan_address_is_frozen` / `stored_plan_id_is_excluded_from_its_own_address` | Change `compute_plan_id` to strip a field name that does not exist, so the stored `plan_id` is folded into its own digest and the address stops being a content-address | yes — `plan_id/differing-stored-id-addresses-the-same: address moved` |
| `check-claim-catalog` (witness kinds) | Delete `ci:seccomp-functional` from **both** `model/claims.toml` and the ADR-001 ledger row for claim 1 — the way a witness would actually be retired. Before this gate the run reported `clean (16 claims, 48 witnesses verified)`: claim 1 had silently lost its only CI evidence with a green board | yes — `claim MVM-SEC-01: declares witness kind \`ci\` but has no \`ci:\` witness` |
| `check-claim-catalog` (witness kinds, converse) | Add a `ci:` witness to `MVM-SEC-08`, which declares `fn` only, leaving the new evidence unpinned and droppable again unnoticed | yes — `has a \`ci:\` witness that \`witness_kinds\` does not declare` |
| `cargo-fuzz crates still compile` | None planted — run against main it independently rediscovered both real defects (`fuzz_authed_path` E0308, `fuzz_build_image` unclosed delimiter) that the nightly took eleven days to surface | yes |
| `included_top_level_is_a_superset_of_the_nix_filter_allowlist` | Remove `"nix"` from `INCLUDED_TOP_LEVEL` while `workspace-filter.nix` still admits it, so a `nix/` change would go unhashed and boot a stale image | yes |
| `excluded_basenames_are_a_subset_of_the_nix_workspace_filter` | Add `"crates"` to `EXCLUDED_BASENAMES`, pruning a tree the nix filter keeps | yes |

The two build-fingerprint rows are a matched pair, and their bindings point in
opposite directions because the nix filter admits by top-level entry and prunes
by basename. Both were planted separately; each fired only its own gate.

The `meta` gate also catches the reverse direction: a scenario tagged with an
unregistered ID, or a scenario whose level tag disagrees with the register.

The layout contracts `check-abi-layout` requires were each planted against
too, since the gate only proves an assertion is present and the assertion is
what has to discriminate. A same-type field reorder is the case of interest:
it changes no types, so nothing but an offset assertion sees it.

| Contract | Planted defect | Reported |
| --- | --- | --- |
| `hv_vcpu_exit_exception_t` | Swap the `syndrome` and `virtual_address` `u64` fields | yes |
| `SockaddrVm` | Revert to the pre-6.0 `svm_zero: [u8; 4]` shape | yes |
| `DmTargetSpec` | Swap the `sector_start` and `length` `u64` fields | yes |

### CI-lane witnesses

Two claims are witnessed in part by a CI lane — a runtime boundary test, a fuzz run,
a dependency audit. Mutation testing cannot reach them: there is no Rust
function body whose mutation exercises a workflow job. They were planted
against by hand instead.

| Claim | Witness | Planted defect | Fired |
| --- | --- | --- | --- |
| MVM-SEC-05 | `ci:fuzz` | Unchecked `s[..8]` slice behind a `deserialize_with` on `GuestRequest::FsRead::path` | yes — libFuzzer `deadly signal` inside a 90s budget |
| MVM-SEC-07 | `ci:cargo-deny` | Remove `MIT` from `deny.toml`'s licence allow-list | yes — `rejected: license is not explicitly allowed` |
| MVM-SEC-04 | `ci:guest-agent-runtime-boundary` | Remove the runtime profile or grant check before dispatching a DevOnly request | yes — the grant and handler conformance tests fail |

**MVM-SEC-05.** The lane could not have fired at all until its
`working-directory` values were corrected — they pointed at crates the
consolidation renamed, so it died on a missing directory rather than on
anything it was meant to detect. With the paths fixed, a planted parser
panic is found inside the per-run budget. The seed corpus is what makes that fast — the
fuzzer starts from valid `GuestRequest` JSON rather than random bytes.

**MVM-SEC-07.** Removing an allowed licence is a deterministic stand-in
for a dependency arriving with a disallowed one; it exercises the same
rejection path without depending on a particular crate's licensing. Note
the lane also fired on a *real* defect during this work — duplicate
`curve25519-dalek` — which is stronger evidence than any plant.

**MVM-SEC-04 — the runtime boundary is the witness.** The universal agent
contains the DevOnly handlers in every build, but a production-safe run still
cannot reach them: request classification, the runtime profile, and the
launch-provisioned signed grant must all authorize the call. The unit suite
enumerates the DevOnly request set, and the CI lane runs those tests against
the same artifact shape used by both tiers.

### Mutation testing

Mutation testing of the claim witnesses was removed from CI: the nightly lane
cost hours per shard and its `mvm-cli` and `mvm-hostd` shards timed out. A claim
witness is therefore checked for existence (`check-claim-catalog`), not for
whether it detects its property breaking.

### Does device-mapper layout drift fail open?

Asked because `DmIoctl`/`DmTargetSpec` build the dm-verity table, and a
drift that produced a *working but unverified* device would make
MVM-SEC-03 silently void rather than loudly broken.

Measured directly against the kernel on Linux 6.8 rather than inferred:
a `dm_target_spec` was submitted to `DM_TABLE_LOAD` with `target_type`
displaced by 4 and by 8 bytes, the displacement a same-size field
reorder upstream of it would cause.

| Layout | `DM_TABLE_LOAD` |
| --- | --- |
| Correct | succeeds; device resumes with a live table |
| `target_type` shifted +4 | `EINVAL` |
| `target_type` shifted +8 | `EINVAL` |

**Fail-closed.** The kernel resolves the target by name string before any
target-specific parsing, so a displaced field yields a name that matches
no registered target and the load is rejected. The mechanism is
target-agnostic, so this holds for `verity` as it does for the `linear`
target used in the probe.

The layout contracts are therefore drift insurance that turns a confusing
runtime `EINVAL` into a build error — worth having, but MVM-SEC-03 was
not at risk. One residual case is not covered: a displacement that
happened to land a *different valid* target name at the kernel's read
offset would resolve. Nothing in the current struct makes that reachable,
and the offset contracts now prevent the displacement outright.

## What this suite does not establish

Anything about a dependency. A library imported here is gated in its own
repository; restating its guarantees would give a claim two sources, which is
what R1 forbids. What may be claimed here is what is built here.
