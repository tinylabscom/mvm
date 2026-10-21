---
kind: design
issue: https://github.com/tinylabscom/mvm/issues/4584
status: accepted
---

# `mvmctl build` as the front door to a `.mvmpkg`

Backing: preview
Validation: targeted

The issue owns scope and progress. This document fixes the design decisions
the issue asks for: the command surface, the trust level of a locally built
package, and the sequence of changes. Nothing here is implemented.

## Decision recorded from the maintainer

A package built locally is signed with the host key and labelled **local
build**. It is never publishable to the registry, never accepted by any
pull, fetch or install path as release-verified, and never described as
secure, verified, or trusted by release identity. This is a hard refusal, not
a warning, and it has a named test (`a_local_build_is_refused_by_push_and_by_pull`,
below). Every other decision in this document is subordinate to it.

## Today

Three user-facing paths each end in the same signed archive:

| Path | Entry | Shared code |
| --- | --- | --- |
| `mvmctl pack build SPEC.json --out X` | `commands/pack/build.rs` (`run`, `pack_export`) | compiles the frozen spec, builds a template slot, health-boots it, then `stage_template` |
| `mvmctl bundle export TEMPLATE --out X` | `commands/bundle/export.rs` (`export_template`, `stage_template`, `TemplateExport`) | seals a built template via `mvm_client::bundle::export_bundle_with_signer` |
| `mvmctl bundle build --image REF --out X` | `commands/bundle/build.rs` | `mvm_client::{materialize_oci_bundle, export_materialized_oci_bundle}` |

All three sign through `mvm_client::bundle::HostBundleSigner`
(`BundleSigner` over the host Ed25519 key, publisher `host:<hostname>`).
`mvm_client::builder_bundle::build_and_export_bundle` is a fourth caller that
exports builder output directly.

`mvmctl build` today is `commands/build/group.rs`: only the contributor
subcommands (`compile`, `validate`, `kernel`, `runtime-overlay`,
`sdk-sidecar`, `address`, `image-set`, `guest-bins`). The positional-path
manifest build (`commands/build/build.rs`, `resolve_manifest_for_args`) is
reached through `machine build`.

`mvmctl run ./app.mvmpkg` is classified by shape in `commands/vm/exec.rs`
(`SOURCE`) and verifies the archive with `verify_bundle_file` against
`FsTrustStore::default_path()` (`~/.mvm/trusted-publishers/<key_id>.pub`).
The host key is not in that store, so a freshly built package does not run
without a manual `mvmctl trust add`. `bundle push` verifies against the same
store (`publish_bundle` in `commands/bundle/registry.rs`), so the host key
cannot be pushed either, by accident of enrolment rather than by rule. That
accident is what this design replaces with a rule.

## Command surface

```
mvmctl build [SOURCE] [--out FILE.mvmpkg] [--label L] [--posture P] [--environment F]
```

- `SOURCE` defaults to `.`. `--out` defaults to `./<name>.mvmpkg`, where
  `<name>` is the pack name, manifest name, or image repository basename. An
  existing destination is refused, as both exporters already do.
- The flags that `bundle export` has today (`--label`, `--cmdline`,
  `--posture`, `--allow-egress`, `--allow-volumes`, `--allow-unauthenticated`,
  `--environment`) carry over unchanged by reusing `bundle::export::Args`
  fields through a shared struct; no new flag semantics.
- `--hypervisor` and `--input-observation` carry over from `pack build`.
- There is no `--sign-with` and no flag that selects another key. The key is
  always the host's own. Publishing under a release identity is a different
  pipeline and not reachable from this verb.

### Source detection

Classified by shape first, filesystem second, in this fixed order. The first
match wins; a second match is an error, never a silent pick.

1. Contains `://` or matches an image-reference shape, and is not an existing
   path: OCI image reference, via the `bundle build` path.
2. A file whose content declares `mvm.pack-spec/v1` (JSON): pack spec, via the
   `pack build` path. Detection reads the schema marker only; it never
   evaluates author code.
3. A file or directory holding `mvm.toml` or `Mvmfile.toml`
   (`manifest::manifest_in_dir`): manifest build.
4. A directory with `flake.nix`, or `--flake REF`: flake build.
5. A directory with an SDK-authored workload (`mvm-sdk` decorator parse):
   compile to the Workload IR, then a flake build.

Errors, each naming the path and the rules tried:
`ambiguous source` when a directory matches more than one of 2-5 (the message
lists the matches and the flag that disambiguates: `--from pack|manifest|flake|sdk|image`),
`unsupported source` when nothing matches, and `source not found`.
`--from` forces one class and skips detection.

## One build path

The build path is: resolve SOURCE to a template slot (or OCI materialization),
then `stage_template` / `export_materialized_oci_bundle`, then
`StagedBundle::publish`. That is already what `pack build` and `bundle export`
do. The new code is a thin dispatcher in front.

Decision on the old commands: `bundle export` and `pack build` are **removed
as user-facing verbs** once `build` covers their inputs (the project has no
compatibility commitment). Their bodies are not rewritten: the functions
named above move or are re-exposed to `build`. `bundle build --image` is
folded into source class 1. `bundle push`, `fetch`, `install`, `gc`, `inspect`
stay; they are the publish and consume side, not the build side.

The contributor subcommands move to `mvmctl dev <sub>` (a new group, same
`BuildCmd` enum and `verb_name` strings, so audit verb names are unchanged
except for the group). Callers to update: `justfile` recipes, `scripts/`,
`.github/workflows/`, `CLAUDE.md`, `public/src/content/docs/reference/cli-commands.md`,
`tests/cli.rs`, and the error hints that print `mvmctl build sdk-sidecar build`
or `mvmctl build kernel` (found with `rg 'mvmctl build (compile|validate|kernel|runtime-overlay|sdk-sidecar|address|image-set|guest-bins)'`).
The `check-claim-catalog` and documented-command gates fail on a stale
reference, which is the safety net.

## Trust levels

A package is classified at the point it is read, from facts the verifier
already has, never from a field the signer chose alone.

| Level | Condition | `run` | `push` | `fetch` / `install` from registry | May be described as |
| --- | --- | --- | --- | --- | --- |
| Release-verified | Signature verifies under a key enrolled in the trust store (`trust add`) or a release identity, via `read_and_verify_bundle` / `verify_bundle_file` | Runs | Allowed | Allowed | Verified, with the key id and publisher |
| Local build | `key_id` equals this host's own key id **and** the signed manifest carries the label `mvm.origin=local-build`, **and** the archive was opened from a local path | Runs, with the notice below, only on the host whose key signed it | **Refused, always** | **Refused, always** | "local build"; never "verified", "secure" or "trusted" |
| Untrusted | Any other signer not in the trust store | Refused (today's behaviour) | Refused | Refused | Unverified |

Rules that make the local level safe:

1. **The label is necessary, not sufficient.** A label is signer-chosen. The
   level is granted only when the key is also this host's key
   (`host_keypair::host_signer_id()` / `key_id_from_pubkey` of the host
   verifying key). A foreign archive carrying the label gets no level and is
   Untrusted. A host-key archive without the label is Untrusted too: the label
   is what makes the intent explicit and what push can refuse on.
2. **The refusal does not depend on the trust store.** Push and every registry
   ingress check the label and the host-key id *before* consulting the trust
   store. Enrolling the host key with `trust add` must not unlock publishing:
   an archive that is local-build by label or by host key is refused whatever
   the store contains.
3. **Local build is not a store entry.** The host key is never written to
   `trusted-publishers/`. The level is computed per archive and lives in code
   (`BundleOrigin::LocalBuild`), so it cannot be inherited by a different
   archive, copied to another host, or escalated by editing a directory.
4. **Host-bound.** Another machine has a different host key, so a copied
   archive is Untrusted there.
5. **Audited.** Admission of a local build emits a chain-signed entry
   (`plan.admitted` already exists; it gains `origin=local-build` and the
   `bundle_sha256` via the existing `audit_emit!` path used by `bundle push`),
   so the audit log distinguishes a local run from a release-verified one.
6. **Wording.** `run` prints one line on stderr: `local build, signed by this
   host's key; not release-verified`. `inspect`, `doctor` and the docs use
   the same phrase. No surface says verified, secure, or trusted for this
   level, and the security claims ledger is not widened: claims 8, 9 and 20
   still describe signed-plan admission and release artifacts, and a local
   build is explicitly outside claim 20.

### The hard rule

Registry ingress and egress classify with one function, `bundle_origin(manifest,
host_key_id) -> BundleOrigin`, placed beside `verify_plan_bundle` in
`mvm_core::plan::bundle`. `publish_bundle` (push), `pull_bundle` consumers
(`fetch`, `install` from `oci://`), and the pack registry install paths must
call it and refuse `LocalBuild` with an error that names the archive and says
local builds are never published. There is no override flag and no environment
variable, and `MVM_SKIP_HASH_VERIFY` / `MVM_SKIP_COSIGN_VERIFY` do not waive
it. Re-signing is the only way to publish, and that is a release pipeline
action, not a CLI one.

## Build then run, with no extra step

`mvmctl build . && mvmctl run ./app.mvmpkg` works because `run`'s archive
verification gains one branch: when `verify_bundle_file` fails with an
unknown key and `bundle_origin` returns `LocalBuild` for a local path, admission
proceeds at the local-build level. The trust store is not modified. Every
other failure (tampered manifest, bad signature, digest mismatch,
foreign key) is unchanged, because the branch runs only after signature and
digest verification of the manifest against the host's own public key.
`--prod` refuses local builds: production admission requires release-verified.

Relationship to flows `run` already supports: `run IMAGE` (OCI, unaffected),
`run ./x.mvmpkg` (gains the local level), `run <installed app>` and
`machine run --bundle` via `bundle install` (installing a local build into the
registry directory is refused if the archive is not local-path-sourced, and
an installed local build keeps its level only while the host key matches),
and the `--app` namespace route (release-verified only; out of scope here).

## New code versus wiring

Wiring (existing code, new call sites):
- `build` dispatcher calling `stage_template`, `export_template`,
  `compile_frozen` + the `pack build` health boot, `materialize_oci_bundle`,
  `export_materialized_oci_bundle`, `build_and_export_bundle`.
- Moving `BuildCmd` under a `dev` group; updating callers.
- Reusing `HostBundleSigner` unchanged.

New code:
- Source detection (`detect_source`) and its two errors.
- The `mvm.origin=local-build` label, written by one function used by every
  exporter on the `build` path, into `BundleManifest.labels` (already a signed
  field, already `deny_unknown_fields`-safe because it is a map entry).
- `BundleOrigin` and `bundle_origin` in `mvm-core`.
- Refusal calls in push, fetch/install registry ingress, pack registry
  install, and `--prod`.
- The `run` local-build branch and the audit field.
- Doc and BDD updates.

## Tests

Named; each fails if the behaviour regresses.

- `a_local_build_is_refused_by_push_and_by_pull`: build with the host key,
  then `publish_bundle` and the registry-install path both refuse, including
  when the host key has been added to a trust store (rule 2).
- `enrolling_the_host_key_does_not_make_a_local_build_publishable`.
- `the_local_label_without_the_host_key_grants_no_level`: a foreign key
  carrying `mvm.origin=local-build` is Untrusted and `run` refuses it.
- `a_host_key_archive_without_the_label_is_not_a_local_build`.
- `bundle_origin_is_release_verified_only_for_enrolled_keys`.
- `a_local_build_runs_without_trust_add_and_leaves_the_store_unchanged`.
- `a_tampered_local_build_is_refused`: flipped artifact byte and flipped
  manifest field.
- `a_local_build_is_refused_under_prod`.
- `a_local_build_admission_is_audited_with_its_origin`.
- `no_surface_calls_a_local_build_verified`: `run` stderr, `inspect`, and
  `doctor` output are checked for the required phrase and for the absence of
  `verified`/`secure`/`trusted` next to a local-build archive.
- `source_detection_picks_each_class_and_rejects_ambiguity`: one fixture per
  class; a directory with both `mvm.toml` and `flake.nix` errors with the
  matches listed; `--from` resolves it.
- `build_refuses_an_existing_out_path`.
- `dev_subcommands_keep_their_audit_verb_names`.
- CLI tests in `tests/cli.rs` for `build --help` and the `dev` group; BDD
  scenario for build then run per source class (documented commands are
  gated); witness runs of `mvmctl build` on each source then `mvmctl run`.

## Staged implementation

1. `bundle_origin`, `BundleOrigin`, the label writer, and the push/fetch/
   install/pack-registry refusals, with the hard-rule tests. This stage
   ships first and alone: it is safe before any new verb exists because it
   only adds refusals.
2. Move contributor subcommands under `dev`; update scripts, CI, docs,
   `tests/cli.rs`.
3. `build [SOURCE]` dispatcher with source detection, pack-spec and
   manifest/flake classes first (code that already exists end to end), `--out`
   defaulting, shared export flags.
4. OCI image and SDK-workload classes.
5. `run` local-build branch, `--prod` refusal, audit field, wording tests.
6. Remove `pack build`, `bundle export`, `bundle build` as verbs; update CLI
   reference, README examples and BDD coverage.
7. Witness runs per source type, then `mvmctl run` of each result.

## Out of scope

Publishing flows and release identity signing; the application launch route
(`run <namespace/name>[@version]`, `--app`); cross-architecture builds.
