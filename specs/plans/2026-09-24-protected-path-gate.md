# Plan: Protected-path gate — refuse guest-authored changes to CI/test/build files

## Status

**Not started.** Drafted 2026-09-24 from the sandbox-hardening grade card
(LinkedIn "7 ways to lock down AI agent sandboxes" assessment, idea 5: *run
file edits in isolated workspaces and protect CI/test files*).

Motivating gap, stated plainly: the sealed dm-verity rootfs means guest edits
stay in the guest — **except** through the one file-artifact channel, `--output`
ext4 collection. Today nothing inspects the paths or content of what the guest
wrote: `parse.rs:225-231` protects the *host destination* of a collection, not
the *guest tree* being collected. A workload (or a prompt-injected agent inside
it) can exfiltrate a modified `.github/workflows` file, a rewritten git hook,
or a tampered build config as a "work product", and the change lands on the
host with a chain-signed *success* record. The second leak is `:rw` dir-shares:
a read-write share overlapping a protected guest path is an explicit opt-in
today with no policy vocabulary for "this path class is never writable".

## Why

The article's attack is an agent that "passes" by deleting a test assertion or
slipping a command into CI config that runs outside the sandbox at review
time. In mvm's architecture the guest cannot touch the host's CI directly —
but its *outputs* are trusted work product by default. A host-side gate at the
existing collection chokepoint turns "trusted by default" into "refused by
default" for a small, explicit set of path classes, with the decision signed
into the plan and audited on the chain.

The seam already exists and already has the right semantics: every rule in
`mvm-fs/src/output` is a refusal, and a refusal rejects the whole collection
(`output/mod.rs:8`). There is no new data plane here — only a new rule class
and a policy field.

## Design position

### Plan field

`protected_paths: ProtectedPathsPolicy` rides inline in the signed
`ExecutionPlan`, following the `RedactionPolicy` precedent
(`execution_plan.rs:162`): additive `#[serde(default)]`, always serialized so
an absent/relaxed policy is attributable — the same reasoning
`stream_retention` documents at `execution_plan.rs:303-311`.

### Policy shape

`ProtectedPathsPolicy` in `crates/mvm-contract/src/policy/`:

- `mode: Enforce | Off` — no silent per-run downgrade; `Off` must be signed to
  exist.
- `paths: Vec<ProtectedPath>` — segment-aware patterns. Default set covers the
  CI/build/test class: `.github/workflows/**`, `.git/hooks/**`,
  `.gitlab-ci.yml`, `cloudbuild.yaml`, `mvm.toml`, and signing/key material
  (`**/*.pem`, `**/*_ed25519*` is **not** in v1 — see open question 2).
- `extra: Vec<ProtectedPath>` — operator extensions (e.g. repo-specific build
  dirs), merged over the default set.

### Matching — reuse, don't reinvent

The matcher follows `MountPathPolicy`'s bidirectional, segment-aware
containment checks (`mvm-core/src/crypto/policy/mount.rs:228-240`): pure,
unit-tested, no string-prefix hacks. A shared `ProtectedPathSet` type (pure
matcher + `contains(rel_path)` + `first_match(rel_path)`) lives next to the
policy type in `mvm-contract` so both enforcement points call the same code.

### Enforcement point 1 (primary) — output collection

New `PathRule` variants in `crates/mvm-fs/src/output/rules.rs`, evaluated in
the existing validate pass of `collect.rs` (validate whole tree, then extract
without following links — symlink escapes are already structurally excluded).
Refusal reuses the standing machinery: whole-collection rejection,
`OutputRefusal::audit_tag()` stable vocabulary, `OutputOutcome::Refused`
chain-signed audit (`outputs.rs:257-264`, `output_audit.rs`). The policy
reaches collection via `PreparedOutputs`, which already holds the signed plan's
grant set.

### Enforcement point 2 — read-write dir-shares

A `:rw` `DirShareSpec` whose guest path intersects the protected set is refused
at admission, reusing the `containing_protected` / `shadowed_protected`
machinery via `MountPathPolicy::with_extra_protected`
(`mount.rs:149`). Read-only shares overlapping protected paths remain legal —
that is the supported pattern for letting an agent *see* CI config.

### Explicit non-goals (v1)

- **Content of network egress.** A `git push` of a tampered workflow to an
  admitted remote cannot be scanned at L4; that belongs to the deferred L7
  egress proxy (`EgressMode::L3PlusL7`, which fails loudly today). Document
  this boundary in the gate's error text and docs.
- **In-guest file-access logging.** Protection stays by sealing, not logging.
- **Stdout/diff channels.** The transcript redaction seam
  (`stream/redact.rs:32`) is the future home if a diff-text gate is wanted;
  v1 covers the file-artifact channel only.
- **PR-level blocking.** mvm produces the audit evidence
  (`OutputOutcome::Refused` on the chain); a CI job reading that evidence is
  the consumer, out of scope here.

## Phases

### Phase 0 — Contract and claim scaffolding

- [x] `ProtectedPathsPolicy` + `ProtectedPathSet` matcher in
  `mvm-contract/src/policy/` (own module); serde roundtrip, default-set, and
  matcher unit tests (segment boundaries, `..` traversal, exact-file vs
  `/**` glob, case handling).
- [x] Additive signed-plan field on `ExecutionPlan` (precedent style);
  plan-bytes/schema-stability test.
- [x] Claim **MVM-SEC-23** row in `model/claims.toml` (level `build`,
  suite `s38_protected_paths`), suite skeleton
  `features/suites/s38_protected_paths/`; `xtask check-conformance` and
  `check-claim-catalog` green.

### Phase 1 — Output collection gate

- [ ] `PathRule::Protected*` variants in `mvm-fs/src/output/rules.rs`,
  threaded from the policy into the `collect.rs` validate pass.
- [ ] Tests: benign tree collects; tree containing a modified
  `.github/workflows/x.yml` is refused whole; refusal audit tag is stable;
  `mode: Off` in a signed policy collects (attributable relaxation); symlinked
  protected name refused (defense in depth even though links aren't followed).
- [ ] `PreparedOutputs` wiring: read the policy from the signed plan, hand it
  to collection; fail-closed if the plan is present but the policy projection
  is missing.

### Phase 2 — Read-write share classification

- [ ] Admission check: `:rw` dir-share intersecting the protected set refused
  via `MountPathPolicy::with_extra_protected`; read-only intersecting shares
  still admitted.
- [ ] Tests: positive (rw `/work` ok), negative (rw `/work/.github` refused),
  edge (shadowing `/` root share, nested mount over protected path).

### Phase 3 — CLI and integration

- [ ] `--protected-path <glob>` (repeatable, extends default set) and
  `--no-protected-paths` (signed `Off`, prod admission may refuse it — follow
  the `ProviderAdmissionTier` precedent) parsed in `shared/parse.rs`.
- [ ] `tests/cli.rs` coverage: flag parsing, plan carries the policy,
  rw-share refusal surfaces a clean error.

### Phase 4 — Live witness, BDD, docs

- [ ] Live e2e: sealed workload writes a `.github/workflows/` change into its
  output volume → collection refused + chain-signed `Refused` record; control
  workload with benign output → collected. Linux-gated, builder VM.
- [ ] BDD scenarios in `s38_protected_paths`; escalate claim level only when
  the live witness lands.
- [ ] Public docs section (filesystem/output guide) stating the L4/L7 boundary
  explicitly; `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` updates in the
  landing PR.
- [ ] Full definition-of-done sweep: `cargo test --workspace`,
  `cargo clippy --workspace -- -D warnings`, `just check-gated`, Linux-gated
  tests in the builder VM.

## Open questions

1. Should the default protected set be enforced when the plan field is absent
   (deny-by-default, matching `NetworkPolicy`), or is an absent field
   "no gate" (matching `stream_retention`'s always-serialized attribution)?
   Proposed: **enforced default set** — the cost of over-refusal is a visible
   error, the cost of under-refusal is a CI compromise; relaxation is one
   signed field away.
2. Does key material (`**/*.pem`, `**/*_ed25519*`, `**/.env*`) belong in the
   default set? Proposed: yes for `**/.env*` and `**/*.pem`, no for broad
   `*_ed25519*` globs (too much collateral on test fixtures).
3. Should prod admission refuse `mode: Off` outright (like it refuses the
   `dev` network preset)? Proposed: yes — mirror the existing tier-refusal
   pattern.
