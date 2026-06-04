# Plan 150 — OSV-unified dependency scanning + actionable remediation

> **For agentic workers:** use `superpowers:subagent-driven-development` or
> `superpowers:executing-plans` to implement task-by-task. Steps use `- [ ]` for tracking.

> **Spec number:** 150 is free on disk, `origin/main`, and open PRs at authoring time
> (144–149 are taken — 149 was claimed by a parallel session's
> `149-live-operator-event-stream.md` mid-authoring, hence 150; PR branches hold 146/147;
> the pre-existing branch/main collision at 144–145 is not ours to resolve here).
> Re-confirm before merge — `xtask check-spec-numbers` is a Lint gate.

> **Sequencing:** Follow-on to the Plan 120 line, not a blocker for it. Depends on the
> app-deps install pipeline actually running in the builder VM (Plan 73 W4/W5 cutover +
> Plan 120 `core_demo_e2e` green) and pairs with the sealed-volume runtime mount
> (`main`'s Plan 145, `145-app-deps-completion`) — land *after* that mount leg so the
> `fix → rebuild → reseal → mount` loop is real end-to-end. Independent of this branch's
> Plan 145 (snapshots/`watch`).

## Context

A peer single-purpose Apple-Silicon sandbox ships two dependency-security features as
headline DX: a single OSV-backed vulnerability scan that spans every ecosystem, and
**automatic fixes** — it tells you the patched version and offers to apply it. We already
have a *stronger* substrate (the sealed, attested, hash-chained deps volume — claim 11 /
ADR-047), but on the audit leg specifically we are behind in three concrete ways:

1. **Two scanners, two schemas.** `run_cve` (`crates/mvm-host-vm-init/src/install.rs`)
   branches per language: `pip-audit` for Python, `pnpm audit` for Node. The host then
   parses *two* different JSON shapes (`CveFinding` in
   `crates/mvm-cli/src/commands/deps/inspect.rs:307` handles both
   `{"dependencies":[…vulns…]}` and `{"advisories":{…}}`). Adding Rust/Go later means a
   third scanner and a third shape.
2. **Detect-and-gate only.** `apply_install_gate` (`crates/mvm-build/src/app_deps_gate.rs`)
   fails closed on high/critical (`GateError::HighCveFinding`) and `mvmctl deps audit`
   reports a severity histogram — but neither tells you *what clears it*.
3. **We discard the fix.** OSV (and the underlying advisories) carry the first fixed
   version per finding. `CveFinding` parses only `{name, severity}` and drops it.

This plan unifies the scan on **OSV** (one scanner — `osv-scanner` — one typed schema,
cross-ecosystem, ready for Rust/Go), captures the fixed-version data, and adds a
remediation surface. It changes only the *audit data source + its presentation*; the
seal/attest/admit machinery (`seal_volume`, `verify_sealed_volume`, `DepsVolumeBinding`,
the audit chain) is untouched. Two hard invariants carry through:

- **The sealed volume stays immutable.** `deps fix` edits the user's *source* lockfile
  (their repo file the volume was built from) and re-runs the normal build→install→seal
  path. It never rewrites bytes inside `~/.mvm/volumes/deps/<hash>/`.
- **No build/install on the host.** `osv-scanner` is a *static* lockfile analyzer (reads
  files, installs nothing) so it is safe on either side; the build-time scan stays in the
  builder VM where it runs today. Any version *resolution* or reinstall that `deps fix`
  triggers runs in the builder VM via the existing installer — see
  [[feedback_builder_tools_on_host]].

This strengthens claim 11's *surfacing*; it adds no security claim and moves no witness.

## Architecture (what already exists)

- **In-VM scan:** `run_cve(language, lockfile_in_vm, cve_path, runner, …)`
  (`crates/mvm-host-vm-init/src/install.rs:506`) shells the per-language tool inside the
  builder VM, writing `cve.json`. Treats "ran without crashing" as success (scanners exit
  nonzero when they *find* vulns).
- **Sealed schema:** `cve.json` is one of four sidecars; the manifest
  (`VolumeManifest`, `crates/mvm-sdk/src/compile/deps_audit.rs:72`) hashes its bytes
  *verbatim* (`cve_sha256`) — it never parses the shape. So changing `cve.json`'s internal
  JSON does **not** touch `VOLUME_MANIFEST_SCHEMA_VERSION` or `verify_sealed_volume`. Only
  the *parsers* (gate + inspect) need to learn the new shape.
- **Gate:** `apply_install_gate(&InstallResult, GateLevel)`
  (`crates/mvm-build/src/app_deps_gate.rs:150`) → `GateError::HighCveFinding{…}` under
  `Prod`; `Dev` warns and continues.
- **Surfacing:** `mvmctl deps inspect` builds `CveSummary{severity_histogram, …}`
  (`inspect.rs:92`, `build_report` at :118); `mvmctl deps audit` re-runs the scan,
  rewrites `cve.json`, reseals, and renames the volume to its new hash, logging the
  rollover loudly (`crates/mvm-cli/src/commands/deps/audit.rs`; `AuditRunner` trait at :93).
- **Egress:** the builder-VM scan reaches the network through the exact-match allowlist
  (`crates/mvm-egress-proxy/src/allowlist.rs:47`): `pypi.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`, `objects.githubusercontent.com`. No wildcards.
- **CI:** the `app-deps-audit` job (`.github/workflows/ci.yml`) seals a clean + a
  high-CVE fixture, asserts the prod gate refuses the high-CVE one and dev admits it, and
  that a byte-flip on `cve.json` makes inspect refuse.

## Tech Stack

Rust workspace; `osv-scanner` from nixpkgs in the builder-VM flake; `clap` subcommands
under `crates/mvm-cli/src/commands/deps/`; `serde`/`sha2` for the sealed schema; `tests/cli.rs`
for arg-parse; `cargo test --workspace` + the `app-deps-audit` CI lane as gates.

---

## Workstream A — Unify the scan on OSV (one tool, one schema)

Per [[feedback_no_backcompat_first_version]] this *replaces* the two per-ecosystem
shapes — it does not add a third alongside them. Existing sealed volumes carry old-shape
`cve.json` and must be re-audited/rebuilt to gain the new schema; that is acceptable
pre-release.

### Task A1: ship `osv-scanner` in the builder VM
- [ ] Add `osv-scanner` to `nix/images/builder-vm/flake.nix` (the package set that already
      provides `pip-audit` / `pnpm` / `cyclonedx-py`). Keep `cyclonedx-py` / `pnpm sbom`
      for the SBOM leg — OSV replaces only the *CVE* leg. Confirm the binary lands on the
      installer `PATH` the `CommandRunner` sees.

### Task A2: one language-agnostic `run_cve`
- [ ] Rewrite `run_cve` (`install.rs:506`) to drop the per-`Language` match and invoke a
      single command: `osv-scanner --lockfile <lockfile_in_vm> --format json --output
      <cve.json>`. `osv-scanner` sniffs the lockfile kind (`requirements.txt`,
      `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, …) so one code
      path covers every ecosystem. Preserve the current success rule (file written ⇒ ok;
      nonzero exit on findings is expected) and the missing-tool stub fallback
      (`CVE_EMPTY_STUB`) so the gate behaviour on a tool-less host is unchanged.

### Task A3: typed OSV finding schema
- [ ] In `crates/mvm-sdk/src/compile/deps_audit.rs`, add the typed shape both the gate and
      inspect parse (one place, `#[serde(deny_unknown_fields)]` like the rest):
      `CveResult { results: Vec<OsvPackageResult> }`, `OsvPackageResult { package,
      ecosystem, version, vulns: Vec<OsvVuln> }`, `OsvVuln { id, aliases: Vec<String>,
      severity: Option<String>, fixed_version: Option<String> }`. `fixed_version` is the
      first fixed release from the advisory's `affected.ranges` — the data we currently
      drop. Serde roundtrip + a fixture-parse test live here.

### Task A4: extend the egress allowlist for the OSV DB
- [ ] `osv-scanner` pulls its database from Google Cloud Storage / the OSV API. Add
      `api.osv.dev` and `osv-vulnerabilities.storage.googleapis.com` to
      `ALLOWED_HOSTS` (`allowlist.rs:47`), update the module doc comment's host list, and
      mirror the existing exact-match tests (`a.is_allowed("api.osv.dev", 443)` true;
      `mirror.osv.dev`, port 80, etc. false). Record the two-host addition in ADR-047
      (Task C1) — the allowlist and the ADR must not drift.

### Task A5: point the parsers at the OSV shape
- [ ] `inspect.rs`: replace the two-shape `CveFinding` parser (`:307`–`:366`) with one that
      reads `CveResult` (A3); keep `severity_histogram` and the top-affected-packages
      output identical, and carry `fixed_version` into the report for WS-B. Update the
      embedded fixture tests (`build_report_handles_pnpm_audit_shape` etc.) to OSV shape.
- [ ] `app_deps_gate.rs`: parse `InstallResult`'s CVE input from the OSV shape; high/critical
      still produces `GateError::HighCveFinding` (first wins). Gate semantics unchanged —
      only the input shape moves. Update the gate's high-CVE fixture accordingly.

---

## Workstream B — Remediation surface (the fix)

### Task B1: show the fix in `deps audit` / `deps inspect`
- [ ] Render the captured `fixed_version`: for each high/critical finding print
      `lodash 4.17.4 → 4.17.21 clears GHSA-jf85-… (high)`; findings with no fixed release
      print `… no fixed version published (manual)`. `--json` gains `fixed_version` per
      finding. Pure presentation over A3 — no resolution, no network.

### Task B2: `mvmctl deps fix`
- [ ] New subcommand `mvmctl deps fix [<volume_hash>] [--lockfile <path>] [--severity
      high|critical] [--write] [--json]` under `crates/mvm-cli/src/commands/deps/`. Behaviour:
  - Resolve the *source* lockfile: `--lockfile`, else the pointer in
    `meta.json.annotations` (the installer records the lockfile path at seal time).
  - For each gating finding with a `fixed_version`, compute the minimal source-lockfile
    edit that bumps that package to its first fixed release ≥ current. Print a unified diff.
  - **Default is dry-run** (print diff + the would-be new volume hash). `--write` applies
    the edit to the source lockfile, then invokes the existing builder-VM
    install→seal→audit path to produce a new sealed volume — no host install (see Context).
  - **Never** edit the sealed volume in place. Refuse + exit nonzero if asked to.
  - Scope guard: direct deps with a single clean fixed version only. Transitive-only vulns,
    or a bump that conflicts with another pinned constraint, are reported as
    `manual: <pkg> needs <ver> but <constraint> blocks it` — never silently guessed.
- [ ] Bind into audit honesty: a `--write` rebuild yields a new volume hash, so any plan
      bound to the old hash fails admission. Reuse the loud reseal+rename log from
      `audit.rs` so the user knows to rebind. No new audit event type.

### Task B3: tests
- [ ] `tests/cli.rs`: `mvmctl deps fix --help` + arg parse (`--severity`, `--write`,
      `--lockfile`, `--json`; mutually-exclusive `--write`/dry-run default).
- [ ] Unit: `deps fix --dry-run` on a fixture lockfile with a known vulnerable+fixed
      package emits the correct one-line bump diff; a finding with no fixed version yields
      `manual`, never a guessed edit; a conflicting-constraint fixture yields `manual`.
- [ ] Gate/parse: OSV-shape `cve.json` with a high finding still trips
      `GateError::HighCveFinding`; `severity_histogram` matches the OSV fixture; allowlist
      exact-match tests for the two OSV hosts.

---

## Workstream C — Docs + ADR amendment + CI

### Task C1: amend ADR-047
- [ ] Update `specs/adrs/047-app-deps-audit-pipeline.md`: record the move from
      per-ecosystem scanners to OSV as the single CVE source, the two added allowlist hosts
      (now six, not "exactly four" — fix the prose the allowlist comment quotes), and the
      `deps fix` remediation surface. State plainly: strengthens claim 11 surfacing, adds
      no claim, moves no witness — so `specs/claims/catalog.md` is unchanged unless the CI
      lane's witness name moves (C3). Keep §"Out of scope" honest (see Deferred below).
      Per [[feedback_adr_out_of_scope_discipline]] keep additions in the same threat model.

### Task C2: reference docs
- [ ] `public/src/content/docs/reference/cli-commands.md`: document `mvmctl deps fix` and
      the new `deps audit` fixed-version output. `public/src/content/docs/contributing/development.md`:
      note `osv-scanner` as the CVE tool the builder-VM flake provides.

### Task C3: CI lane
- [ ] Update the `app-deps-audit` job (`.github/workflows/ci.yml`): regenerate the clean +
      high-CVE fixtures so they seal OSV-shape `cve.json` (via `mvm-build`'s
      `mvm-app-deps-fixture-tool`), keep the prod-refuse / dev-admit / byte-flip assertions,
      and add a `mvmctl deps fix --dry-run --json` assertion that the high-CVE fixture
      surfaces the expected `fixed_version`. If a witness file/lane name changes, update
      `specs/claims/catalog.md` in the same commit ([[project_spec_numbering_chaos]] sibling
      gate `check-claim-catalog`).

---

## Out of scope / deferred

- [ ] **Transitive / multi-constraint remediation.** v1 fixes direct deps with a single
      clean bump; conflicting-constraint and transitive-only findings are *reported*, not
      solved. A real version solver (run in the builder VM) is a later plan.
- [ ] **Continuous / scheduled re-audit** (the peer tool hints at always-on monitoring) →
      fleet concern, belongs in mvmd; add a counterpart note in `mvmd/specs/notes/`. Do not
      build a daemon here.
- [ ] **Filesystem-access evidence** (the peer tool also logs which files a sandboxed run
      touched; mvm logs network flows but has *no* fs-access evidence). Larger lift —
      guest-side fs tracing — and in tension with the headless model; candidate for its own
      plan, explicitly **not** in this one.
- [ ] **Signing / pinning the OSV DB snapshot** for reproducible audits across time →
      future hardening; v1 trusts the OSV feed the same way today's pip-audit trusts PyPI.
- [ ] **A GUI** — `deps audit --json` / `deps fix --json` are the substrate a future UI
      would consume.

## Acceptance (this plan is done when)

- [ ] A single `osv-scanner` invocation produces `cve.json` for Python *and* Node from the
      builder VM; the per-language `run_cve` branch is gone; the gate and inspect parse one
      OSV schema.
- [ ] `mvmctl deps audit` / `deps inspect` show the fixed version for each gating finding;
      `mvmctl deps fix` writes the minimal source-lockfile bump (dry-run by default),
      refuses to touch the sealed volume, and on `--write` produces a fresh attested volume
      via the builder-VM path with a loud hash rollover.
- [ ] ADR-047 amended; allowlist + ADR host lists agree; `app-deps-audit` CI lane green
      against OSV-shape fixtures; `check-spec-numbers` + `check-claim-catalog` pass.
- [ ] `cargo fmt --all -- --check` (nightly — [[reference_ci_lint_uses_nightly_rustfmt]]),
      `cargo test --workspace`, `cargo clippy --workspace -- -D warnings` green.

## Self-review

- **Reuses, does not rebuild:** seal/verify/admit, the `AuditRunner` seam, the reseal+rename
  loop, the gate, the egress allowlist, and the `app-deps-audit` lane all already exist —
  this swaps one scanner + schema and adds a presentation/`fix` surface over them.
- **Minimal blast radius:** `cve.json` is hashed verbatim, so the OSV shape change touches
  zero of the manifest/admission machinery — only two parsers.
- **Invariants held:** sealed volume immutable (`fix` edits source, rebuilds in-VM); no
  host install; allowlist stays exact-match; gate semantics unchanged.
- **Honest scope:** transitive/conflict cases reported not guessed; no new claim; deferred
  items (fs evidence, scheduled re-audit, DB pinning) named so omission is deliberate.
- **Dependencies explicit:** after Plan 120 green + the sealed-volume runtime mount
  (`main` Plan 145) so `fix → rebuild → mount` is a real loop; independent of this branch's
  Plan 145.
