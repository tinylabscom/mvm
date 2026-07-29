# BDD / Conformance Setup: mvm vs. UOR Foundation Template

**Scope:** Compare the BDD and conformance-testing machinery in this repo with the
[`uor-Foundation/template`](https://github.com/uor-Foundation/template) repository,
identify gaps, and outline how the template's ideas could be adapted here (not
copied verbatim).

**Date:** 2026-07-29

**Implementation status:** Implemented on branch `feat/bdd-conformance-integration`.
The model register, generated `CONFORMANCE.md`, R1/R2/R4 `xtask` gates, R3
meta-gate, `VERIFICATION.md`, and PR CI wiring are all in place and passing
clippy/tests.

---

## 1. What the template provides

The template is intentionally *machinery only*: an empty claim register, an empty
ledger, and no shipped crates. Its relevant pieces are:

| Path | Purpose |
| --- | --- |
| `model/ids.toml` | Conformance ID register: every capability claim gets an ID, honesty level, suite, and statement. |
| `model/ledger.toml` | Non-ID claims (`some-true` reproductions, `open` measurements). |
| `model/authorities.toml` | External authorities cited by `some-true` claims. |
| `crates/model` | Parses the model and generates `CONFORMANCE.md`. |
| `crates/conformance` | BDD runner + honesty meta-gate. |
| `xtask` | Repository gates: `check-model`, `audit-limits`, `audit-deferral`. |
| `Justfile` | `just vv` acceptance gate; `just bdd` runs R2/R3 meta-gates. |
| `VERIFICATION.md` | Falsifiability table: every gate names the defect it is proven to catch. |

The template enforces six rules (R1–R6), of which the BDD/conformance-relevant
ones are:

- **R1** — `model/*.toml` is the single source of every claim; `CONFORMANCE.md`
  is generated from it.
- **R2** — Every claim has one of three honesty levels: `some-true`, `build`,
  or `open`. The suite must not assert an `open` claim or present a
  `some-true` claim as internally proven.
- **R3** — A capability begins as a register row, then a Gherkin scenario,
  then a failing test whose name ends in the ID, then the implementation.
- **R4** — Nothing is deferred (no `TODO`, `FIXME`, `unimplemented!`, etc.).
- **R5** — No unsanctioned error: shipped crates may only return errors the
  model sanctions.
- **R6** — Nothing shipped depends on a dev-only crate; no wildcard
  dependencies. Enforced by `cargo-deny`.

---

## 2. What mvm already has

| Capability | Where it lives | Status |
| --- | --- | --- |
| Gherkin feature files | `features/suites/**/*.feature` | ✅ 17 suites |
| cucumber-rs runner | `crates/mvm-conformance/tests/conformance.rs` | ✅ `harness = false`, feature-gated behind `bdd` |
| Step definitions / World | `crates/mvm-conformance/tests/steps/`, `tests/world.rs` | ✅ |
| Tag-based filtering | `crates/mvm-conformance/src/lib.rs` | ✅ `@wip`, `@live`, `@firecracker`, `@bundle` |
| `just bdd` recipe | `Justfile` | ✅ |
| BDD CI workflow | `.github/workflows/bdd.yml` | ✅ invoked by release/publication workflows |
| BDD compile-check on PR | `.github/workflows/ci.yml` "Clippy (BDD conformance target)" | ✅ compiles the target, but does not run scenarios |
| Claim catalog with witnesses | `specs/adrs/001-microvm-security-posture.md` + `xtask check-claim-catalog` | ✅ partial |
| Extensive xtask gates | `xtask/src/check_*.rs` | ✅ many custom lints |
| `cargo-deny` | `deny.toml` + `.github/workflows/security.yml` | ✅ |
| Falsifiability / verification doc | — | ❌ no `VERIFICATION.md` equivalent |
| Generated conformance index | — | ❌ no `CONFORMANCE.md` |
| Model-as-single-source TOML | — | ❌ no `model/` directory |
| Honesty-level discipline | — | ❌ not formalized |
| Capability order enforcement (R3) | — | ❌ not enforced |
| Deferral audit | — | ❌ no `audit-deferral` equivalent |
| Limit/error audit | — | ❌ no `audit-limits` equivalent |

In short: mvm has a **richer, production-grade BDD execution layer** (cucumber
runner, real `mvmctl` integration, live VM opt-ins, extensive fixtures) but lacks
the template's **claim-registry discipline** (single-source model, generated
conformance doc, honesty levels, R3 order enforcement).

---

## 3. Gaps and how to integrate them

### 3.1 A single-source claim register (`model/`)

**Gap:** Claims are currently embedded in prose (`specs/adrs/001-microvm-security-posture.md`)
and tracked through `check-claim-catalog`. There is no machine-readable register
that also owns the Gherkin scenarios.

**Integration option (adapt, don't copy):**

- Create a lightweight `model/` directory with TOML files tailored to mvm's
  existing taxonomy (e.g. `security-claims.toml`, `behavior-claims.toml`).
- Reuse the existing ADR-001 claims-catalog table as the seed data rather than
  starting from an empty register.
- Generate `CONFORMANCE.md` from that register.
- Keep the existing `features/suites/` file layout; add a required tag format
  such as `@MVM-CLI-01 @build` so the meta-gate can map scenarios to IDs.

This does not require adding a `repo-model` crate verbatim; the parsing and
checking can live in the existing `xtask` crate or in `mvm-conformance`.

### 3.2 Honesty levels (R2)

**Gap:** Claims are not classified by epistemic status. Marketing copy in docs
is gated by `check-doc-claims`, but there is no equivalent classification of
*security* claims as reproduced / built / measured.

**Integration option:**

- Add a `level` field to the existing ADR-001 claims-catalog rows:
  - `some-true` — reproduced from an authority (e.g. "Firecracker uses KVM").
  - `build` — constructed and validated here (e.g. "vsock-only egress").
  - `open` — measured and reported, never asserted (e.g. cold-start latency).
- Extend `check-doc-claims` or add a small `check-honesty` xtask that scans
  `README.md`, `CONFORMANCE.md`, and `public/src/content/docs/` for assertive
  words (`proves`, `guarantees`, `establishes`) attached to `open` or
  `some-true` IDs.

### 3.3 R3: feature → scenario → failing test → implementation

**Gap:** Scenarios and tests are not mechanically tied to registered IDs. An
implemented test can exist without a registered ID, and a registered claim can
exist without a scenario.

**Integration option:**

- Require every scenario to carry an ID tag (e.g. `@MVM-KERNEL-03`) and a level
  tag (e.g. `@build`).
- Add a meta-gate test in `crates/mvm-conformance/tests/meta.rs` (or as an
  `xtask`) that:
  1. Reads `model/*.toml`.
  2. Parses `features/suites/**/*.feature` for ID tags.
  3. Scans workspace test names for IDs (lowercased with underscores).
  4. Fails if any registered ID lacks a scenario or a test, or if any
     scenario/test names an unregistered ID.
- This can reuse the existing `workspace_test_names`-style logic already
  present in the template, or be simplified by reading `cargo test -- --list`
  output from a cached run.

### 3.4 Generated conformance doc (`CONFORMANCE.md`)

**Gap:** There is no single, generated, reviewer-visible conformance index.

**Integration option:**

- Generate `CONFORMANCE.md` from the `model/` register.
- Include:
  - ID, level, suite, and statement for every claim.
  - A mapping from each ID to its Gherkin scenario file and its test name(s).
  - A "cited authorities" section for `some-true` claims.
- Add an xtask gate `check-conformance-md` that regenerates the file in memory
  and diffs against the committed version, so edits to the doc must go through
  the model.

### 3.5 Deferral audit (R4)

**Gap:** The repo already forbids `unwrap()` in production code and has many
policy lints, but it does not have a repo-wide scan for deferral markers
(`TODO`, `FIXME`, `unimplemented!`, `XXX`, placeholder sections).

**Integration option:**

- Add an `xtask check-deferrals` gate that scans `crates/`, `xtask/`, `tests/`,
  `specs/`, and root markdown files for forbidden markers.
- Follow the template's trick of spelling markers in halves
  (`concat!("TO", "DO")`) so the gate can scan its own source without
  self-matching.
- Allow backticked mentions and narrow `EXEMPTIONS` entries, mirroring the
  style of `check-no-network-literals` and `check-single-home`.

### 3.6 Limit / error audit (R5)

**Gap:** The template restricts shipped crates to a small set of sanctioned
error types. mvm has richer error handling, but there is no gate ensuring every
reportable error is traceable to a declared model parameter.

**Integration option:**

- This is the hardest rule to adopt because mvm has many domain-specific error
  types. A practical adaptation is:
  - Inventory all error types returned by shipped crates.
  - In the claim register, map each error family to the claim that sanctions it
    (e.g. "`EgressPolicyError` is sanctioned by the vsock-only egress claim").
  - Add a gate that fails if a shipped crate introduces a new public error type
    not listed in the register.
- Do not try to collapse all errors into three generic types; that would be a
  copy of the template's shape, not its intent.

### 3.7 Falsifiability table (`VERIFICATION.md`)

**Gap:** There is no documented record of planted defects proving each gate can
fail.

**Integration option:**

- Add `specs/VERIFICATION.md` (or a section in `specs/SPRINT.md`) with a table:
  | Gate | Planted defect | Reported? |
- For each new or existing gate, include one row showing the defect that was
  introduced to prove the gate fires.
- Start with the new gates proposed above (`check-conformance-md`,
  `check-honesty`, `check-deferrals`) and backfill the most critical existing
  gates (`check-claim-catalog`, `check-no-overclaim`, `check-doc-claims`) over
  time.

### 3.8 BDD on the per-push path

**Gap:** The BDD suite only runs in release/publication workflows. A change can
break the cucumber runner and still pass ordinary PR CI (only `clippy-bdd`
catches compile failures).

**Integration option:**

- Add a lightweight "BDD smoke" job to `.github/workflows/ci.yml` that runs
  `just bdd` with `MVM_BDD_LIVE` unset. This executes the hermetic scenarios
  (`s0_cli`, `s7_workload_identity`, `s8_readme_contract`, `s9_kernel_pin`,
  `s11_snapshot`, `s12_warm_claim`) without KVM.
- Keep the full KVM-requiring scenarios in the existing `bdd.yml` workflow,
  called only where real microVMs are available.
- Alternatively, split the honesty meta-gate into a separate `.github/workflows/honesty.yml`
  job (as the template does) so a red mark reads as "claim drift" rather than
  "broken code."

---

## 4. Recommended phasing

A minimal, high-value integration would be:

1. **Model register (R1)** — Convert the ADR-001 claims-catalog table into a
   small TOML register under `model/` and generate `CONFORMANCE.md`.
2. **Scenario tags + R3 meta-gate** — Require every existing scenario to carry
   an ID/level tag; add a meta-gate tying IDs to scenarios and test names.
3. **Honesty lint (R2)** — Add `level` to register rows and scan docs for
   assertive language about `open` / `some-true` claims.
4. **Deferral audit (R4)** — Add `xtask check-deferrals` and drive existing
   `TODO`/`FIXME` items into tracked issues or completions.
5. **BDD smoke on PR** — Run hermetic BDD scenarios in `.github/workflows/ci.yml`.
6. **Falsifiability doc** — Add `specs/VERIFICATION.md` as gates are added.

`cargo-deny` (R6) and the rich cucumber execution layer are already in place,
so those do not need work.

---

## 5. What not to copy

- Do not copy `repo-model` / `repo-conformance` crate names or structure; mvm's
  existing `xtask` and `mvm-conformance` crates are the right homes.
- Do not adopt the template's restrictive three-error-type rule wholesale; mvm's
  domain is larger and needs a register-driven error inventory instead.
- Do not replace the existing ADR-based documentation with a generated doc;
  generate `CONFORMANCE.md` *in addition* to the ADRs, and keep ADRs as the
  narrative source.
- Do not drop `@wip` / `@live` / `@firecracker` tags; they are mvm's existing
  capability-filtering mechanism and map naturally onto the template's
  register-level discipline.
