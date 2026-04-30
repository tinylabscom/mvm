# Plan 30 — W6: documentation + CI gates

> Status: ✅ shipped — 2026-04-30
> Owner: Ari
> Parent: `specs/plans/25-microvm-hardening.md` §W6
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Estimated effort: 1 day (after the other workstreams have landed)
>
> ### Shipped artifacts
>
> - **W6.1** ADR-002 lives at
>   `specs/adrs/002-microvm-security-posture.md` (already shipped).
> - **W6.2** `CLAUDE.md` "Security model" section enumerates the
>   seven CI-enforced claims, names the test/workflow that backs
>   each one, and links to ADR-002 + plan 25.
> - **W6.3** `.github/workflows/security.yml` hosts five lanes:
>   `cargo-deny` (W5.2), `cargo-audit` (W5.2), `prod-agent-no-exec`
>   (W4.3), `reproducibility` (W5.3), `fuzz` (W4.2 — 5 min on PRs,
>   30 min on the nightly cron), and `hash-verify-tests` (W5.1).
>   Boot-regression and verity lanes (W2/W3) are intentionally
>   left out until the corresponding workstream tests exist —
>   the workflow grows alongside its inputs.
> - **W6.4** `mvmctl security status` now adds five live probes:
>   vsock proxy socket mode (W1.2), `~/.mvm` mode (W1.5), pre-built
>   dev image cache state, `deny.toml` presence (W5.2), and a
>   reminder of the hash-verified download path (W5.1). The
>   non-JSON output now also prints the public CI-badge URLs for
>   the security and CI workflows. Four unit tests cover the
>   probe shape and a couple of representative paths.

## Why

Without W6, the work in W1-W5 is invisible. The whole point of
ADR-002 is that the project's security claims are *technically
verifiable*; W6 is what surfaces those checks to contributors,
maintainers, and users. CI gates that fail on regressions, a
documented security model so contributors don't accidentally
weaken it, and a `mvmctl security status` that shows an operator
the live state of every check.

W6 is small but load-bearing. Without it, every other workstream
quietly degrades over time as new code lands.

## Scope

In: docs (`CLAUDE.md`, `specs/adrs/002`), one new GitHub Actions
workflow (`.github/workflows/security.yml`), and an enrichment
of `mvmctl security status`.

Out: protocol-level changes, build-system changes. W6 only wires
existing tests and asserts existing invariants.

## Sub-items

### W6.1 — ADR-002 ✅ shipped

The ADR lives at `specs/adrs/002-microvm-security-posture.md`. No
further work; this checkbox is here for accounting.

### W6.2 — `CLAUDE.md` security model section

**What**

`CLAUDE.md` today has one sentence: "No SSH in microVMs, ever:
microVMs are headless workloads. … Guest communication uses
Firecracker vsock only." Replace with a full subsection:

```md
## Security model

mvm makes seven CI-enforced security claims:

1. *No host-fs access from a guest beyond explicit shares.* —
   tested: `crates/mvm-runtime/tests/w2-guest-isolation.rs`.
2. *No guest binary can elevate to uid 0.* —
   tested: `crates/mvm-runtime/tests/w2-no-new-privs.rs`.
3. *A tampered rootfs ext4 fails to boot.* —
   tested: `crates/mvm-runtime/tests/w3-verity-tamper.rs`.
4. *The guest agent does not contain `do_exec` in production.* —
   gated: `.github/workflows/security.yml::symbol-check`.
5. *Vsock framing is fuzzed.* —
   gated: `.github/workflows/security.yml::fuzz`.
6. *Pre-built dev image is hash-verified.* —
   tested: `crates/mvm-cli/tests/dev-image-hash.rs`.
7. *Cargo deps are audited on every PR.* —
   gated: `.github/workflows/security.yml::cargo-{deny,audit}`.

Out of scope (named in ADR-002):

- A malicious *host*. mvmctl trusts the host with the
  hypervisor and private build keys.
- Multi-tenant guests.
- Hardware-backed key attestation.

Architecture detail in
`specs/adrs/002-microvm-security-posture.md`. Implementation
sequence in `specs/plans/25-microvm-hardening.md`.
```

**Files**

- `CLAUDE.md`: replace the "No SSH" sentence with the section
  above.

**Tests**

- A markdown linter run as part of the security workflow
  ensures the section keeps a current shape — but the real
  test is human review on PRs that touch security paths.

### W6.3 — `.github/workflows/security.yml`

**What**

One workflow file that hosts every CI-side gate. Triggers: pull
requests targeting `main`, plus a nightly cron. Skips: doc-only
changes (paths-ignore). Lanes:

- **Linting / dep checks** (Ubuntu, fast):
  - `cargo deny check` (W5.2).
  - `cargo audit` (W5.2).
  - `cargo clippy --workspace --all-targets -- -D warnings`.

- **Symbol check** (Ubuntu, fast):
  - Build production `mvm-guest-agent`.
  - `nm` + grep for `do_exec`/`exec_handler` (W4.3).
  - Fail on hit.

- **Reproducibility** (Ubuntu, slower):
  - Double-build mvmctl, hash both, diff (W5.3).

- **Fuzz** (Ubuntu, 1h time-budget):
  - `cargo +nightly fuzz run parse_request_frame -- -max_total_time=3600`
    (W4.2).
  - Failure means a panic; uploads the crash artefact to the
    PR.

- **Boot regression** (Linux/KVM lane):
  - Builds a test microVM with two services.
  - Asserts per-service uid isolation (W2.1).
  - Asserts ro `/etc/passwd` (W2.2).
  - Asserts `setpriv --no-new-privs` denies `su` to root
    (W2.3).
  - Asserts seccomp `essential` denies `mount(2)` (W2.4).
  - Asserts dm-verity boot (W3) and tamper-panic (W3.2).
  - Asserts agent runs as uid 901 (W4.5).
  - Asserts dev image SHA-256 verification (W5.1).

The boot lane is the most expensive; gate it on `paths` so it
runs only when guest-shape code actually changes.

**Files**

- `.github/workflows/security.yml`: ~150 lines, structured by
  lane.

**Tests**

- The workflow is the test infrastructure. A test PR that
  intentionally fails one gate (e.g., flips
  `deny_unknown_fields`) shows the gate fires.

### W6.4 — `mvmctl security status` enrichment

**What**

`crates/mvm-cli/src/commands/ops/security.rs::security_status`
already exists and prints the seccomp profile + posture summary.
Add live checks:

- **Proxy socket mode.** `stat ~/.mvm/vms/mvm-dev/vsock.sock`,
  print mode + complain if not 0700.
- **Dev image roothash.** Read the bundled-with-mvmctl expected
  roothash, read the actually-running rootfs's roothash from
  the dev VM's kernel cmdline (`/proc/cmdline` via
  `shell::run_in_vm`), confirm match.
- **Active seccomp tier.** Read it from
  `~/.mvm/config.toml` or the most recent `mvmctl up` invocation
  (whatever's authoritative; document if neither).
- **CI badges URL.** Print the public URL for each badge so the
  user can sanity-check the project-wide gates' state.

JSON output mode (`--json`) for scripting. Human output is
table-shaped with PASS/WARN/FAIL columns, pattern matching the
project's existing `doctor` command.

**Files**

- `crates/mvm-cli/src/commands/ops/security.rs::security_status`:
  add the four new probes, structure as a list of
  `SecurityCheck { name, status, detail }` records.

**Tests**

- Unit test for each probe with mocked filesystem / shell.
- End-to-end: `mvmctl security status` against a fresh `dev up`
  prints all-green; against a chmod'd-bad socket prints the
  one expected red.

## Sequencing

W6.1 ✅ done. The other three are sized as one PR each:

1. PR-A: W6.2 — pure docs.
2. PR-B: W6.3 — workflow file. Lanes are added as the
   underlying tests they invoke land (W2/W3/W4/W5). Initial
   version of the workflow runs only the lanes whose tests
   exist; new gates appear as their PRs land.
3. PR-C: W6.4 — `security status` enrichment.

PR-B is iterative: it lands in chunks alongside the workstreams
it gates rather than as a single mega-PR.

## CI gates added by this plan

W6 doesn't add gates; it *hosts* the gates from W2-W5. This plan
is the integration layer.

## Rollback shape

- W6.2 docs: trivial.
- W6.3 workflow: disabling a lane is a one-line `if: false`.
- W6.4 status checks: each probe is independent; remove with
  no API impact.

## Reversal cost

Low for all three.

## Acceptance criteria

W6 is done when:

1. ✅ `CLAUDE.md` contains the "Security model" section
   linking to ADR-002.
2. ✅ `.github/workflows/security.yml` runs all the lanes that
   correspond to landed workstreams; failing any one blocks
   merge.
3. ✅ `mvmctl security status` prints the four new probes and
   reports correct PASS/WARN/FAIL on a known-good and
   known-bad host configuration.
4. ✅ Plan 25 §W6 checkboxes flipped.
5. ✅ The security badges in the README (or wherever) link to
   the workflow's runs.
