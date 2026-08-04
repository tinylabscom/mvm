# SDK & Testing Model

The authoring pipeline (SDK) and the verification pipeline (BDD-first testing) — the two halves that make "what the codebase does" and "what it's proven to do" the same thing.

## SDK

`mvm-sdk` keeps the existing pipeline shape: **tree-sitter → Workload IR → nix template**. The IR itself moves to `mvm-contract` (see the crate map in [02-architecture.md](02-architecture.md)); `mvm-sdk` retains authoring, the decorator, runtime-authoring support, and the pipeline logic that walks source through tree-sitter into that IR and out to a nix template. The template base is a user-specified **base OCI image**.

### `PackageType` trait

Each language detects its own manifest and surfaces a **locked** dependency set, preferring the strongest guarantee available:
- `uv.lock` / `poetry.lock` over `requirements.txt`
- a lockfile over bare `package.json`
- `Cargo.lock`
- `Package.resolved`

Falls back to the loose manifest when no lockfile exists, but flags it — a loose manifest is a degraded, not silent, path.

Built-in package types: Python, TypeScript, Rust, Swift. Users register their own via the trait — extensibility is first-class, not a special case bolted on later.

Custom package types run in the user's trust domain (the user wrote the detection/resolution logic), but the dependency set they produce still flows through the sealed app-deps audit (claim 11 in the claims catalog — see [04-security.md](04-security.md) and [08-adr-consolidation.md](08-adr-consolidation.md)) exactly like a built-in type's output. Extensibility never bypasses the hash-lock / CVE-scan / SBOM seal.

Language surfaces live under `crates/mvm-sdk/sdks/` (moved off the repo root as part of this restructure). The Python surface stays `mvm` — users only ever `import mvm`, regardless of how the internals are organized.

### Runtime SDK + decorator

Both are first-class and enabled — a user can control a live microVM via `mvm-client` from SDK code, not just author one ahead of time. The security boundary is **no shell in prod**: lifecycle operations, the declared entrypoint, audited output, `expose_tcp`, snapshot, and fork are all allowed against a sealed production VM. Arbitrary interactive `exec` or console access into a sealed prod VM stays dev-only, gated behind `dev-shell` — this is the same boundary that backs claims 4 and 15 in the security model (no `do_exec` symbol, no console symbol, in a production agent build).

## Testing — BDD-first

Every user-facing behavior and every security claim begins as a Gherkin `.feature` scenario, becomes a green cucumber-rs test, then a parametric implementation. Nothing is "done" until its scenario is green and CI-gated — this is a hard sequencing rule, not a preference: the scenario is written and red *before* the implementation, for every workstream from here forward.

- Suites live at `features/suites/sN_<name>/*.feature`, numbered by area: `s0_cli`, `s1_build_run`, `s2_egress_vsock`, `s3_secrets_pii`, `s4_verified_boot`, `s5_lifecycle`, `s6_admission_audit`.
- A dev-only cucumber-rs runner crate, `crates/mvm-conformance` — deliberately *not* one of the ~11 product crates in the target crate map — wires step definitions to `mvm-client`, so scenarios drive the real facade rather than a mock. This is what makes the scenarios trustworthy: they exercise the same entry point the CLI and SDK use, not a test-only shortcut.
- The claims catalog becomes executable: each numbered security claim maps to a scenario, complementing (not replacing) the existing machine-checked witnesses described in [04-security.md](04-security.md).
- `just bdd` runs the suite; it is folded into `just ci` / the full local gate, so a BDD regression blocks the same way a unit-test regression does.

See [06-execution-plan.md](06-execution-plan.md) WS0.6 (harness bring-up) and WS1g (SDK crate restructure) for the workstream detail, and [07-progress-and-decisions.md](07-progress-and-decisions.md) for what's landed so far.
