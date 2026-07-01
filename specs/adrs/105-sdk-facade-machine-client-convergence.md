# ADR-105: SDK ↔ facade machine-driving convergence on the `MvmClient` trait

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: `specs/notes/mvm-client-facade-design.md` + Plan 216 (the `mvm-client` facade), ADR-104 (cloud control-plane trust boundary — the facade's remote path), ADR-041 (signed audited execution plans — claim 8, the admission the local `run` path must not skip). Sequenced by: Plan 218.

## Context

There are **two** clients that drive local microVM lifecycle, with overlapping responsibility and different mechanisms:

- **`crates/mvm-sdk/src/machine.rs`** — a builder-based client (`MachineClient`, `Machine::{start, stop, exec, shell}`, `MachineRunBuilder{image, command, …}`) whose module doc says it *"deliberately shells to `mvmctl machine …`"* — it drives lifecycle by spawning the `mvmctl` subprocess.
- **`crates/mvm-client`** — the `MvmClient` facade: `list_machines` / `run_machine` / `stop_machine` / `machine_logs` over `LocalBackend` (in-process) or `GatewayBackend` (REST). Landed in Plan 216.

Both drive machines; the SDK reinvents it via subprocess. That is the repo's most common bug source (duplicated logic drifts) applied to a security-sensitive surface — the SDK's `run` and the facade's `run` both ultimately need the signed-plan admission (claim 8), and two separate drivers means two places to get admission right (or wrong).

### Why the SDK shells a subprocess — the constraint that shapes any fix

The dependency graph runs high→low:

```
mvm-client (local feature) → mvm-backend → mvm-build → mvm-sdk → mvm-core
```

`mvm-sdk` sits **below** the runtime. If the SDK linked `LocalBackend` (which pulls `mvm-backend`), the result is a cycle: `mvm-sdk → mvm-client(local) → mvm-backend → mvm-build → mvm-sdk`. The process boundary in `machine.rs` is a **deliberate** way to sidestep that cycle, not an oversight. Any convergence must respect it.

### The unlock

`mvm-client` with **default features carries no `mvm-*` dependencies** — only `async-trait` / `serde` / `thiserror`; `mvm-backend` and `mvm-core` are optional, pulled only by the `local` feature. So the **trait + DTOs are cycle-safe**: `mvm-sdk` can depend on `mvm-client` (`default-features = false`) to get `MvmClient` + `MachineSpec` etc. without pulling the runtime, and provide its own subprocess-backed impl.

## Decision

Keep the two crates and their **distinct responsibilities** — `mvm-sdk` is *authoring* (the `Workload` IR: image, entrypoints, deps, resources, network, hooks), `mvm-client` is *operating* (drive machine lifecycle). Converge only the overlapping *"drive a machine"* mechanism onto the shared trait:

1. **One interface: `MvmClient`.** The trait + DTOs are the single machine-driving contract. Both layers depend on the cycle-safe light surface (`mvm-client` with `default-features = false` where the runtime must not be linked).
2. **Three impls, one per layer's constraint:**
   - `LocalBackend` (in-process) — CLI. Needs the runtime; lives above it.
   - `GatewayBackend` (REST) — studio / remote. No runtime dep.
   - **A subprocess impl in `mvm-sdk`** — the SDK keeps shelling `mvmctl machine`, but *behind `MvmClient`*, so it satisfies the same contract while respecting the cycle.
3. **One spec vocabulary.** The SDK's `Workload`/`App` IR is the rich authoring definition; it **lowers** to the facade's operational `MachineSpec` (a projection: image/resources/env → the run spec). No second parallel spec type maintained by hand.
4. **One admission path.** When the admitted-boot library seam lands (issue #1388 / Plan 214), *both* `LocalBackend::run` and the SDK's subprocess `run` route through the **same** admitted-boot function. There is never a second, admission-skipping boot path — the property claim 8 protects.

## Consequences

- The SDK's bespoke `machine.rs` shrinks to an `MvmClient` impl + the authoring-side builders; its ad-hoc lifecycle surface stops being a parallel API.
- Callers (SDK live/invoke, CLI, studio) program against `MvmClient`, so swapping transport or moving a workload local↔remote is a backend choice, not a rewrite.
- `MachineSpec` gains a documented lowering from `Workload`; the two stop drifting.
- No dependency cycle is introduced: the shared surface is the runtime-free trait+DTOs; runtime-linking impls stay in the crates that already sit above the runtime.

## Alternatives considered

- **Make `mvm-sdk` depend on `LocalBackend`.** Rejected — introduces the `mvm-sdk → mvm-backend → mvm-build → mvm-sdk` cycle. The subprocess boundary exists precisely to avoid this.
- **Merge `mvm-sdk` and `mvm-client`.** Rejected — they are genuinely different responsibilities (authoring vs operating) at different points in the dep graph; merging would drag the runtime under the SDK.
- **Leave two drivers, document the overlap.** Rejected — the duplication is on the security-critical `run`/admission path; two drivers means two admission implementations to keep correct. Converging on one trait + one admitted-boot fn is the whole point.
- **Put the shared spec/trait in `mvm-core`.** Considered. The trait is async (`async-trait`); `mvm-core` is the runtime-free foundation and the `check-core-runtime-free` gate forbids pulling async runtimes there. Keeping the trait in `mvm-client` (default-features light) is the cycle-safe home; `mvm-core` may hold pure DTO structs if reuse warrants.

## Scope / sequencing (Plan 218)

- **P1** — `mvm-sdk` depends on `mvm-client` (`default-features = false`); add a subprocess `impl MvmClient` (list/stop/logs) that shells `mvmctl machine`. Additive; the existing builders stay.
- **P2** — Define the `Workload`/`App` → `MachineSpec` lowering; the SDK's run builder produces a `MachineSpec`.
- **P3** — Migrate SDK live/invoke call sites to the `MvmClient` trait; retire the duplicated bits of `machine.rs`.
- **P4** — When the admitted-boot seam lands, wire `LocalBackend::run` **and** the SDK subprocess `run` through the one admitted-boot library fn. Closes issue #1388 for the facade.
