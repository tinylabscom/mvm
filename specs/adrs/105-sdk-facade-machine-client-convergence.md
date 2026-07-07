# ADR-105: SDK ↔ facade machine-driving convergence on the `MvmClient` trait

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: `specs/notes/mvm-client-facade-design.md` + Plan 216 (the `mvm-client` facade), ADR-104 (cloud control-plane trust boundary — the facade's remote path), ADR-041 (signed audited execution plans — claim 8, the admission the local `run` path must not skip). Sequenced by: Plan 218.

## Update (2026-07-06): the trait lives in `mvm-core`, one user-facing crate

The original decision below put the trait + DTOs in a standalone `mvm-client`
crate and pushed `LocalBackend` into a second `mvm-client-local` crate to keep
the first `mvm-*`-free. Two crates, two imports (`mvm_client::{MvmClient, …}` +
`mvm_client_local::LocalBackend`) — confusing for consumers.

That two-crate split is replaced. The trait + DTOs + `MockBackend` + the remote
`GatewayBackend` now live in **`mvm-core::client`**, behind a `client` feature
(the gateway behind `client-remote`). `LocalBackend` and `connect` live in a
single user-facing **`mvm-client`** crate that re-exports the `mvm-core::client`
surface, so consumers write one import:

```rust
use mvm_client::{MvmClient, MachineSpec, LocalBackend};
```

**Why this is now the right home** — and why the "rejected: put it in
`mvm-core`" bullet below was mistaken: it claimed the `check-core-runtime-free`
gate "forbids pulling async runtimes there." The gate (`xtask
check-core-runtime-free`) only forbids **`tokio`**. `async-trait` is a
proc-macro (`proc-macro2`/`quote`/`syn`) that desugars async methods to boxed
futures — it pulls no async runtime — so gating it behind `client` keeps
`mvm-core`'s default closure `tokio`-free, and the guest-agent gate
(`check-guest-agent-runtime-free`, which *does* forbid `async-trait`) stays
green because the guest never enables the feature. The cycle the split existed
to avoid also dissolves: `mvm-core` is the foundation everyone already depends
on, so `mvm-sdk` reaches the trait via `mvm-core/client` with no new edge, and
`LocalBackend`'s `mvm-backend` dependency stays above the foundation in
`mvm-client`. `mvm-sdk`'s subprocess `SubprocessBackend` and the cycle guard
(`no_backend_dep.rs`) are unchanged in intent.

The prose below is the original (superseded) reasoning, kept for history.

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

The trait + DTOs must live in a crate whose **manifest declares no `mvm-*` dependency at all**. A first attempt — `mvm-client` with `default-features = false` — **fails**: Cargo detects cycles on the *manifest* graph, **optional dependencies included**. Because `mvm-client`'s manifest declares `mvm-backend` (for the `local` feature), it forms a cycle regardless of features:

```
mvm-sdk → mvm-client → mvm-backend → mvm-build → mvm-network → mvm-sdk
```

(verified live: `cargo` refuses with `cyclic package dependency: mvm-backend depends on itself`). Turning the feature off does not help — the edge is in the manifest.

The real fix is structural: **extract `LocalBackend` (the only `mvm-backend`-linking piece) into a separate `mvm-client-local` crate.** Then `mvm-client` holds the trait + DTOs + `GatewayBackend` + `connect` and its manifest carries **zero `mvm-*` deps**, so `mvm-sdk` can depend on it freely. `mvm-client-local` sits *above* the runtime (it links `mvm-backend`) and is used by the CLI. `connect(Target::Local)` — which can no longer reach `LocalBackend` — directs callers to construct `mvm_client_local::LocalBackend` directly.

## Decision

Keep the two crates and their **distinct responsibilities** — `mvm-sdk` is *authoring* (the `Workload` IR: image, entrypoints, deps, resources, network, hooks), `mvm-client` is *operating* (drive machine lifecycle). Converge only the overlapping *"drive a machine"* mechanism onto the shared trait:

1. **One interface: `MvmClient`.** The trait + DTOs are the single machine-driving contract, in `mvm-client` — whose manifest carries no `mvm-*` dependency (`LocalBackend` moved to `mvm-client-local`). Every layer depends on that cycle-free crate for the contract.
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
