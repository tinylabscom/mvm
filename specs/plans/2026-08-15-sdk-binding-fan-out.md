# SDK binding fan-out

Backing: shipped-source
Validation: check-stubs

**Status: PROPOSED**
**Opened:** 2026-08-15

## Why

mvm ships two language SDKs. Comparable systems-runtime projects ship five or
six off a single stable C boundary, and the marginal cost of the sixth is a
shim rather than a port. mvm has the same boundary and has not spent it.

The prompt for this was an outside read of an edge-inference runtime that hangs
Swift, Kotlin, Flutter, React Native, Python and Rust off one opaque-handle C
ABI, so no binding reimplements engine logic. mvm's in-guest host-services
veneer is the same shape and says so in its own module doc: "A new language SDK
is then a shim-sized change — load the `.so`, marshal a request, call
`mvm_hsvc_call`, parse the reply — with zero new Rust binding code."

## The correction this plan exists to record

"Add more SDK languages" is not one job. mvm has **two** SDK surfaces with very
different marginal costs, and conflating them produces a wrong estimate.

### Surface A — in-guest host services (`libmvm_host_services.so`)

The C-ABI veneer in `crates/mvm-sdk/src/host_services_ffi.rs`. Two `no_mangle`
exports, JSON in, JSON out, one paired free function, an `i32` status. Workload
code running *inside* a booted guest calls it to reach `host.audit.v1` /
`host.time.v1` / `host.cost.v1`.

Existing consumers: `sdks/python/mvm/_hostsvc.py` (ctypes),
`sdks/typescript/src/_hostsvc.ts`.

**Marginal cost of a new language: a shim.** This is the surface where the
fan-out is genuinely cheap, and the design already anticipates it. The veneer
holds no key and is not a security boundary — every gate (the
`ExecutionPlan.services` binding, category forcing, size and rate caps,
correlation-id assignment) is host-side — so a new shim cannot widen the trust
surface.

### Surface B — host-side authoring and control

What `import mvm` gives you on a developer's machine. Two halves:

- **Generated types.** `xtask gen-stubs` drives Rust-owned JSON Schemas through
  pinned per-language generators (`datamodel-code-generator` for Python,
  `json-schema-to-typescript` for TypeScript) into `_ir`, `_protocol`,
  `_runtime`. `xtask check-stubs` fails on drift. Adding a language here is a
  new `StubArtifact` generator target — mechanical.
- **Hand-written facade.** `_cli`, `_machine`, `_sandbox`, `_session`,
  `_subprocess`, `audit`, `host`, the decorator/DSL surface. These wrap the
  `mvmctl` binary via subprocess; they are **not** FFI bindings. This is where
  the real per-language cost lives, and none of it is generated today.

So a new language costs: one codegen target (cheap) + one hostsvc shim (cheap) +
one facade (the actual work).

## The risk this plan must not create

Two facades already drift-check against each other by running the real packages
in `crates/mvm-conformance/tests/steps/sdk.rs`. That file hard-panics on any
language but `python` / `typescript`:

```rust
other => panic!("unsupported SDK fixture language {other:?}"),
```

That panic is load-bearing — it is the reason a third language cannot be added
without confronting the drift question. N hand-written facades with no shared
witness is N places for the CLI contract to rot silently. **No new facade lands
without its conformance fixtures in the same change.**

## Scope

- [ ] Generalize the SDK conformance fixture resolver beyond the two hardcoded
      languages, so `fixture_path` is table-driven and adding a language is data.
      Keep the refusal for an unknown language — turn the panic into a named
      error listing the registered set, matching `LaunchLane::from_str`.
- [ ] Add the chosen language to `xtask gen-stubs` as a `StubArtifact` generator
      target, with the generator version pinned in the xtask exactly as the
      existing two are, and `check-stubs` covering it.
- [ ] Add the hostsvc shim for the chosen language against the existing C ABI.
      No Rust changes: if the shim needs a Rust change, the veneer contract is
      wrong and that is a separate finding.
- [ ] Add the facade, scoped to what the conformance fixtures cover — the
      decorator/IR surface and the imperative runtime-recording surface. Do not
      port helpers no scenario exercises.
- [ ] Add conformance fixtures for both surfaces in the same change, so the new
      facade is drift-checked from its first commit rather than retrofitted.
- [ ] Add the language to the SDK release pipeline (`sdks/release.toml`) and to
      the SDK release dry-run lane.

## Recommendation on which language

**Go**, on the grounds that the workloads mvm targets — agents, infrastructure
control planes — are disproportionately Go, and Go's cgo story makes the
surface-A shim straightforward.

Deliberately not Rust: `mvm-sdk` *is* the Rust SDK, and a Rust consumer links
the crate rather than the C ABI, so "add Rust" is a packaging question, not a
binding one.

This is a product call, not a technical one. The plan holds for any target; only
the shim mechanics change.

## Sequencing note

`#2568` (feat/337) is in flight and touches env-var ownership across *both*
existing bindings plus `sdks/python/mvm/_cli.py`. Land that first. Starting a
third binding against a contract that is mid-move guarantees the new binding
encodes the old names.

## Out of scope

Nothing here changes the trust posture. Surface A is untrusted-guest code by
construction and surface B shells out to `mvmctl`, which performs its own
admission. A binding that appears to need a new host-side capability is a
finding to raise, not to implement inside this work.
