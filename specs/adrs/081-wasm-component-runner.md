# ADR-081 — Production in-microVM wasm-component runner

**Status:** Proposed 2026-06-12.
**Extends** [ADR-080](080-wasm-preview-promotion-and-capability-policy.md) (§4 two
fidelity regimes — this ADR builds the prod-tier execution for the WASM-component
regime; §6 wasmtime as a new untrusted-input surface). **Builds on**
[ADR-069](069-wasm-sandbox-backend.md) (the off-isolation-scale wasm-sandbox
*preview* backend; this ADR is the *production microVM* path, not that backend).
**Cross-refs:** ADR-002 (claims 1–3 isolation, 5 untrusted parsers, 8 signed
plan, 10 egress, 11 sealed deps, 13 secrets), ADR-047 (app-deps audit — the
builder already compiles untrusted inputs), ADR-057 (symmetric builder VM — the
sandbox the AOT compile runs in), Plan 188 (the capability projection/clamp seam
this extends from network to fs/env).

## Context

ADR-080 §4 names two fidelity regimes for the Tier-0→ship promotion. The
**WASM-component** regime is the clean one: a workload that *is* a `.wasm`
runs on the same engine in preview and prod (wasmtime ≈ wasmtime), so the
microVM just wraps it. ADR-080 deferred building that prod runner to its own
design. This ADR is that design — the **production, in-microVM wasm-component
runner**: make "a `.wasm` is a workload" real, with the component executing on
**wasmtime inside the guest**, the microVM providing isolation.

The runtime mechanism is already scaffolded: `crates/mvm-guest/src/runner/`
has a `Wasm` runner variant whose interpreter is `wasmtime` and whose entry is
`wasmtime run dispatch.wasm`, using the stdin→stdout function-invoke contract —
handled exactly like the `python3`/`node` runners. So **wasmtime is a guest
binary** (Nix-baked into the rootfs), invoked as a subprocess. **mvm's host
code never links wasmtime.** The work is to wire the surrounding pieces:
admit the `.wasm` as an artifact, project policy into the guest's WASI config,
and bake the engine.

The browser / host-streamed *preview* execution of components (ADR-080's P8
relay) is a **separate** subsystem that consumes the same component artifact;
it is out of scope here.

## Decision

### 1. v1 targets WASI Preview 1 modules, with a P2-ready seam

v1 runs WASI Preview 1 modules via the existing `wasmtime run` + stdin→stdout
invoke contract — the most-scaffolded path. The artifact-admission, capability
projection, and IR shapes are kept **WASI-version-agnostic** so swapping to
WASI Preview 2 / the Component Model (WIT worlds, `wasi:sockets`,
`wasi:http`) is a runner-internal change, not a re-architecture. P1 has no
socket API, which is *why* network stays a microVM-layer concern in v1
(below).

### 2. The `.wasm` is an admitted, content-addressed artifact

v1 source is a **local `.wasm` file**: `mvmctl run ./component.wasm`
(auto-detected, or `--wasm`). The file is SHA-256'd and admitted through the
**existing claim-8/9 path** — a signed `ExecutionPlan` whose content-addressed
artifact is the `.wasm`, with provenance (digest, wasmtime version) recorded in
the chain-signed audit log. No parallel admission path.

- **Fast-follow (this ADR's P6 leg):** a registry reference
  (`--wasm <registry>@sha256:…`), reusing the OCI claim-14 path — mutable refs
  refused under `--prod`, cosign verification, provenance recorded.
- **Deferred:** SDK-compiled-from-user-code (author in any language → `.wasm`)
  — the byte-identical-preview dream lives there, but it needs per-language
  compile-to-wasm toolchains and is its own program.

### 3. WASI capabilities are clamp-authored — the Plan 188 seam extended network→fs/env

In WASI P1 the *fine* layer the component sees is **filesystem preopens + env
vars** (P1 has no sockets). These grants are governed by the **clamp model
from Plan 188**, now extended from network to fs/env: the workload **requests**
fs/env capabilities in its IR; the authoritative **tenant policy bounds** them;
the granted set is the **intersection** (a request can attenuate, never widen).
**Default-deny** on both sides — a component is denied every dir/var not
granted. This makes ADR-080 §3's "one capability policy, two enforcement
fidelities" literal:

- **fine:** the resolved capability policy → wasmtime fs preopens + env grants,
  in-guest (extends `mvm-core::policy::projection`).
- **coarse:** the microVM layer — nftables/passt egress (Plan 188/190, already
  built). In P1 this is the *only* network enforcement; the `WasiEgress`
  *network* grant shape (Plan 188) becomes live only at P2 sockets.

Env grants carry `SecretRef` placeholders, substituted host-side, never raw
(claim 13) — same as every other workload.

### 4. AOT-compile at build for prod; JIT only for preview

The dangerous step is turning attacker `.wasm` bytes into native code. For the
**production in-microVM path**, the component is **AOT-compiled in the builder
VM** (`wasmtime compile` → a `.cwasm`); the guest runs the **precompiled**
artifact. Consequences:

- **No JIT in the live guest** → the guest seccomp profile can **forbid**
  `mmap(PROT_EXEC)` / exec-`mprotect`, materially tightening the
  workload-bearing tier (the whole point of running in a locked-down microVM).
- The compiler runs on attacker bytes in the **builder**, which already
  executes attacker-influenced build logic (`nix build`, `uv pip install`) in
  its own sandbox (ADR-047/057) — no *new* privileged trust boundary, one more
  build step in a place designed for it.
- **Deterministic** (claim 7 double-build) given a pinned wasmtime version,
  which is recorded in provenance; the `.cwasm` is same-arch as the guest by
  construction; precompiling removes cold-start JIT latency.

The **preview tier keeps JIT** (`wasmtime run` the `.wasm`) — there the
browser / host sandbox contains the JIT and the fast author-loop matters.

**Fidelity note (honest):** prod runs the AOT `.cwasm`, preview JITs the same
source `.wasm` — *same source component, two compilations*, identical wasm
semantics but not literally the same machine code. A far tighter gap than the
source-language regime's Pyodide-vs-CPython; recorded, not hidden.

### 5. wasmtime is a guest binary, never a host dependency

wasmtime enters the rootfs via Nix for `Wasm`-kind workloads (like `python3`/
`node`), pinned and recorded in the build closure. The host crates do **not**
take a `wasmtime` Cargo dependency — keeping the host TCB unchanged and the new
untrusted-input surface *inside* the guest, behind the microVM.

## Security considerations (the threat-model delta)

The new surfaces beyond the existing claim set:

1. **wasmtime as a new untrusted-`.wasm` parser/compiler (claim 5 family).** A
   wasmtime validation/codegen bug → arbitrary code where it runs. Mitigated by
   defense-in-depth (Decision 4 puts the *compile* in the sandboxed builder and
   the *execution* of precompiled code in the sealed guest with no JIT), version
   pinning + `cargo deny`/audit, and confining the in-guest wasmtime as the
   uid-901 setpriv service (claims 1–2). **We do not fuzz wasmtime ourselves —
   we rely on its upstream OSS-Fuzz coverage** (the ADR-055 precedent for the
   virtio parsers) and record that as the posture.
2. **The WASI config generator is new security-critical code**, peer to the
   Plan 188 projection seam: it turns the resolved policy into the actual
   preopen/env grant set; a bug = over-grant. It carries the same discipline —
   **deny-by-default, the clamp invariant (a request never widens tenant
   policy), and negative tests** ("a denied dir is not preopened").
3. **Resource exhaustion.** The microVM cgroup/jailer caps bound the blast
   radius, with wasmtime **fuel/epoch + a wall-clock timeout** as the inner
   bound so one component cannot wedge its VM.
4. **WASI preopen enforcement is wasmtime's to get right** (path-traversal /
   symlink escape out of a preopen) — an explicit **trust assumption**, the way
   nftables is trusted for egress. Bounded by: the rootfs is verity/read-only
   except granted writable dirs, and an escape is still inside the sealed guest.
5. **Secrets-in-env are exfil-safe in v1, with a P2 caveat.** A substituted
   credential in env (claim 13) has no exfil path in P1 (no sockets; network
   blocked at the microVM). When P2 `wasi:sockets` lands, the Plan 129
   egress-substitution / host proxy MUST mediate the component's outbound or a
   network-granted component could leak it. Flagged now, enforced at P2.
6. **P2 imports/worlds are capabilities to clamp** (forward-looking): a
   component's imports (`wasi:http`, custom host functions) are ambient
   authority if auto-satisfied. The capability/clamp model must govern which
   imports are granted; the v1 seam anticipates this so P2 is not a
   re-architecture.

## Claim mapping

A wasm-component workload runs in a microVM, so it inherits claims 1–3
(isolation), 8 (signed plan), 10 (default-deny egress), 11 (sealed deps, if it
has any), 13 (secrets), 15 (no interactive sealed access). The new fine-grained
fs/env enforcement (Decision 3) is a *strengthening* within claims 1–2, not a
new numbered claim — promotion to the ADR-002 table can follow the OCI-provenance
precedent once witnesses exist. The AOT-no-JIT-in-guest posture (Decision 4)
strengthens the claim-1/2 seccomp story.

## Decomposition (an ADR + ~3 plans — for `writing-plans`)

| Piece | What | Reuses |
|---|---|---|
| **A1** | Capability-policy extension: the resolved policy + `mvm-core::policy::projection` carry fs/env capabilities (not just network); `clamp` from Plan 188 applies; the WASI-config generator (deny-by-default, clamp invariant, negative tests). **Foundation — A2/A3 consume it.** | Plan 188 projection/clamp |
| **A2** | `.wasm` artifact admission: `mvmctl run ./x.wasm` → SHA-256 → signed `ExecutionPlan` with the `.wasm` as the content-addressed artifact → provenance (digest + wasmtime version) in the audit chain. | claim 8/9 admission |
| **A3** | Guest runner + Nix bake + AOT: bake wasmtime into the rootfs for `Wasm` workloads; AOT-compile the `.wasm`→`.cwasm` in the builder; generate the `wasmtime run` invocation + WASI config (preopens/env, as data) from A1; tighten guest seccomp to forbid `PROT_EXEC`; run under the existing invoke contract. | the `Wasm` runner scaffold + the factory bake (Plan 191-style) |

**Sequencing:** A1 (foundation) → A2 + A3 (largely parallel; both consume A1).
v1 "done": `mvmctl run ./hello.wasm` boots a microVM, the AOT-compiled
component runs on wasmtime under clamped fs/env grants with a no-`PROT_EXEC`
guest seccomp, output returns, provenance recorded.

## Alternatives considered

- **JIT-in-guest** (compile at load): rejected for prod — forces the guest
  seccomp to permit executable-memory syscalls, loosening the workload-bearing
  tier. Kept for the preview tier where a sandbox already contains it.
- **Linking the `wasmtime` crate into the host** (e.g. a host-side WASI runner):
  rejected — grows the host TCB for no benefit; the component runs in the guest,
  so wasmtime belongs in the guest (subprocess), like python/node.
- **A new parallel admission path for `.wasm`**: rejected — reuse claim-8/9;
  a `.wasm` is just another content-addressed artifact.
- **WASI P2 / Component Model for v1**: deferred — the scaffold is P1 and P1
  modules cover the v1 target; Decision 1's seam keeps P2 a later swap.

## Consequences

- A `.wasm` becomes a first-class, claim-bearing workload with no new host
  dependency and no new host trust surface; the new untrusted-input surface is
  in-guest, behind the microVM, and (for prod) is precompiled in the sandboxed
  builder rather than JIT'd in the live workload.
- The capability model graduates from network-only to network+fs/env, all
  through the one Plan 188 projection/clamp seam.
- New code/gates owned by plans A1–A3: the fs/env projection + WASI-config
  generator (with the clamp/deny-by-default witnesses), the `.wasm` admission,
  the AOT build step + the tightened guest seccomp, the Nix wasmtime bake.
- Out of scope: the preview/relay tier (ADR-080 P8), SDK-compile-to-wasm
  (Decision 2 deferred), and WASI P2 (Decision 1 seam).
