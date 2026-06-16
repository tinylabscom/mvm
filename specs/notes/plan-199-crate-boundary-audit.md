# Plan 199 Workstream C — crate-boundary audit

**Date:** 2026-06-16 · **Owner:** mvm · Companion to
[`plans/199-host-runtime-packaging-and-crate-boundaries.md`](../plans/199-host-runtime-packaging-and-crate-boundaries.md)

## Method

Workspace inventory from `cargo metadata --no-deps`; default-binary closure from
`cargo tree -p mvmctl -e no-dev` (the build a normal user runs — no dev-deps, no
optional features). The plan's stated metric is **default binary closure, not
crate count**, so each decision below asks "does this boundary cost the default
binary anything, and does merging preserve an isolation boundary?" — never "is
the crate small?".

## Numbers

- Workspace packages: **17 library/bin crates** + root `mvmctl` + `xtask`.
- Default `mvmctl` closure: **328 crates** (third-party-dominated).
- Workspace crates **in** the default closure (13): `libkrun-sys`, `mvm`,
  `mvm-backend`, `mvm-build`, `mvm-cli`, `mvm-core`, `mvm-guest`, `mvm-hostd`,
  `mvm-mcp`, `mvm-network`, `mvm-oci`, `mvm-sdk`, `mvm-storage`.
- Workspace crates **outside** the default closure — separate targets, baked or
  optional (4): `mvm-guest-helpers` (in-guest bins baked into the rootfs),
  `mvm-vm-host` (per-VM host bins, cfg-gated), `mvm-verify` (wasm-clean, zero
  `mvm-*` deps), `mvm-sdk-macros` (orphaned placeholder — see below).

**Headline:** merging any two workspace crates removes **0** crates from the 328
closure (closure size is set by third-party deps, not by how mvm's own code is
partitioned). Crate-count is therefore the wrong lever for binary size; the only
levers that move the 328 are (a) dropping third-party deps — Plan 126's job — and
(b) feature-gating optional code out of the default build. The boundaries that
follow are kept for **isolation/ownership**, which the non-goals require us to
preserve.

## Per-crate decisions

### Tiny crates the plan named explicitly

| Crate | LOC | In closure | Decision | Rationale |
|---|---|---|---|---|
| `mvm-sdk-macros` | 11 | no | **Remove** (until macro bodies ship) | Orphaned placeholder: `grep` shows **zero** dependents — not even `mvm-sdk` references it. An empty proc-macro crate with no bodies is YAGNI; deleting it is a pure subtraction across no boundary. Re-add when `#[mvm::function]` et al. actually have bodies. |
| `mvm-mcp` | 1384 | yes | **Keep crate; gate later** | Clean optional surface (wire types + stdio JSON-RPC). Its direct deps (`anyhow`/`serde`/`serde_json`/`tracing`/`tracing-subscriber`) are **already** in the core closure, so it adds **0** new closure crates — gating it is a *code-size/compile* win, not a dependency win. Recommend a future `mcp` cargo feature on `mvm-cli` (default-on for parity, off for a slim build); **do not merge** into the CLI (keeps the JSON-RPC surface testable in isolation). Low priority. |
| `mvm-verify` | 436 | no | **Keep separate** | Wasm-clean audit-log verifier, zero `mvm-*` deps by design (ADR-069). The whole point is a minimal dependency surface for the browser verifier; merging would contaminate it. |
| `mvm-guest-helpers` | 1559 | no | **Keep grouped** | In-guest `[[bin]]`s baked into the rootfs by mkGuest — they run in the guest, never in the host binary. Already consolidated from two crates (plan 121 D3); no smaller split is proven useful. |

### Other tiny in-closure crates (boundary-justified)

| Crate | LOC | Decision | Boundary it enforces |
|---|---|---|---|
| `mvm-network` | 370 | **Keep** | `NetworkProvider` trait seam (Plan 123 Phase A). Impl lives in `mvm-backend`, mesh in mvmd — the trait is the mvm↔mvmd ownership split, not dead weight. |
| `mvm-storage` | 2328 | **Keep** | `VolumeBackend` trait + `LocalBackend`; `ObjectStore`/`Encrypted` impls are mvmd's (plan 45 §D5). Same mvm↔mvmd split. |
| `mvm-vm-host` | 4088 | **Keep** | Per-VM host `[[bin]]`s (one process per guest) — the process-moat boundary (ADR-066 §3). cfg-gated, top of the dep tree, nothing links it as a lib. |
| `mvm-sdk-macros` | — | (see above) | — |

### Large crates

`mvm-cli` (61k), `mvm-hostd` (44k), `mvm-core` (42k), `mvm-build` (36k),
`mvm-backend` (24k), `mvm-guest` (22k), `mvm-sdk` (16k), `mvm` (11k),
`libkrun-sys` (4k), `mvm-oci` (5k) — all carry a clear single ownership and a
real isolation reason (`mvm-core` = runtime-free foundation; `mvm-hostd` = the
trusted-host process roles; `mvm-guest` = the in-guest TCB; `libkrun-sys` = the
one FFI boundary). None is a merge or split candidate under the non-goals.

## Actions surfaced (each its own tested follow-up commit)

1. **Delete `mvm-sdk-macros`** — remove the crate dir + the `[workspace].members`
   and `[workspace.dependencies]` entries; `cargo check --workspace` must stay
   green (zero dependents make this safe). The one unambiguous crate-count win.
2. **Feature-gate `mvm-mcp`** behind an `mcp` feature on `mvm-cli` (default-on) —
   code-size/compile win only; no closure change. Lower priority; do after (1).

Everything else: **keep as-is.** The workspace is right-sized for the security
and ownership boundaries the plan's non-goals require; there is no
cosmetic-count merge to make.

## What this does NOT change

The 328-crate default closure is unaffected by any of the above except the
(modest) code-size from gating `mvm-mcp`. Real closure reduction is Plan 126
(dependency reduction), tracked separately. This audit's job was to prove that
crate *boundaries* are isolation decisions, not size decisions — and they are.
