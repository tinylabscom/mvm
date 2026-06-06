# Design — Plan 159 first slice: the Plan-152-independent VZ DX layer

> **Status (2026-06-05):** Brainstormed, approved for first steps. This is
> the scoping/design artifact for the first independent increment of
> `specs/plans/159-vz-inspired-macos-dx.md`. The numbered implementation
> plan is produced from this via writing-plans.
>
> **Naming:** the inspiration project is referred to obliquely ("the DX
> reference" / "the multi-crate Rust-native VZ runtime") per repo naming
> policy. Oblique-reference key: auto-memory
> `reference_objc2_vz_external_references`.

## Goal

Ship every Plan 159 DX feature that needs **nothing from the Rust-`objc2`
VZ supervisor (Plan 152)** as one coherent, phased push. This is the
"everything compatible with our model that we can do *now*" slice. The
headline vz differentiators — the warm "instant" path (WS-1) and
checkpoint/restore/fork (WS-2) — are deliberately **out** because they
require the Plan 152 supervisor primitives; they remain the critical path
to full parity and are sequenced after 152.

## Scope

In:

- **WS-3** — user-facing `mvmctl sign` + a doctor signing-status line.
- **WS-5 B** — resume ergonomics (`-c/--continue`, `-r/--resume <id>`,
  `--ephemeral`), mapped onto the existing `session` construct.
- **WS-5 C** — a shared `--json` output helper + coverage on the
  highest-value read commands.
- **WS-4** — acquisition DX: honest one-time-cost framing, local-first
  resolution, resumable downloads (in-binary parts core; `curl|sh`
  installer is a lighter follow-on).

Deliberately deferred (and **not** because they need Plan 152):

- **WS-5 D — verb-vocabulary renames.** A mechanical, breaking rename
  pass. Folding it in would bury the feature diff under churn; it gets its
  own reviewable commit.
- **WS-5 E — streamed `exec`.** Crosses into the **guest vsock protocol**
  (changes `GuestResponse::ExecResult` from buffered to streamed in
  mvm-guest). Different subsystem, different risk/testing surface; its own
  slice.

Net property of this slice: **host-side / CLI only — no guest-protocol
change, no mass renames.** Keeps it to a single (phased) implementation
plan.

## Invariants (do not regress)

- Claims 1–14 intact; no SSH into guests; no in-guest agent injection.
- Hermetic-Nix (ADR-046) untouched — WS-4 only changes *how published
  prebuilts are fetched*, never reintroduces host-Nix or prebuilt
  dependence on the contributor path.
- The claim-6 SHA-256 gate and `MVM_SKIP_HASH_VERIFY` posture are never
  weakened by the resumable-download work.
- Single-tenant-per-VM (claims 3/8): one-shot `run`/`up` VMs stay
  ephemeral and are **not** made resumable; resume applies only to the
  `session` construct that is already designed to persist.

## WS-3 — `mvmctl sign` + doctor signing status

**Current state.** `sign_binary()` + the `ENTITLEMENTS_PLIST` constant
(the `com.apple.security.virtualization` + `com.apple.security.hypervisor`
pair) are private in
`crates/mvm-backend/src/providers/apple_container/macos.rs:390-416`.
`ensure_signed()` (same file, `:345-383`) auto-signs and re-execs with
`MVM_SIGNED=1`; it is called only from
`apple_container/macos.rs:529` (`start_vm`) and
`crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs:68`. Doctor already
probes the supervisor's entitlement via `vz_entitlement_probe()`
(`crates/mvm-cli/src/doctor.rs:901-916`) and renders checks by category
(`doctor.rs:348-376`, security category at `:53-71`).

**Build.**

- Expose a public entry in `mvm-backend`:
  `sign_binaries(targets: &[PathBuf]) -> Vec<SignReport>`, reusing
  `sign_binary()` + the existing temp-plist mechanism.
  `SignReport { path, applied: bool, entitlements_present: bool }`.
- New `mvmctl sign` command in the `env` command module, beside `doctor`.
  Resolves the three relevant binaries via the existing resolvers —
  `std::env::current_exe()` for `mvmctl`, the `mvm-vz-supervisor` chain at
  `crates/mvm-backend/src/vz.rs:1075-1134`, and the
  `mvm-libkrun-supervisor` chain at
  `crates/mvm-backend/src/libkrun.rs:561-601`. Signs each, then
  **verifies** by re-running the entitlement probe, and prints the signed
  paths + per-binary verdict.
- macOS-only. On Linux it prints a clear "not applicable on this platform"
  and exits 0.
- Doctor: add a `signing` check in the **security** category that probes
  `mvmctl`'s own entitlements (mirroring `vz_entitlement_probe`). When an
  entitlement is missing, the `info` text reads `run 'mvmctl sign'`.
  Auto-sign stays on the normal launch path; `sign` is the explicit
  repair.

## WS-5 B — resume ergonomics (sessions only)

**Current state.** `session start/attach/exec/run-code/console/kill/ls/
info/set-timeout/reap` exist
(`crates/mvm-cli/src/commands/vm/session.rs:41-202`). Session metadata
lives at `$XDG_RUNTIME_DIR/mvm/sessions/<id>.json` with `created_at`,
`last_invoke_at`, `state` (Running/Killed/Reaped). There is **no**
most-recent pointer and no `-c/-r/--ephemeral`.

**Build.**

- "Most recent" is **derived, not persisted**: scan session files for the
  newest `last_invoke_at` (fall back to `created_at`) among `Running`
  sessions. Nothing new to keep in sync. `attach` already bumps
  `last_invoke_at`.
- `session attach` gains:
  - `-c/--continue` — no id → re-attach the most-recent `Running` session.
  - `-r/--resume <id>` — explicit id (the existing positional id stays the
    canonical form; this is the vz-parity verb surface mapped onto it).
- `session start --ephemeral` — mark the session auto-reap-on-detach/exit,
  riding the existing `reap` machinery.
- One-shot `run`/`up` remain ephemeral-by-design and are **not**
  resumable; documented in `--help`.

## WS-5 C — shared `--json` helper + coverage

**Current state.** ~11 commands hand-roll
`serde_json::to_string_pretty(...)` inline (e.g. `image ls/inspect`,
`ls`/`ps`, `session ls/info`, `sandbox gc`, `run --json`, `artifact
inspect`). No shared path; coverage is uneven.

**Build.**

- One small helper, `crates/mvm-cli/src/json_out.rs`:
  `emit_json<T: Serialize>(value: &T) -> Result<()>` (pretty + trailing
  newline + consistent stdout discipline). Deliberately minimal — **no**
  schema/envelope framework (YAGNI). Migrate the existing inline call
  sites to it so there is exactly one JSON path.
- Add `--json` to the committed first set of high-value read commands
  currently missing it: **`doctor`** (machine-readable diagnostics — the
  biggest win), `network list`, `network inspect`, `snapshot ls`,
  `cache info`, and the `audit` list view. (`deps inspect` already emits
  JSON — confirm it routes through the helper.)
- Remaining commands are an explicit follow-up `--json` audit, not part of
  this slice.

## WS-4 — acquisition DX (in-binary core; installer follow-on)

**Current state.** `download_dev_image`
(`crates/mvm-cli/src/commands/env/apple_container.rs:1193`, with
`download_dev_image_inner` at `:1212`) streams the artifact through
SHA-256 and rejects+deletes on mismatch (claim 6), but is not resumable
and does not frame the one-time cost. A sibling fetch for the dev-shell
image mirrors it (`apple_container.rs:3572`), and an operator-provided
local-image path exists (`:1564`) — the local-first chain unifies these.

**Build.**

- **Honest one-time-cost framing:** before an unavoidable first-run
  download, print the payoff inline ("one-time — subsequent runs restore
  in seconds").
- **Local-first resolution chain:** flag → installed path → cache → CDN.
- **Resumable downloads:** HTTP Range + a `download-state.json` sidecar
  recording bytes-fetched + expected sha256. Resume appends; the assembled
  artifact **still streams through the existing SHA-256 gate before
  acceptance** — mismatch deletes, exactly as today. The claim-6 gate and
  `MVM_SKIP_HASH_VERIFY` posture are untouched.
- **Installer `curl|sh`:** lighter follow-on (touches the release
  pipeline) — captured, not a blocker for this slice.

## Testing & verification

Per-feature, on the local Vz dev host (isolate with
`MVM_CACHE_DIR`/`MVM_DATA_DIR`; see auto-memory
`project_dev_host_runs_builder_via_vz`):

- **WS-3:** on a fresh source checkout, `mvmctl sign` makes a
  previously-unsigned binary boot a VZ VM, and `doctor` flips the signing
  check to OK. (mvm-backend test bins can be codesign-SIGKILL'd on macOS —
  lean on Linux CI for everything that isn't the macOS-only sign path; see
  `reference_mvm_backend_test_binary_macos_codesign_sigkill`.)
- **WS-5 B:** unit test for most-recent selection; `tests/cli.rs` parsing
  tests for `--continue`/`--resume`/`--ephemeral`; `--ephemeral` auto-reap
  behavior.
- **WS-5 C:** `emit_json` unit test; per-command `--json` shape tests.
- **WS-4:** interrupt + resume a dev-image download → byte-correct result
  still passes the SHA-256 gate; a tampered partial is rejected + deleted.
- **Gates:** `cargo nextest run --workspace`,
  `cargo test --workspace --doc`,
  `rustup run nightly cargo fmt --all -- --check` (CI uses nightly
  rustfmt — see `reference_ci_lint_uses_nightly_rustfmt`),
  `cargo clippy --workspace -- -D warnings`. Never run `core_demo_e2e`
  unbounded (`feedback_never_run_core_demo_e2e_unbounded`).

## Phasing (one plan, four phases)

1. **WS-3** — `mvmctl sign` + doctor (quick, self-contained).
2. **WS-5 C** — json helper + coverage.
3. **WS-5 B** — resume ergonomics.
4. **WS-4** — acquisition DX (split the `curl|sh` installer off if it runs
   heavy).

Work happens in a fresh git worktree off `main`
(`feedback_always_use_git_worktrees`); commits carry no Claude co-author
trailer (`feedback_no_claude_coauthor_trailer`).

## Parity ledger (where this slice sits vs. full vz parity)

This slice closes 2.5 rows of the Plan 159 parity checklist (`self-sign`,
session-continuity flags, the `--json` half of machine-readable output).
The rest of the path to parity:

- **Captured in Plan 159, deferred:** verb parity (WS-5 D), streamed exec
  (WS-5 E), resumable-download `curl|sh` installer (WS-4 follow-on).
- **Gated on Plan 152 (the headline differentiators):** warm "instant"
  path + background logs (WS-1), checkpoint/restore/fork/diff/`--tag`
  (WS-2). **Full parity is not reachable without Plan 152.**
- **Decision-gated (may be deliberately declined to preserve invariants):**
  macOS guests (ADR-001), project `init`/config (ADR-046), OCI/Compose
  `stack` (mvmd's domain). Parity target = "everything compatible with our
  security + hermetic-Nix model," explicitly declining these three.
- **Unowned — one true gap:** signed patch / binary-delta image
  distribution; needs a home decision (overlaps `mvm-oci` + Plans
  155/156) before the parity checklist can read complete.

## References

- `specs/plans/159-vz-inspired-macos-dx.md` — parent plan (WS map +
  parity checklist).
- `specs/plans/163-vz-support-execution-roadmap.md` — sequencing; this
  slice is the 152-independent subset of S5.
- `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md` — the
  supervisor the gated features depend on.
- `crates/mvm-backend/src/providers/apple_container/macos.rs` — sign
  harness (WS-3).
- `crates/mvm-cli/src/doctor.rs` — doctor report structure (WS-3).
- `crates/mvm-cli/src/commands/vm/session.rs` — session construct (WS-5 B).
- `crates/mvm-cli/src/commands/` + `crates/mvm-cli/src/exec.rs` — CLI
  surface (WS-5 C).
</content>
