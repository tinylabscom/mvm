# Plan 98 — `VzBuilderVm` finishing slices (auto-detect, CLI flag, doctor, persistent, CI, docs)

> **Status (2026-05-26):** Phase A/B/C of the original Plan 98 scope
> shipped **as Plan 97 Phase C** while this plan was being brainstormed,
> via PRs #434–#442 + #445. The seam (`VmBackendForBuilder`), shared
> orchestration (`builder_vm_runtime`), `LibkrunBuilderVm` refactor,
> `VzBuilderVm` driver, `builder_backend_select.rs` env-var dispatch,
> and `is_macos_26_or_later()` predicate are all on `origin/main`.
>
> Plan 98 now scopes **only the finishing slices** the parallel sessions
> did not pick up: auto-detect (macOS 26+ Apple Silicon → Vz default),
> `--builder` CLI flag, `mvmctl doctor` builder-backend reporting,
> **persistent variant for Vz that mirrors libkrun's `mvmctl dev`**,
> Install E2E verification, CI lane updates, and docs.
>
> Plan 99 (Stage 0 audit/cache contract for Vz builder dirs, #448) is
> the foundation Phase 2 builds on — cross-reference it, do not
> duplicate its directory contract.
>
> Pick-up command for fresh sessions: read this file top to bottom,
> then jump to the next unchecked item.

## Selection policy (locked)

- Default: **auto-detect** by host platform. macOS 26+ Apple Silicon → Vz; everywhere else (macOS 13-25, Linux) → libkrun.
- Override priority: `--builder <libkrun|vz>` CLI flag > `MVM_BUILDER_BACKEND` env var > auto-detect.
- Vz on macOS 13-25 is **opt-in only** via the override path.
- Auto-detect must **refuse Vz when the entitlement / MDM probe fails**
  (PR #445's `vz_check` semantics) and fall through to libkrun, rather
  than fail mid-build.

## Locked decisions (planning round 2026-05-26)

1. **Rebase off `origin/main` before any commit** in the worktree.
2. **No macos-26 self-hosted CI runner required.** Phase 3 ships the
   floor that runs on `macos-latest` + Linux. Real `uv pip install`
   smoke under Vz is a named deferred follow-up (§3.6), not blocking.
3. **Extend ADR-046** (option a) rather than open a new ADR. Builder-VM
   backend selection lives in one place.
4. **Phase 1 PR opens as ready (non-draft) immediately.** Phase 3
   (Vz CI lane) lands separately; main + libkrun lanes gate Phase 1.
5. **Persistent drivers stay parallel** (`VzPersistentBuilderVm`
   alongside `LibkrunPersistentBuilderVm`), mirroring the one-shot
   driver pattern from Plan 97 Phase C.

## Shipped (Phase A/B/C — by parallel sessions on origin/main)

- [x] `is_macos_26_or_later()` in `crates/mvm-core/src/platform/platform.rs:189`
- [x] `crates/mvm-build/src/builder_backend_select.rs` — `BuilderBackendChoice` enum, `MVM_BUILDER_BACKEND_ENV`, `resolve_choice()` (env-var only — no auto-detect yet)
- [x] `resolve_builder_backend()` factory returning `Box<dyn BuilderVm>`
- [x] Selection unit tests (10+ cases)
- [x] `VmBackendForBuilder` seam in `crates/mvm-build/src/builder_vm.rs`
- [x] `crates/mvm-build/src/builder_vm_runtime.rs` — shared `stage_job_dir`, `JobResult`, `finalize_flake_job`, `finalize_install_job`, `NixStoreImageLock`, `builder_vm_timeout`, stderr-tail formatters
- [x] `crates/mvm-build/src/libkrun_builder.rs` — refactored against the seam, both `LibkrunBuilderVm` driver + `LibkrunBuilderBackend` impl
- [x] `crates/mvm-build/src/vz_builder.rs` — `VzBuilderVm` driver + `VzBuilderBackend` impl (Plan 97 Phase C complete)
- [x] `mvm-vz`: `VirtioFsShare.read_only` for builder mode (PR #440)
- [x] Vz Phase E control socket: pause/resume/balloon/snapshot SAVE (PR #430)
- [x] Doctor: `vz_check` entitlement + MDM-policy sub-probes for the **runtime** path (PR #445)
- [x] Stage 0 audit/cache contract for Vz builder dirs (Plan 99 PR-1, #448)

## Progress checklist — remaining slices

### Phase 1 — Selection user-surface (auto-detect + CLI flag + doctor)

User-facing knobs that the env-var-only shipping skipped. One PR.

- [x] **1.1** `auto_detect_default_for(is_macos_26_apple_silicon: bool)` + `auto_detect_default()` in `builder_backend_select.rs`. Pure helper for testability.
- [x] **1.2** `resolve_env_override()` returns `Option<BuilderBackendChoice>` (separates "unset/empty/unknown" from "explicit override"). Unknown values log a warning and fall through.
- [x] **1.3** `resolve_choice_with_override(flag: Option<BuilderBackendChoice>)` applies CLI flag > env > auto-detect priority. `resolve_choice()` becomes `resolve_choice_with_override(None)`.
- [x] **1.4** Added `--builder <libkrun|vz>` global flag to the Cli struct at `crates/mvm-cli/src/commands/mod.rs`. The flag is folded into `MVM_BUILDER_BACKEND` at startup so the existing env-var dispatch in `mvm_build::builder_backend_select` honours it transparently — no per-call-site plumbing needed.
- [x] **1.5** `mvmctl doctor` (`crates/mvm-cli/src/doctor.rs`) reports the resolved backend, override source (flag/env if set), and per-VMM probe results via `builder_backend_check()`. Reuses existing `vz_check` + `has_libkrun()` predicates. Format: `<backend> — <source> — <availability>`. Stub variant for `not(feature = "builder-vm")` builds.
- [x] **1.6** Selection unit tests extended: auto-detect path, override precedence (flag > env > auto), edge cases (empty env, unknown env).
- [ ] **1.7** `cargo test --workspace` + `just lint` green.
- [ ] **1.8** PR opened (non-draft per locked decision #4), review requested.

### Phase 1 — gap-fix slice (this PR, §0.x — caught in 2026-05-26 planning round)

Pre-ship gap review surfaced four items missing from the original
§1.x scope. All four land in the same PR as Phase 1.

- [x] **0.1** Extend §2.C1 grace guard to cover the `MVM_BUILDER_BACKEND` env-var path. The original predicate at `crates/mvm-cli/src/commands/env/dev.rs::run` checked `cli.builder.as_deref() == Some("vz")` only, so `MVM_BUILDER_BACKEND=vz mvmctl dev up` bypassed the guard and silently routed through `current_backend()` (libkrun) — a real bug. New `dev_action_blocked_by_vz_guard()` pure predicate covers both override paths, case-insensitive + whitespace-stripped to match `resolve_env_override`'s semantics. 16 hermetic unit tests in `dev.rs` cover the flag path, env path, case/whitespace variants, and unaffected verbs (`down`/`status`/`cache`).
- [x] **0.2** `--builder` help-text + value-parser tests in `crates/mvm-cli/src/commands/tests.rs`. Asserts the flag surfaces in `mvmctl --help` output via `cli_command().render_help()`, accepts `libkrun`/`vz`, rejects unknown values via clap's `value_parser = [...]`, and is `None` by default. Subsumes §1.6a (doctor snapshot rolls into §0.3).
- [x] **0.3** Doctor `builder backend` line unit-tested on Linux. New tests in `doctor.rs::tests` assert the format `<backend> — <source> — <availability>` for both the env-unset (auto-detected → libkrun) and env-override (`MVM_BUILDER_BACKEND=vz` → vz NOT available on Linux) cases. Stub-path test covers `cfg(not(feature = "builder-vm"))`. Tests cfg-gated to `target_os = "linux"` because `auto_detect_default()` queries the real host; macOS hosts get coverage via the existing `vz_check_macos_reports_*` tests.
- [x] **0.4** CI apple-lane builds with `--features builder-vm`. Verified `mvm-cli/Cargo.toml` sets `default = ["builder-vm"]` (Plan 72 W5.B cutover), so every `cargo test` / `cargo build` invocation in the workflow exercises the new selection + doctor code. No workflow patch needed.
- [x] **0.5** Source-checkout dev-image builder fallback: when auto-detect selects `vz` and there is no explicit `--builder` / `MVM_BUILDER_BACKEND` override, `ensure_dev_image` now retries the build with `libkrun` after a Vz builder bring-up failure instead of aborting `mvmctl dev up`. Explicit overrides still fail loudly. Unit coverage pins the backend attempt order; CLI/install docs now mention the fallback.

### Phase 1 — deferred follow-ups (not blocking the Phase 1 PR)

(§1.6a now subsumed into §0.3 — no remaining deferred items.)

### Phase 2 — Vz persistent parity + Install E2E + coexistence

The user-requested parity: `mvmctl dev up/down/shell/status` must work
under Vz exactly as it does under libkrun.
`crates/mvm-build/src/persistent_builder.rs` is backend-agnostic
(supervisor owns a `UnixStream` to the running VM; driver owns the
VM lifecycle). So the seam is "construct the right concrete driver";
everything downstream of socket-connect is shared.

- [ ] **2.1** Audit `crates/mvm-build/src/persistent_builder.rs` and `LibkrunPersistentBuilderVm` in `libkrun_builder.rs`. Snapshot the libkrun driver's API surface (start, dispatch socket path, PID file path, console log path, Drop semantics, audit emit).
- [ ] **2.2** Write `VzPersistentBuilderVm` parallel to `LibkrunPersistentBuilderVm` in `crates/mvm-build/src/vz_builder.rs` (or sibling file if size warrants). Mirrors the libkrun API one-for-one. Wires to the **same** `PersistentBuilderSupervisor`.
- [ ] **2.3** State dir layout (parity + isolation). Per Plan 99 PR-1 (#448), Vz builder state dirs live under `~/.cache/mvm/builder-vm/vms/mvm-builder-vz-<job_id>/` (subdirectory pattern; the orphan reaper at `apple_container.rs:3292` is prefix-agnostic and `VzBuilderVm` already writes `builder.pid`). For the persistent variant, pick a stable name (e.g. `mvm-builder-vz-persistent/` mirroring libkrun's `mvm-builder-vm-persistent/`) and confirm the same files (`dispatch.sock`, `builder.pid`, `console.log`, `audit.jsonl`, `lock`) participate in Stage 0 cleanup without code changes. Add a regression test mirroring Plan 99 PR-1's `reap_picks_up_orphaned_vz_builder_state_dir` for the persistent dir.
- [ ] **2.4** `mvmctl dev shell` console parity. Vz uses `VZVirtioConsoleDevice` rather than libkrun's PTY-over-vsock. Confirm Plan 97 Phase C already exposes a console path; surface it through the same `dev shell` user verb.
- [ ] **2.5** Cross-backend state coexistence. Per §2.3, both backends' persistent state dirs live under the same parent (`~/.cache/mvm/builder-vm/vms/`), distinguished by name prefix (`mvm-builder-vm-persistent/` vs `mvm-builder-vz-persistent/`). The dispatch must:
  - `mvmctl dev down` enumerate the parent dir and stop whichever backend's persistent dir is currently active (matches the running PID).
  - `mvmctl dev status` reports per-backend state (which prefix exists + which PID is alive).
  - `mvmctl dev up` refuses (with a clear error) when the *other* backend's persistent dir has a live PID.
  - Test: `MVM_BUILDER_BACKEND=libkrun mvmctl dev up && MVM_BUILDER_BACKEND=vz mvmctl dev up` exits nonzero with a helpful message naming the running backend + the `dev down` remedy.
- [ ] **2.6** Install job E2E smoke on Vz. `MVM_BUILDER_BACKEND=vz mvmctl up --prod ./examples/python/hello-app-with-deps` produces a sealed volume identical to libkrun's. `mvmctl deps inspect --json` reports it.
- [ ] **2.7** Byte-flip on `cve.json` makes `verify_sealed_volume()` refuse — same as libkrun.
- [ ] **2.8** Doctor: running-persistent-VM indicator. Extend the Phase 1 doctor check to *also* report whether a persistent VM is currently running and which backend started it. Format suggestion: `Builder backend: vz (auto) — libkrun-vm-stopped, vz-vm-running PID 12345 since 2026-05-26T12:34`.
- [ ] **2.9** Regression check. `mvmctl dev` under libkrun unchanged; `cargo test --workspace` + `just lint` green.
- [ ] **2.10** Resource ceilings parity. Confirm Vz persistent uses the same RAM/CPU defaults the one-shot driver picked in Plan 97 Phase C (and that they honour the Plan 72 W5.D RAM cap). Document any divergence in ADR-046.
- [ ] **2.11** Builder VM image flake path. Confirm `find_builder_vm_flake()` is the source for *both* drivers' VM image. No "Vz pulls a prebuilt" backdoor. Add an integration test that boots Vz against the in-repo flake (`nix/images/builder-vm/`) from a source checkout. This is the ADR-046 §"Source-checkout builds never depend on mvm-published artifacts" invariant applied to the second backend.

### Phase 2 — security parity (Claims 1, 5, 7, 8, 9)

The builder VM is the dev tier, *but* its Install arm is the prod-grade
path that produces the sealed deps volumes Claim 9 covers, and every
admission flows through the Claim 8 audit chain. So the security
claims have to hold across both backends, not just libkrun.

- [ ] **2.S1** State dir + dispatch socket permission parity (Claim 1, W1.2 / W1.5). Per §2.3 the Vz persistent state dir lives at `~/.cache/mvm/builder-vm/vms/mvm-builder-vz-persistent/`. Confirm mode `0700` (inherits from `~/.cache/mvm/builder-vm/` parent already enforced by Stage 0); confirm dispatch socket mode `0700`; confirm `audit.jsonl`, `builder.pid`, `console.log` files mode `0600`. Add a test that stats the dir + socket after a Vz persistent `dev up`. Cross-reference Plan 99 PR-1 — reuse, don't duplicate.
- [ ] **2.S2** Cross-backend Install gate byte-equivalence (Claim 9). §2.6's hash equivalence test must compare *contents* of the sealed volume, not only the final sha256: `content/` tree byte-equal, `sbom.cdx.json` byte-equal, `fetch.log` byte-equal, `cve.json` byte-equal across libkrun and Vz on the same Install input. This prevents an attacker who controls one backend from shipping a divergent volume that the other backend's verifier trusts via cache hit.
- [ ] **2.S3** Audit emit chain under Vz (Claim 8). Verify `mvmctl up --prod` under `MVM_BUILDER_BACKEND=vz` emits the same `plan.admitted` / `plan.launched` / `plan.failed` entries to `~/.mvm/audit/<tenant>.jsonl` as the libkrun path. Add a test that runs `mvmctl audit verify` after a Vz Install and asserts the chain is clean.
- [ ] **2.S4** Vz entitlement / MDM probe applies to the builder path. Phase 1's doctor builder-backend line must surface the *same* probe results PR #445 brought for the runtime. Auto-detect must *refuse* Vz when the entitlement is missing on macOS 26+ — fall through to libkrun rather than fail mid-build. Add a test of the auto-detect fallback path (mock the probe).
- [ ] **2.S5** `cargo deny` / `cargo audit` cover `crates/mvm-vz` (Claim 7). Confirm the CI `deny` + `audit` jobs in `ci.yml` exercise the Vz crate; add it explicitly to `deny.toml`'s scope if it's been excluded.
- [ ] **2.S6** Vz host-side control-socket parser surface (Claim 5). PR #430's pause/resume/balloon/snapshot SAVE control socket is host-side untrusted-input surface. Default: add a `cargo-fuzz` target under `crates/mvm-vz/fuzz/` mirroring `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs`. Fallback (document in ADR-046): host-process-local with `0700` parent dir inherits ADR-002 host-trust assumption.
- [ ] **2.S7** Snapshot SAVE secret-leak protection. If Vz persistent uses Phase E's SAVE, the on-disk memory dump can contain build secrets. It must live inside `~/.cache/mvm/builder-vm/vms/mvm-builder-vz-persistent/` (0700 parent inherited from Stage 0), file mode `0600`, get cleaned up by `mvmctl cache prune` and on clean `dev down`. Test: stat the SAVE file after a save, assert mode + path; run `cache prune` and assert removal.

#### New security items (2026-05-26 planning round — Slice 2C)

- [ ] **2.S8** Virtiofs share parity (Claim 1). Vz and libkrun construct `VirtioFsShare` configs independently. If Vz mounts a path libkrun doesn't (or with a different r/w bit), Claim 1 ("no host-fs access from a guest beyond explicit shares") holds per-backend but breaks symmetry. Test: enumerate `VirtioFsShare` from both driver constructors for the same input; assert set equality on `(host_path, guest_path, read_only)` triples.
- [ ] **2.S9** Builder VM kernel/rootfs parity for the Install arm (Claim 9). libkrun extracts its kernel from `libkrunfw`'s `.rodata`; Vz boots whatever its `VZLinuxBootLoader` is pointed at. If the kernels diverge, binaries produced from the same Nix derivation could too (libc/kernel-header drift), breaking §2.S2 byte-equivalence at the volume level. Per `feedback_dev_vm_vs_prod_security_tiers.md` the dev tier doesn't need dm-verity, but the Install arm IS the prod-grade path. Test: boot both backends with the same Install input; capture `/proc/version` + `uname -r` + kernel sha256 inside the guest; assert equality. If divergence is unavoidable, document in ADR-046 §"Why Install-arm kernels differ" with a justification paragraph for why §2.S2 still holds at the volume byte level.
- [ ] **2.S10** Sealed-volume `meta.json` backend-neutrality (Claim 9). `meta.json` is hash-chained per CLAUDE.md. If the hash input embeds the backend name (e.g. `{"backend": "libkrun", ...}`), identical content yields different hashes per backend — supervisor refuses cross-backend cache hits AND an attacker could forge different-backend signatures on identical content. Test: (1) inspect the meta.json schema in `mvm_sdk::compile::deps_audit`; (2) decode meta.json from a libkrun-sealed and a Vz-sealed Install on the same input; (3) assert byte equality. If the backend name leaks in, normalise it out before hashing.
- [ ] **2.S11** `MVM_BUILDER_BACKEND` env-var honor after §2.C1 guard removal (security-adjacent correctness, **Slice 2B**). When Slice 2B removes the §2.C1 grace guard, `commands/env/dev.rs` could regress to silently routing through `current_backend()` for `MVM_BUILDER_BACKEND=vz` without the flag. Test: after §2.5 dispatch lands and §2.C1 guard removed, integration test asserting `MVM_BUILDER_BACKEND=vz mvmctl dev up` actually boots the Vz persistent driver (not libkrun) and `dev status` reports `vz`. Mirrors §0.1's test on the opposite side.
- [ ] **2.S13** Console-stream confidentiality. `mvmctl dev shell` opens a PTY into the builder VM where build-time env vars (`.env` contents, API keys for fetches, pip-index credentials) and source scroll across. The console log file is mode `0600` per §2.S1, but the LIVE PTY stream flows through the supervisor process. Test: (1) start a `dev shell` via the Vz driver; (2) `lsof -p <supervisor_pid>` and assert no fd is open against a path outside `~/.cache/mvm/builder-vm/vms/mvm-builder-vz-persistent/` AND mode > `0600`; (3) `mvmctl dev down` and assert `console.log` is mode `0600` (already in §2.S1).

### Phase 2 — correctness parity

- [ ] **2.C1** Phase 1 grace under partial implementation. With `--builder vz` available but Vz persistent not yet landed, `mvmctl --builder vz dev up` must error clearly: "Vz persistent mode arrives in Phase 2 (Plan 98); use `--builder libkrun` for `dev up`." Add this to Phase 1's CLI plumbing (`commands/build/persistent_builder.rs`) as a guard, then remove the guard in Phase 2 once the driver lands.
- [ ] **2.C2** `mvmctl cache prune` honours the Vz lock. Per Plan 99 PR-1, the orphan reaper at `apple_container.rs:3292` is already prefix-agnostic and Stage 0 cleanup picks up `mvm-builder-vz-*` dirs automatically. Verify the persistent dir (`mvm-builder-vz-persistent/`) participates too — extend the existing `reap_picks_up_orphaned_vz_builder_state_dir` test or add a persistent variant.
- [ ] **2.C3** Backend in structured logs + error messages. `tracing` spans in the build path carry a `backend=vz|libkrun` field. Error messages that mention state dirs reference the correct path. One grep test in CI catches the regression.

### Phase 3 — CI lane updates (floor only, no macos-26 runner)

Per locked decision #2, ship the floor that runs on `macos-latest` + Linux.

- [ ] **3.1** Selection unit tests run everywhere. The 10+ tests in `builder_backend_select.rs` are hermetic; confirm they're exercised in the existing Ubuntu `test` lane and the `apple` lane.
- [ ] **3.2** `macos-latest` Vz construction smoke. Extend (or add a step to) the existing `apple` lane in `.github/workflows/ci.yml`:
  - `cargo test -p mvm-build vz_builder` — runs the Vz driver's unit tests on the macos-latest runner. Construction is pure; first I/O happens in `run_build`.
  - `MVM_BUILDER_BACKEND=vz cargo test -p mvm-build builder_backend_select` — exercises the env-var path on macOS.
- [ ] **3.3** `app-deps-audit` lane stays unchanged. Backend-agnostic verification path; cross-backend parity covered at the unit-test level by §2.S2.
- [ ] **3.4** Linux `test` lane assertion: `auto_detect_default()` picks `Libkrun` on Linux. Already covered by `auto_detect_default_for_everything_else_picks_libkrun`; just confirm it runs.
- [ ] **3.5** Architecture-invariants workflow re-check. Locate via `gh workflow list`; confirm no new `server-binding` patterns introduced by Phase 1/2.

### Phase 3 — deferred follow-ups

- [ ] **3.6** Real `uv pip install` + `pip-audit` round-trip under Vz on macos-26 self-hosted runner — gated on Plan 72 W4/W5 cutover; ADR-047 already names this deferred for libkrun too.

### Phase 4 — Docs

- [ ] **4.1** `CLAUDE.md`:
  - Extend "Host dependencies" so macOS 26+ users know the libkrun Homebrew trio is optional when Vz is the default.
  - Add "Builder backend selection" subsection under Architecture / Key Design Decisions documenting auto-detect, env, flag, priority order.
  - Mention the state-dir layout: both backends live under `~/.cache/mvm/builder-vm/vms/`, distinguished by name prefix (`mvm-builder-vm-*` for libkrun, `mvm-builder-vz-*` for Vz) — the Stage 0 reaper handles both. Document the coexistence rules from §2.5.
- [ ] **4.2** Extend `specs/adrs/046-builder-vm-via-libkrun.md` with a "Vz as a second builder backend" subsection under Decision **(Slice 2C — lands with the security tests so ADR text and evidence merge in one review)**:
  - Selection policy (auto-detect rule, override priority).
  - Parallel-driver choice (not generic).
  - State-dir isolation + coexistence behaviour.
  - Resource ceilings under Vz (any divergence from libkrun).
  - Cross-reference Plan 99 for Stage 0 audit/cache contract.
  - **Security claim parity** — explicit statement that Claims 1, 5, 7, 8, 9 hold under Vz with the same evidence: state-dir mode `0700` (§2.S1), virtiofs share parity (§2.S8), audit chain emission (§2.S3), `cargo deny`/`cargo audit` coverage (§2.S5), cross-backend Install volume byte-equivalence including kernel parity (§2.S2 + §2.S9), `meta.json` backend-neutrality (§2.S10), control-socket fuzz or host-trust justification (§2.S6), snapshot-SAVE secret protection (§2.S7), and console-stream confidentiality (§2.S13). Cross-reference ADR-002 for the threat model that Vz inherits unchanged.
  - Discipline: per `feedback_adr_out_of_scope_discipline.md` ADR-046's "Security claim parity" subsection lists ONLY items in the same threat model as the parent claim. Adjacent surfaces (Sprint 56 Claim 10, networking observability) belong in their own ADRs, not here.
- [ ] **4.2a** Update `specs/adrs/002-microvm-security-posture.md` (Slice 2C) — no claim change. Add per-claim sub-note under Claims 1, 5, 7, 8, 9: *"evidence applies to both libkrun and Vz builder paths — see ADR-046 §'Vz as a second builder backend' for backend-specific artifacts."* Otherwise the claim table reads libkrun-only.
- [ ] **4.2b** Update `specs/adrs/047-app-deps-audit-pipeline.md` (Slice 2C) — add a "Backend symmetry" sub-paragraph to the Claim 9 evidence section citing §2.S2 (volume content byte-equivalence) and §2.S10 (`meta.json` hash-chain backend-neutrality). One short paragraph; proof lives in the tests.
- [ ] **4.2c** Cross-references (Phase 4 docs slice — no scope change to the target ADRs):
  - `specs/adrs/056-vz-backend.md` — add "Persistent builder variant" pointer paragraph to Plan 98 Slice 2A's `VzPersistentBuilderVm` (two sentences max; full design in ADR-046).
  - `specs/adrs/055-passt-virtio-net.md` — one sentence on whether Vz networking diverges from libkrun's `krun_add_net_unixgram` path. If yes, name the attachment type and link to Plan 97 Phase A / Plan 98.
  - `specs/adrs/041-signed-audited-execution-plans.md` — one-line backend-symmetry note to Claim 8 evidence citing §2.S3.
  - `specs/adrs/057-symmetric-builder-vm.md` (Sprint 56) — bidirectional cross-link with Plan 98 (Vz builder narrows the asymmetric-trust gap on macOS that Sprint 56 fully closes; no scope change to ADR-057).
- [ ] **4.3** `specs/SPRINT.md` final close-out — flip Phase 1/2/3/4 checkboxes in the Sprint 55 entry as each PR lands; this PR is the "all green" pass.

### Phase 4 — deferred follow-ups

- [ ] **4.4** ADR-055 cross-reference update if Vz network defaults diverge from gvproxy (likely out of scope; note explicitly). [Superseded by §4.2c above — leaving the placeholder for any post-2C deviation discovered.]
- [ ] **4.5** §2.S12 — multi-binary same-host dispatch socket collision. Two `mvmctl` versions (system-install + dev worktree) racing on the same dispatch socket. Per ADR-002 the host is trusted; this is a robustness gap (panic, hang, stale state), not a security boundary violation. Track here rather than spending Slice 2C cycles on it. Likely fix: PID-file check before socket bind, refuse with clear "another mvmctl is running this dir" error.

---

## Verification (end-to-end)

After Phase 1:
- `cargo run -- --help` shows `--builder <libkrun|vz>` in the global flags.
- `cargo run -- doctor` reports the auto-detected builder + per-VMM probes.
- On macOS 26+ Apple Silicon: `cargo run -- build --flake .` defaults to Vz.
- On Linux + macOS 13-25: defaults to libkrun.
- `MVM_BUILDER_BACKEND=vz cargo run -- --builder libkrun build ...` — flag wins.
- `mvmctl --builder vz dev up` exits nonzero with the §2.C1 grace-guard message until Phase 2 lands.
- `cargo test --workspace` and `just lint` both green.

After Phase 2:
- `MVM_BUILDER_BACKEND=vz cargo run -- dev up && cargo run -- dev shell -- 'uname -a'` works on macOS 13+.
- `MVM_BUILDER_BACKEND=vz cargo run -- dev down` stops cleanly.
- `cargo run -- dev status` reports both backends' state.
- Coexistence: `MVM_BUILDER_BACKEND=libkrun ... dev up && MVM_BUILDER_BACKEND=vz ... dev up` exits nonzero with a clear message.
- `MVM_BUILDER_BACKEND=vz cargo run -- up --prod ./examples/python/hello-app-with-deps` produces sealed volume; `mvmctl deps inspect <hash> --json` reports it; byte-flip `cve.json` → `verify_sealed_volume` refuses.
- Cross-backend hash equivalence test passes (§2.6) AND content/SBOM/fetch.log/cve.json byte-equivalence test passes (§2.S2).
- `stat ~/.cache/mvm/builder-vm/vms/mvm-builder-vz-persistent` shows the dir inherits mode `0700` from `~/.cache/mvm/builder-vm/`; dispatch socket mode `0700`; `audit.jsonl` mode `0600`.
- `mvmctl audit verify` is clean after a Vz Install (§2.S3).
- `mvmctl doctor` reports `vz_check` entitlement probe on the builder line; auto-detect falls back to libkrun when the probe fails (§2.S4).
- `cargo deny check` and `cargo audit` pass with `crates/mvm-vz` in scope (§2.S5).
- Vz control-socket fuzz target exists under `crates/mvm-vz/fuzz/` *or* ADR-046 names the host-trust justification (§2.S6).
- Snapshot SAVE (if used by persistent) lives at the expected path inside the 0700 dir, file mode `0600` (§2.S7).
- §2.C1 grace guard removed in Phase 2's PR.

After Phase 3:
- `apple` lane in `ci.yml` runs Vz construction smoke green.
- Linux `test` lane confirms libkrun auto-detect.

After Phase 4:
- `grep -n "Builder backend" CLAUDE.md` returns the new subsection.
- `grep -n "Vz" specs/adrs/046-builder-vm-via-libkrun.md` shows the added subsection with security-claim-parity language.
- All Plan 98 checkboxes flipped + Sprint 55 entry in `SPRINT.md` reflects close-out.

## Files (remaining work)

### Modified by Phase 1
- `crates/mvm-build/src/builder_backend_select.rs` — auto-detect + override variant (shipped in worktree).
- `crates/mvm-cli/src/commands/mod.rs` — `--builder` flag on Cli.
- `crates/mvm-cli/src/commands/build/persistent_builder.rs` — consume flag + §2.C1 grace guard.
- `crates/mvm-cli/src/commands/vm/up.rs` — consume flag (InstallDriver path).
- `crates/mvm-cli/src/doctor.rs` — builder-backend reporting.
- `specs/SPRINT.md` — Sprint 55 entry for Plan 98.

### Modified by Phase 2
- `crates/mvm-build/src/vz_builder.rs` — `VzPersistentBuilderVm` driver.
- `crates/mvm-cli/src/commands/build/persistent_builder.rs` — coexistence dispatch (§2.5), remove §2.C1 guard.
- `crates/mvm-cli/src/commands/dev/` (whichever module owns `dev up/down/shell/status`) — coexistence logic.
- Tests: cross-backend volume-hash + content equivalence, permission-mode parity, audit-chain emit on Vz, entitlement-fallback auto-detect.
- Possibly: `crates/mvm-vz/fuzz/` for §2.S6.

### Modified by Phase 3
- `.github/workflows/ci.yml` — `apple` lane Vz construction smoke step.

### Modified by Phase 4
- `CLAUDE.md` — Host dependencies + Builder backend selection + state dirs.
- `specs/adrs/046-builder-vm-via-libkrun.md` — Vz subsection.
- `specs/SPRINT.md` — final close-out bump.

### Reused untouched
- `crates/mvm-build/src/builder_vm.rs`, `builder_vm_runtime.rs`, `libkrun_builder.rs`, `vz_builder.rs` one-shot driver, `persistent_builder.rs` supervisor (all Phase A/B/C work, stable; backend-agnostic).
- `crates/mvm-core/src/platform/platform.rs` — `is_macos_26_or_later()`.
- `crates/mvm-vz/src/lib.rs` + supervisor.
- `crates/mvm-build/src/app_deps_gate.rs` / `mvm_sdk::compile::deps_audit::verify_sealed_volume` — backend-agnostic.
- Plan 99 PR-1 (#448) Stage 0 audit/cache contract — cross-reference, do not duplicate.
