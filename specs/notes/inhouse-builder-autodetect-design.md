# In-house HVF builder — auto-detected, Vz-free selection (design)

Date: 2026-07-02 · Issue: #1403 · Related: #1401 (workload agent reachability)

## Goal

Make the HVF builder the **auto-detected** builder backend on macOS-26
Apple Silicon, with **no flag and no environment variable required**. A bare
`mvmctl machine run --flake …` (or `build image` / `template build`) on that tier
builds the flake inside an HVF builder VM, whose builder image is
**auto-resolved locally** (config-hash-keyed + cached) — never supplied by env
vars, never depending on host Nix.

## Non-goals (separate work, not this spec)

- **Workload `--hypervisor` auto-detect flip** (running the guest on the hvf
  VMM without `--hypervisor hvf`). That is gated on #1401 and owned there.
  Until it lands, a bare `machine run --flake` on macOS-26 *builds* hvf and
  *runs* the workload on whatever the workload auto-detect resolves.
- **Vz code deletion.** Vz is being deprecated entirely, but the Vz backend +
  `mvm-vz-supervisor` still serve the *workload* path until #1401 flips it, so the
  actual deletion of `VzBuilderVm` / `BuilderBackendChoice::Vz` / the `dev_vz.rs`
  builder paths / the supervisor is the final consolidated Vz-removal step (gated
  on both #1401 and this being proven). This spec makes the code **stop choosing
  Vz**; it does not delete Vz.
- **`Install`-job pipeline** — `run_build` returns `NotYetImplemented` for
  `Install` on *every* backend today; unchanged here.

## Approved architecture

Four units plus a proof. The dependency direction is the load-bearing constraint:
`InHouseBuilderVm` lives in `mvm-backend` (above `mvm-build`), so `mvm-build`'s
selection factory cannot construct it — the construction is injected from
`mvm-cli`, which sees both crates.

### Unit 1 — Selection surface (`mvm-build`, pure)

- Add `BuilderBackendChoice::InHouse`; `name() == "hvf"`.
- `resolve_env_override` parses `"hvf"` (override still possible, never
  required).
- **Auto-detect flip:** `auto_detect_default_for(macOS-26 Apple Silicon)` returns
  `InHouse` (was `Vz`). Vz is no longer a default on any tier.
- `resolve_stage0_backend_for_choice(InHouse)` → **libkrun** (hvf Stage 0 is
  a gap, exactly as Vz's was; the "Stage 0 is libkrun" invariant holds).

### Unit 1b — Vz-free fallback + failure classification (`mvm-build`, pure)

The auto-detect flip is made production-safe by the existing ADR-093 transparent
fallback, retargeted off Vz:

- `builder_attempt_order`: auto-detected `InHouse` → **`[InHouse, Libkrun]`**. Vz
  is not in the chain. Explicit `--builder hvf` → single attempt, no fallback.
- **Classification hardening (load-bearing):** today `is_builder_vm_level_failure`
  only matches `SupervisorExited` / `LibkrunUnavailable`, but
  `InHouseBuilderVm::run_build` returns `ExtractionFailed` / "did not power off"
  on boot/transport failure — which would *not* trigger the fallback. Map the
  hvf builder's boot / VM-create / disk-transport / power-off-timeout
  failures to a VMM-level `BuilderVmError` so the fallback fires. Without this, a
  not-yet-working hvf builder would break the build instead of falling back.

### Unit 2 — Pipeline dependency inversion (`mvm-build`)

- `dev_build` stops calling `resolve_builder_backend_with_override` internally
  (dev_build.rs:645). Introduce a `BuilderVmFactory` trait:
  `fn make(&self, BuilderBackendChoice) -> Result<Box<dyn BuilderVm>, BuilderVmError>`.
- `mvm-build` ships `DefaultBuilderVmFactory` covering libkrun / vz / qemu.
- The pipeline takes an injected `&dyn BuilderVmFactory` and composes with
  `run_with_builder_fallback` (the attempt closure calls the factory per choice).
  This is what lets a higher crate supply the hvf builder without inverting
  the crate graph.

### Unit 3 — In-house builder-image auto-resolver (`mvm-cli`)

Resolve the HVF builder image with no env vars:

1. Take the existing cached `BuilderVmImage` (`~/.cache/mvm/builder-vm/<arch>/` —
   the same source libkrun/vz use), producing it via the normal builder path if
   absent (source-checkout-local; host Nix never used).
2. Ensure an **HVF-bootable raw arm64 `Image`** kernel (not ELF `vmlinux`).
3. `rootfs_inject` the cross-compiled `mvm-host-vm-init` so the rootfs speaks the
   disk transport.
4. **Config-hash-key + cache** under `~/.cache/mvm/builder-vm/hvf/<hash>/`;
   reuse warm.

Returns `(kernel, rootfs)` → `InHouseBuilderVm::new(...)`. All paths via
`mvm-core::config`. Hash-keying + cache-reuse are unit-tested; the underlying
image build is integration-gated.

### Unit 4 — CLI wiring (`mvm-cli`)

- `--builder` accepts `hvf` (folded to `MVM_BUILDER_BACKEND=hvf` at
  startup like the others) — an override, not a requirement.
- `mvm-cli` builds an `InHouseAwareFactory` wrapping `DefaultBuilderVmFactory` +
  the Unit-3 resolver: `InHouse` → resolve image → `InHouseBuilderVm`; every other
  choice → delegate. Injects it into the pipeline (Unit 2).
- Update the CLAUDE.md builder auto-detect wording and `mvmctl doctor`'s
  builder-backend line to report hvf as the macOS-26 default.
- Fail-closed, actionable errors (image-resolve failure names the cause). No
  silent fallback for an *explicit* choice.

### Unit 5 — Live proof (DoD)

`mvmctl machine run --flake examples/sleeper` on macOS-26 (no flags) auto-detects
the hvf builder and builds the flake. The builder guest's host↔guest path
rides the hvf VMM; whether this is live-green now or gated on #1401 is
determined during implementation (the builder returns artifacts over a virtio-blk
output disk, which may be independent of the agent-vsock bug #1401 fixes). Lands
with a non-gated test asserting the **fallback** keeps bare macOS-26 builds
working when hvf cannot run, plus the full hvf-success e2e (gated with
`#[ignore]` if it depends on #1401).

## Data flow

`(no flag)` → auto-detect `InHouse` → CLI `InHouseAwareFactory` resolves
`(kernel, rootfs)` (cache hit, or derive-from-builder-image + `rootfs_inject`) →
`InHouseBuilderVm::new` → injected `BuilderVmFactory` → `dev_build` →
`run_with_builder_fallback` (`[InHouse, Libkrun]`) → `BuilderRunner` boots the
hvf VMM builder VM → guest runs `cmd.sh` → artifacts return over the
virtio-blk output disk → `finalize_flake_job` → `BuilderArtifacts`.

## Error handling

- In-house VMM / image-resolve failure on the **auto** path → classified VMM-level
  → transparent fallback to libkrun.
- In-house failure on an **explicit** `--builder hvf` → surfaced unchanged
  (single attempt).
- libkrun unavailable after hvf falls back (macOS-26 box without the
  `slp/krun/*` Homebrew trio) → actionable error (install the trio / hvf
  prerequisite). This is the intended cost of deprecating Vz: the Vz safety net is
  gone by design, not kept as a crutch.
- `Install` job → `NotYetImplemented` (unchanged).

## Testing

- **Unit 1/1b:** enum / `name` / env parse / `auto_detect_default_for` → InHouse;
  `builder_attempt_order` (`[InHouse, Libkrun]` auto, single explicit); a failing
  hvf builder falls back to libkrun and the build still succeeds.
- **Unit 2:** pipeline drives an injected `StubBuilderVm` factory — no real backend.
- **Unit 3:** image-resolver hash-key + cache-reuse (pure).
- **Unit 4:** `--builder hvf` accepted; factory dispatch (`InHouse` → resolver,
  others → default).
- **Unit 5:** non-gated fallback-keeps-builds-working test; `#[ignore]`-gated
  full hvf e2e if #1401-dependent.
- Gates: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -D
  warnings`; `cargo nextest run`; no plan/PR citations in source comments.

## Sequencing / honesty

Units 1, 1b, 2, 4 and the resolver cache logic are fully buildable and testable
now. The auto-detect flip is safe to land now **because** the Vz-free fallback +
classification hardening guarantee bare macOS-26 builds still succeed (via
libkrun) when hvf cannot yet run. This ships production-complete code; the
only thing possibly gated on #1401 is the *live hvf-success* proof, and the
final Vz *code* deletion is the separate consolidated step after #1401.
