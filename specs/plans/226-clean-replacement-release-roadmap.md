# Plan 226 — Clean-Replacement release roadmap (v0.17 macOS → v0.18 Linux)

**Status:** Strategic reference (2026-07-06). This roadmap's macOS→Linux *sequencing* stands, but its **R1P1 execution was superseded** and not landed — the 0.17.0 HVF-default release is driven by **Plan 228** (`228-release-0-17-0.md`) and the full Vz deletion by the **`feat/plan-222-delete-vz`** branch. Kept for the strategic framing (keep libkrun; gvproxy=macOS / passt=Linux; Hetzner KVM box for R2 validation). Two findings for those owners: `create_linux_env()`→`VzDevEnv` is the live macOS build substrate that must be flipped before the Vz files can be deleted, and `just check-linux` needs the rustup toolchain (`PATH=$HOME/.cargo/bin:$PATH`).
**Owner:** Ari
**Supersedes nothing; sequences the tail of:** Plan 214 (clean-replacement architecture), ADR-098 (HVF macOS backend), ADR-102 (`VmmDriver` seam), ADR-108 (verb-grant measured trust).

## 1. Purpose

Define the two releases that finish the clean-replacement: retire the legacy
Apple-Virtualization (`vz`) backend and the userspace network gateways
(`gvproxy`, `passt`) in favour of the in-house HVF VMM and **vsock-only egress**,
while **keeping the `libkrun` VMM** (moved onto vsock egress).

This is a meta/release plan: it names the workstreams, their ordering, their
acceptance gates, and the CI/claim-witness/cross-repo tail. Release 1's
executable step-by-step is produced by the `writing-plans` pass off this doc.

## 2. The reframe (read this first)

**The default flip already landed on `main`.** Both selection sites resolve
macOS-26 Apple Silicon to the in-house HVF VMM today:

- Workload: `AnyBackend::auto_select()` → `InHouse(WorkloadRunner…)`
  (`crates/mvm-backend/src/backend.rs:569`).
- Builder: `builder_backend_select::auto_detect_default_for()` → `InHouse`.
- String path: `resolve_effective_hypervisor()` → `"inhouse"`
  (`crates/mvm-cli/src/commands/shared/resolve.rs:248`).
- `vz` is now **opt-in only** (`--hypervisor vz` / `MVM_HYPERVISOR=vz`).

So "make HVF the default macOS backend" is **done**. The remaining milestone
work is the **deletion** of `vz`/`gvproxy`/`passt` and clearing the code that
still hard-depends on them.

## 3. Target end-state

| Component | Fate |
|---|---|
| **HVF / in-house** | Keep — default macOS 26, vsock-only egress |
| **libkrun** (VMM) | **Keep** — cut over to **vsock-only egress**; stays as macOS builder fallback + Linux builder default |
| **Firecracker** | Keep — Linux workload; egress → vsock in R2 |
| **Vz** (`vz.rs`, `vz_control.rs`, `vz_objc.rs`, `mvm-vz-supervisor`, `mvm-build/src/vz.rs`, `vz_builder.rs`) | **Delete** — Release 1 |
| **gvproxy** (macOS gateway) | **Delete — Release 1** (macOS backends → vsock) |
| **passt** (Linux gateway) | **Delete — Release 2** (Linux backends → vsock, validated on KVM box) |

The gateway split maps exactly onto the release boundary:
**gvproxy = macOS = R1**, **passt = Linux = R2**. `MVM_NETWORKING` defaults are
per-OS (macOS=gvproxy, Linux=passt), so each release removes one gateway on its
own OS with no cross-OS coupling.

### 3.1 The one consequence of keeping libkrun

libkrun's network path *is* gvproxy (macOS) / passt (Linux). Keeping the libkrun
VMM while deleting the gateways therefore requires moving libkrun onto
**vsock-only egress** — the "libkrun vsock egress" Slice-1 work that is already
built-but-inert (no Rust sets `MVM_VSOCK_EGRESS`). Activating that path on macOS
libkrun is what lets gvproxy be deleted in R1.

## 4. Release 1 — v0.17.0 "macOS clean-replacement"

**Definition of done:** HVF is the sole macOS *default* workload + builder + dev
backend; the **entire Vz path is deleted**; macOS egress is **vsock-only** and
**gvproxy is deleted**; `libkrun` remains (on vsock egress) as the macOS builder
fallback + macOS-13-25 backend; `passt` remains untouched (Linux only).

### Workstreams

- **WS-D — Checkpoint/fork descope (option A).** `machine checkpoint/fork`
  returns a clear "unsupported on HVF — tracked for R2/WS-E" error on macOS;
  tests updated. Removes the last *runtime* dependency on Vz. `VzBackend` is the
  only `SnapshotCapability::SaveRestore` backend today
  (`crates/mvm-backend/src/vz.rs:217`), and the full-VM checkpoint path is
  Vz-coupled (`crates/mvm-backend/src/checkpoint/mod.rs`). Closes/absorbs #1478.

- **WS-B — Dev builder VM on HVF.** `crates/mvm-cli/src/commands/env/dev.rs`:
  `DevBackend` gains `InHouse`, macOS-26 default → inhouse, Vz dev path removed
  (currently HVF dev is opt-in `MVM_DEV_BACKEND=hvf`). Prove `dev up/shell/status`
  live on HVF.

- **WS-C — Builder on HVF-default, libkrun-fallback (macOS).** No fallback-net
  removal — libkrun **stays** as the macOS builder fallback (`[InHouse, Libkrun]`).
  Scope is only: confirm the in-house builder is robust enough to be the default,
  and that the fallback still selects libkrun cleanly with Vz gone.

- **WS-N — macOS egress → vsock; delete gvproxy.** Activate libkrun vsock egress
  on macOS (drive `MVM_VSOCK_EGRESS`; wire the built-but-inert guest path),
  confirm HVF is already vsock-only, then delete the gvproxy wrapper
  (`crates/deps/libkrun-sys/src/gvproxy.rs`), host launcher
  (`crates/mvm-build/src/host_gvproxy.rs`), and gvproxy arms in the network
  provider abstraction. **OPEN RISK (verify during writing-plans):** the macOS
  *builder* VM's own egress for `nix` fetches — with gvproxy gone the in-house /
  libkrun builder must have a working egress path (vsock or otherwise). Confirm
  covered or add a task.
  - [x] 2026-07-08 guest-side activation slice landed for OCI `--image` runs: the
        runtime-injected `/init` now bakes and starts `mvm-egress-client`,
        exports proxy envs, the embedded/cacheable guest runtime includes the
        egress client binary, HVF threads `mvm.vsock_egress=1` on eligible
        boots, and the OCI exec path records/injects matching proxy env vars.
  - [x] 2026-07-08 activation follow-through landed: OCI `--image` runs with
        outbound egress enabled (`--net` / `--allow-host`) now select only a
        backend that can honestly provide `{ vsock, no_guest_nic,
        host_vsock_proxy }`; incapable backends are refused instead of silently
        degrading to a guest NIC. Vz now omits the guest NIC/gvproxy entirely
        on this raw OCI path and boots with the host egress endpoint already
        listening, so the in-guest shim fails closed if the endpoint is absent.
        The same selector now gates persistent OCI-backed machine boots
        (`machine run -d --image ...` and `machine start` on an image-backed
        machine), closing the remaining stored-lifecycle fallback onto the
        legacy NIC path.
  - [x] 2026-07-08 gvproxy-specific test retirement landed: the remaining
        gvproxy-only bridge witnesses are removed from
        `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`, and the dedicated
        `gvproxy::tests` module is removed from
        `crates/deps/libkrun-sys/src/gvproxy.rs`. Passt/native-rvproxy
        coverage stays in place while WS-N continues toward code deletion.
        Remaining WS-N scope: builder egress, libkrun default-on cutover, and
        global gvproxy deletion.

- **WS-A — Delete the Vz path.** Remove `mvm-backend/src/vz.rs` (~4.3k),
  `vz_control.rs`, `mvm-vm-host/src/vz_objc.rs` (~2.3k), the `mvm-vz-supervisor`
  bin, `mvm-build/src/vz.rs` + `vz_builder.rs`, the `AnyBackend::Vz` variant + all
  match arms, `is_vz_default_tier`, the `selection.rs` capability tables, and the
  standby-pool `vz_compat`. **Keep the `mvmctl::runtime::*` re-export shims** so
  mvmd still builds — no coordinated breaking change in R1 (see §7). Gates on
  WS-D + WS-B + WS-C landing (nothing may still call Vz at runtime).

- **WS-E — HVF SaveRestore (option B).** Implement `SnapshotCapability::SaveRestore`
  on `InHouseDriver`/`HvfBackend` (guest-memory + device-state capture/restore).
  Independent workstream; on landing it replaces WS-D's error with the real HVF
  checkpoint/fork path. If WS-E slips, R1 still ships with WS-D as the floor and
  WS-E lands as a fast-follow.

- **WS-F — CI / xtask / claim-witness migration (Vz only).** Retire Vz-only
  witnesses: the `mvm-vz-supervisor` `SupervisorConfig` fuzz target
  (`security.yml`), the claim-tier tables and audit labels that hard-code `vz`
  (`resolve.rs:349-379`, `vz:l4-host-port`), and any `xtask` literals. **Leave
  libkrun/passt witnesses in place** — Linux still uses them (claim 5 libkrun
  fuzz, passt-hashes fuzz, `passt-framing` job). Update `specs/claims/catalog.md`
  and confirm `xtask check-claim-catalog` is green.

- **WS-G — ADR ratification.** Move ADR-098 Proposed→Accepted; scope its
  Vz-sunset criteria to macOS and record them met (warm-restore deferred to WS-E,
  representative-workload boot proven on HVF). Note ADR-108 status.

- **WS-H — Release engineering.** Docs + `CLAUDE.md` drop Vz and state "macOS 26
  needs no Homebrew VMM deps for the default path"; `CHANGELOG`; kernel-pin
  freshness (#1264) as it applies to the HVF/workload kernel; verify-and-close
  #1403 (already fixed on `main`); version bump + Homebrew formula.

### Sequencing

```
WS-D ┐
WS-B ┼─→ WS-A (delete Vz) ─→ WS-F ─→ WS-G ─→ WS-H (cut v0.17.0)
WS-C ┘
WS-N ──(parallel; delete gvproxy)──────────────────↑
WS-E ──(parallel; independent; restores checkpoint/fork on HVF)
```

WS-D/B/C/N run concurrently. WS-A gates on D+B+C. WS-N (gvproxy delete) is
independent of the Vz delete but both must land before WS-H. WS-E is independent
and may land any time in the window.

## 5. Release 2 — v0.18.0 "Linux clean-replacement"

**Planned only after a fresh re-evaluation of the post-R1 code** (the tracker is
stale and this repo moves fast — re-scout before committing slices). Sketch:

- Fix **#1405** (KVM-box flake boot: 0-byte flake-slot kernel-link + stale
  nix-store rootfs); bring the Hetzner box (`88.99.197.234`,
  `ssh -i ~/.ssh/hetzner-rvproxy root@…`) online as the live-KVM validation target.
- **Plan 214 S4:** converge Firecracker egress `nftables`→vsock bridge; move the
  Linux libkrun *builder* onto vsock egress; live-KVM sign-off on the box.
- **Delete passt** (`crates/deps/libkrun-sys/src/passt.rs`, the FC-bridge passt-hash
  parser, passt-hashes verification, the `passt-framing` CI job); delete
  `BuilderNet` + remaining NIC attach paths.
- Expand `xtask check-vsock-only-egress` `GUARDED_DIRS` to the whole workload path
  (today it deliberately scopes Firecracker/libkrun/vz out).
- Migrate remaining claim witnesses (claim 10 egress enforcer off the gateway
  bridge; keep libkrun VMM fuzz).
- Coordinate `mvmctl::runtime::*` shim removal with mvmd (§7).
- Confirm checkpoint/fork fully re-homed (HVF via WS-E + Firecracker).

**libkrun stays** in R2 — the VMM survives, only its passt egress moves to vsock.

## 6. Open risks / verify-during-planning

1. **macOS builder egress with gvproxy gone** (WS-N) — the nixpkgs-fetching
   builder VM must have a working non-gvproxy egress path. Verify before deleting
   gvproxy.
2. **libkrun vsock egress activation** — Slice-1 is built-but-inert; confirm the
   guest path actually carries traffic once `MVM_VSOCK_EGRESS` is set, on macOS
   libkrun specifically.
3. **HVF SaveRestore scope** (WS-E) — guest-memory + device-state capture is a
   real VMM feature; size it early so R1 doesn't silently depend on it.
4. **Cross-repo `mvmctl::runtime::*`** — R1 keeps shims; R2 removes them with mvmd.

## 7. Cross-repo coordination (mvmd)

mvmd consumes the `mvmctl::runtime::*` contract (re-exported from `mvm-backend::base`).
Deleting Vz internals in R1 must **preserve those re-export shims** so mvmd keeps
building. The shim removal is an explicit R2 step coordinated with the mvmd repo.

## 8. Open-issue disposition

| # | Disposition |
|---|---|
| #1478 checkpoint/fork Vz-coupled | Absorbed by **WS-D** (descope) + **WS-E** (re-home). |
| #1403 in-house builder not CLI-selectable | **Verify + close** — fixed on `main`; residue is the Vz delete (WS-A). |
| #1264 kernel pin trails upstream | **WS-H** (release-tail), HVF/workload kernel scope. |
| #1405 flake boot on KVM box | **R2 prerequisite.** |
| #1270 / #1229 (Vz-path bugs) | **Obsoleted by WS-A** — do not fix; let deletion close them. |
| #1156 OCI run exec / #1366 Sandbox.connect / #1388 mvm-client seams | Post-release; out of this roadmap. |
| #1462 / #1404 live-validation follow-ups | Ride WS-E / R2 live-boot. |
| #1458 measured-boot/vTPM | Out of scope (ADR-002 scope expansion). |

## 9. Acceptance for v0.17.0

- [ ] No `vz` references remain in the workload/builder/dev selection paths; `--hypervisor vz` is gone or errors clearly.
- [ ] `vz.rs`/`vz_control.rs`/`vz_objc.rs`/`mvm-vz-supervisor`/`mvm-build/src/vz.rs`/`vz_builder.rs` deleted.
- [ ] gvproxy deleted; macOS egress is vsock-only; `just check-linux` + macOS build green.
- [ ] `dev up/shell/status` run on HVF by default on macOS-26; libkrun still the fallback.
- [ ] `machine checkpoint/fork` either works on HVF (WS-E) or returns a clear tracked-unsupported error (WS-D).
- [ ] `xtask check-claim-catalog` green with Vz witnesses migrated; libkrun/passt witnesses intact.
- [ ] ADR-098 Accepted; `CLAUDE.md`/docs/`CHANGELOG` updated; #1403 closed; version bumped.
- [ ] `cargo fmt --all --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings` all green.

## 10. Next step

Invoke the `writing-plans` skill to turn **Release 1** into the executable
step-by-step implementation plan (per-WS tasks, TDD order, verification commands).
Release 2 is planned in a separate pass after the post-R1 code re-evaluation.
