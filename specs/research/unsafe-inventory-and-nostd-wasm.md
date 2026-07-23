# Unsafe inventory + no_std/wasm reach — audit note

Grounded in the tree at `/Users/auser/work/tinylabs/mvmco/mvm` (branch `main`).
Method: `rg -n "\bunsafe\s+(fn|impl|extern|\{|trait)" --type rust` across the
workspace, excluding `unsafe_code` attribute/comment lines and `target/`.

Headline: **642 real unsafe sites**, **346 `// SAFETY:` comments**. The unsafe
is overwhelmingly irreducible — FFI, OS syscall wrappers, and guest-memory/virtio
pointer work inherent to being a from-scratch VMM plus a headless-guest init plus
a process-moat supervisor. There is a small, targeted hygiene slice worth doing;
a blanket minimization pass is not.

Crate-level `#![forbid(unsafe_code)]`: **`mvm-protocol`**, **`mvm-fs`**.
Zero-unsafe crates (not yet forbidding): **`mvm-net`**, **`mvm-client`**,
**`mvm-conformance`**, **`mvm-vz-supervisor`** (stale post-Vz-removal stub).

---

## Part A — unsafe inventory

### Per-crate table

| Crate | Real unsafe | Hot spots (file:count) | What it does | Category |
|---|---|---|---|---|
| `mvm-runtime` | 188 | `hvf/` 55, `vmm/` 28, `base/` 11, `microvm/` 10, `vm/` 9, `kvm/` 8 | Apple Hypervisor.framework FFI (`hv_vm_*`/`hv_vcpu_*`), guest-RAM mapping + virtqueue walks (`GuestMem`, `hvf/guest_ram.rs`, `vmm/virtio.rs`), KVM ioctls, snapshot mmap, `libc::{kill,flock,waitpid,setsid}` liveness/spawn | FFI + syscall + VMM-memory (irreducible in kind) |
| `mvm-agentd` | 140 | `console.rs` 30, `guest_net.rs` 15, `entrypoint.rs` 14, `mvm-verity-init.rs` 11, `mvm-guest-agent.rs` 10, `signals.rs` 8, `netinit.rs` 7, `port_forward.rs` 7 | In-guest init: PTY `openpty`/`ioctl` (`extern "C"`), network `SIOC*` ioctls, `extern "C"` signal handlers, mount/pivot/exec in the entrypoint runner | OS syscall wrappers (irreducible) |
| `deps/libkrun-sys` | 105 | `libkrun_bindings.rs` 63, `sys.rs` 23, `passt.rs` 7, `native_gateway.rs` 6 | `libkrun_bindings.rs` = rust-bindgen output (`extern "C"` decls). `sys.rs` = hand-written thin safe wrappers, each one FFI call deep, errno→`Result` | Legitimate FFI (irreducible; bindgen is generated) |
| `mvm-hostd` | 63 | `smoltcp_egress.rs` 9, `supervisor/substitution_proxy.rs` 7, `supervisor/raw_egress.rs` 7, `parent_death.rs` 6, `mvm-hvf-supervisor.rs` handlers | Egress socket plumbing, `prctl(PR_SET_PDEATHSIG)`, `extern "C"` stop/pause/resume signal handlers, fork/`setsid` for the process moat | syscall wrappers (irreducible) |
| `mvm-cli` | 62 | `doctor/builder.rs` 14, `commands/vm/console.rs` 8, `commands/vm/checkpoint.rs` 7, `signal.rs` 6 | `libc::kill(pid,0)` liveness probes, terminal raw-mode termios, self-pipe SIGINT handler, `getpid`, and ~10 `std::env::set_var` (Rust-2024 unsafe) | syscall wrappers + env-var (mostly irreducible; env-var slice reducible) |
| `mvm-build` | 57 | `mvm-host-vm-init.rs` 24, `stage0-init.rs` 9, `mvm-builderd.rs` 8, `mvm-egress-proxy.rs` 5 | Builder-VM guest-init: `extern "C"` decls, mount/pivot_root/exec, signal handlers — the same syscall class as `mvm-agentd` but for the builder guest | OS syscall wrappers (irreducible) |
| `mvm-host-services-ffi` | 19 | `lib.rs` 19 | The C-ABI cdylib every language SDK dlopens: `pub unsafe extern "C" fn mvm_hsvc_call/_free`, `CString`/slice marshalling across the FFI boundary | Legitimate FFI — this IS the contract (irreducible) |
| `mvm-core` | 6 | `util/test_env.rs` 6 | All six are `std::env::{set_var,remove_var}` inside the test-env helper (Rust-2024 made these `unsafe`) | Rust-2024 env-var (test-only; not reducible, but already centralized) |
| `mvm-sdk` | 1 | `compile/flake.rs` 1 | One `std::env::remove_var` in a test | Rust-2024 env-var (test-only) |

### Categories, honestly

1. **Legitimate FFI — irreducible.** `libkrun_bindings.rs` (bindgen, 63),
   `sys.rs` hand-written wrappers (23), passt/native_gateway (13), the HVF
   `hv_*` calls in `mvm-runtime/src/hvf/` (~55, wrapped behind the portable
   `HypervisorVm`/`HypervisorVcpu` seam in `vmm/hv.rs`), and the
   `mvm-host-services-ffi` C-ABI exports (19). None of this can be safe Rust:
   it is the boundary to libkrun's C, Apple's Hypervisor.framework, and the
   language-SDK dlopen contract. **Do not touch.**

2. **OS syscall wrappers via `libc` — irreducible.** `kill`/`waitpid`/`flock`/
   `setsid`/`fork`/`prctl`/`ioctl(SIOC*/TIOC*)`/`openpty`/`mmap` and `extern "C"`
   signal handlers, spread across `mvm-agentd` (guest init), `mvm-build`
   (builder-guest init), `mvm-hostd` (supervisor/process-moat), and `mvm-cli`
   (liveness + terminal). This is what a headless-guest init and a fork/exec
   process-moat supervisor *are*. The `libc` crate is already the thin safe-ish
   layer; the residual `unsafe` is the syscall invocation itself.

3. **Guest-memory / virtio raw-pointer ops — irreducible in kind, improvable in
   quality.** `vmm/guest_mem.rs` (`unsafe impl Send`, `ptr.add`,
   `copy_nonoverlapping`), `hvf/guest_ram.rs` (mmap + `slice::from_raw_parts`),
   `vmm/virtio.rs` (`unsafe fn new`, descriptor-ring pointer copies). Mapping
   guest RAM and walking virtqueues over raw host pointers is intrinsic to an
   in-house VMM. `GuestMem` already exposes bounds-checked `read`/`write`
   helpers; a slice of `virtio.rs` still does ad-hoc `ptr.add` + `copy`.

4. **Rust-2024 env-var unsafe — cosmetic.** `std::env::set_var`/`remove_var`
   became `unsafe` in edition 2024 (thread-safety, not memory-safety). ~30 sites,
   almost all test-only. `mvm-core::util::test_env` already wraps this; the
   reducible slice is the handful of *open-coded* call sites in
   `mvm-cli/src/commands/mod.rs`, `commands/build/build.rs`, and
   `mvm-runtime/src/substitution_spawn.rs` that bypass the helper.

### Reducibility verdict

- **~95%+ is irreducible** (categories 1–2 and the *kind* of 3). It exists
  because mvm is a from-scratch VMM + guest-init + process-moat. Eliminating it
  means not being those things. Do not propose removing FFI or syscall wrappers.
- **SAFETY-comment coverage is ~54%** (346 / 642). The gap is concentrated in
  formulaic sites (`kill(pid,0)`, `set_var`) that don't need one, but also in the
  category-3 raw-pointer blocks that genuinely should document their bounds /
  aliasing / initialization invariants.

### Recommendation — Part A

**Do not run a blanket minimization pass.** Do one small, targeted hygiene pass:

1. **SAFETY invariants on the VMM-memory blocks.** Add/complete `// SAFETY:`
   on the raw-pointer sites in `vmm/guest_mem.rs`, `vmm/virtio.rs`,
   `hvf/guest_ram.rs`, stating the offset-in-bounds, non-aliasing, and
   initialization preconditions. Where `virtio.rs` still does direct
   `ptr.add` + `copy_nonoverlapping`, route it through `GuestMem`'s existing
   checked accessors so the unsafe lives in one audited place. This is the only
   block where a real memory-safety bug could hide.
2. **Funnel env-var unsafe through `mvm_core::util::test_env`.** Replace the
   ~5 open-coded `std::env::set_var`/`remove_var` sites with the existing helper.
   Zero behavior change; shrinks the raw-unsafe count and localizes it.
3. **Lock in the zero-unsafe crates.** Add `#![forbid(unsafe_code)]` to
   `mvm-net` and `mvm-client` (both already unsafe-free). Cheap, prevents
   regression, extends the property that `mvm-protocol`/`mvm-fs` already hold.

**Leave as-is:** all FFI (`libkrun-sys`, `mvm-host-services-ffi`, HVF), all
`libc` liveness/signal/ioctl/spawn wrappers, the bindgen file, `mvm-vz-supervisor`
(dead — delete under separate Vz-cleanup, out of scope here).

---

## Part B — no_std / wasm reach

### Where the boundary is today

`mvm-protocol` is `#![no_std]` + `alloc` + `#![forbid(unsafe_code)]`
(`crates/mvm-protocol/src/lib.rs:13-14`), and it is **CI-gated for real**: the
`wasm-no-std-boundary` job in `.github/workflows/ci.yml` builds it on
`wasm32-unknown-unknown` and *runs its tests* on `wasm32-wasip1` via wasmtime.
The `schema` feature (schemars codegen) and `--test` builds drop `no_std`
deliberately; the shipped wasm library surface stays no_std.

The heavy lifting is **already done**. Increment 3 of the protocol/core split
(`specs/refactor/07-progress-and-decisions.md`, `10-increment3-...`) is COMPLETE:
the entire claim-8 signed `ExecutionPlan` (46/46 fields byte-identical), the
wire/policy/audit DTOs, and the `Workload` IR now live in `mvm-protocol` and
compile on wasm32. This is the documented WS11 "wasm-container capable" core goal
(`specs/refactor/01-goals.md`).

### Candidate crates and their blockers

- **`mvm-net` — plausible but low-value.** Pure trait/registry/policy seam, zero
  unsafe, no async, no I/O in the seam itself; depends only on `mvm-core` +
  `mvm-protocol`. It is std *only transitively*, through `mvm-core`. To go
  no_std it would need to drop its `mvm-core` dep to `mvm-protocol`-only. Feasible
  — but the trait's implementors (TAP/bridge/gateway/passt in `mvm-runtime`,
  mesh in mvmd) are all host-side std, so a wasm consumer gains almost nothing
  from a no_std `NetworkProvider` trait. Not worth it absent a concrete wasm
  caller.

- **`mvm-core` — no.** std-bound *by design*: 30+ files touch
  `std::fs`/`env`/`process`/`os::unix` — `config.rs` (MVM_HOME paths),
  `crypto/{keystore,secret_store,snapshot_*,egress_ca,volume}` (file-backed key
  and secret stores), `util/atomic_io.rs`, `platform/linux_env.rs`,
  `plan/bundle.rs` (tar/fs). It is deliberately the std layer *on top of*
  `mvm-protocol`; the wasm-relevant pure DTOs were already extracted downward.
  Leave it.

- **Everything above `mvm-core` — no.** `mvm-runtime`/`-hostd`/`-agentd`/`-cli`/
  `-build`/`-client` carry a hard std + tokio + OS floor. tokio enters the
  shipped `mvmctl` through `mvm-hostd` (async server) and `mvm-agentd` (async
  guest); this is architectural, not incidental (dependency-floor note in
  memory). The only lever ever identified is splitting `mvm-hostd`'s sync-admit
  path from its async-server path — and that is about keeping tokio out of a
  *default* build, not about no_std/wasm.

- **`mvm-sdk` — no.** Its build-time `compile/`/IR-emission path is std
  (file I/O, Nix template emission). Its IR types already delegate to
  `mvm-protocol`.

### Is it worth it? Against concrete goals

- **Browser SDK surface — already satisfied.** The realistic browser/wasm target
  is exactly what `mvm-protocol` delivers today: audit-log *verification*,
  plan/bundle DTO parsing, IR validation, all runnable with no host. A browser
  SDK depends on `mvm-protocol` alone. **No further no_std migration is a
  prerequisite** — the CI gate proves it builds and its tests pass under wasm.

- **`WasmBackend` (WS11) — a runtime seam, not a no_std task.** Running a workload
  through the shared `VmBackend` + egress/audit/secret-substitution seam needs a
  wasm *runtime* on the host (e.g. wasmtime — itself std). It does not require
  making any additional crate no_std; the no_std *core* it consumes already
  landed with `mvm-protocol`.

### Recommendation — Part B

**Leave the no_std boundary exactly where it is — at `mvm-protocol`.** The split
was done deliberately, is complete for the signed-plan/IR/DTO surface, and is
CI-gated on `wasm32-unknown-unknown` + `wasm32-wasip1`. Do **not** chase no_std
for `mvm-core` (std by design) or anything above it (tokio/OS floor is
architectural and load-bearing). The one incrementally-feasible move —
`mvm-net` to no_std — is low-value because its implementors are host-side; skip
it until a real wasm consumer needs the trait. For a browser SDK, build on
`mvm-protocol` as-is. The next wasm milestone (`WasmBackend`) is a host-side
runtime feature, not a crate-flattening exercise.
