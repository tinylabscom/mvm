# Tier-1 aarch64 edge host (Raspberry Pi 4/5) — verification findings

Date: 2026-07-27
Status: G1 CONFIRMED a non-bug via a live aarch64 Firecracker boot (ttyS0);
BDD `@firecracker` capability gate + local aarch64 nested-KVM env landed; G2
arch gate DEFERRED — reverted after code review found a placement regression
(see the Slice A note below).

## Question

Can a runtime-only `mvmctl` on a KVM-capable aarch64 board (Pi 4/5, RK3588)
admit and run an already-signed, content-addressed bundle end-to-end, with no
local build?

## Verified

1. **The workspace cross-compiles for `aarch64-unknown-linux-gnu`** — full
   `cargo zigbuild --workspace --lib --all-features`, exit 0 (3m48s, from a
   macOS host via zig). No aarch64-specific compile failures at the lib level.

2. **The runtime-only admit-and-run path exists and is hardware-independent.**
   `bundle install <src>` extracts a verified `.mvmpkg` to `~/.mvm/bundles/<sha>/`;
   `up --manifest <sha>` resolves artifacts straight from that registry dir
   (`vm/template/lifecycle/artifacts.rs::bundle_artifacts_for_sha`) with no nix
   and no builder VM. Admission itself (`mvm_hostd::plan_admission::admit_for_run`
   → verify plan → validity window → nonce replay → `verify_plan_bundle` →
   chain-signed audit emit) touches only filesystem + Ed25519/SHA-256; it drives
   the in-memory mock backend in tests, so it needs no `/dev/kvm` and no builder.
   The first and only hardware gate is `backend.start()`.

3. **Firecracker is the default Linux/KVM backend; libkrun is opt-in.**
   `AnyBackend::auto_select` picks Firecracker on native KVM. `mvm-cli` default
   features do not enable the `libkrun-sys` FFI, so a stock Pi binary links no
   `libkrun.so`. Guest arch resolves correctly (`GuestArch::host()` maps
   non-x86_64 → Aarch64).

## Gaps to close for a real Pi boot

### G1 — console device (CORRECTED: mostly a non-bug for Firecracker)

**Correction (verified against Firecracker docs):** Firecracker emulates a legacy
16550A UART on *aarch64 too*, so `console=ttyS0` is CORRECT for the Firecracker
path on aarch64. The PL011/`ttyAMA0` expectation applies to QEMU's `virt` machine
and the in-house HVF path, NOT to Firecracker. The sweeping arch→console change
described below is therefore NOT needed; the only plausible aarch64 delta is
adding `keep_bootcon` if the boot log comes up silent. **CONFIRMED 2026-07-27 on
real aarch64 Firecracker v1.10.1 in the Lima nested-KVM guest:** a stock
Firecracker-CI aarch64 `vmlinux-6.1.102` boots and emits a full kernel console
log on `console=ttyS0` (`Booting Linux on physical CPU ... aarch64`), no change
needed and `keep_bootcon` not required for boot output. Using a QEMU-`virt` boot as a proxy (PL011→ttyAMA0) would have
mis-led us into breaking a correct cmdline — hence the original "don't change the
contract blind" caution.

Original finding, retained for context — console device is x86-named across the
Firecracker path:

`console=ttyS0` is baked into the FC production path, not just tests:
- `crates/mvm-runtime/src/driver/fc.rs:74` (+ the rationale comment at :67)
- `crates/mvm-runtime/src/compat.rs:102,145` — a compat *contract* requiring it
- `crates/mvm-runtime/src/artifacts/builders/nix.rs:148`
- `crates/mvm-runtime/src/vm/template/lifecycle/build.rs:87,89`
- `crates/mvm-runtime/src/qemu.rs:85` (dev/test backend, same issue)

aarch64 has no 8250 ISA serial; a PL011 (`ttyAMA0`) is expected, which the
in-house HVF path already uses (`hvf_bootargs.rs:14`). This is cross-cutting —
it touches a validation contract and its tests — so it is its own slice, and the
exact correct console device for *Firecracker on aarch64* must be confirmed on
real aarch64 KVM before changing the contract. Do not change blind.

### G2 — no host-arch gate at bundle admit (hermetic, no hardware needed)

`BundleManifest.arch` is only displayed by `bundle fetch`; neither
`admit_for_run` nor `bundle_artifacts_for_sha` compares it to
`GuestArch::host()`. An `x86_64` `.mvmpkg` installed on a Pi is admitted and
fails only at boot, with a confusing error. Fix: fail closed at admit/resolve
when `manifest.arch != GuestArch::host()`. Fully unit-testable against the
existing hermetic admission tests (`plan_admission.rs` tests,
`up/admission.rs::admit_plan_tests`). Recommended next slice — no hardware.

## Blocker for true end-to-end

The boot half (`backend.start()` → Firecracker on `/dev/kvm`) needs an aarch64
KVM host. The available cloud KVM box is x86_64, which validates the
arch-independent admit/verify/audit logic but not an aarch64 boot. A Pi 4/5 or
an aarch64 KVM instance is required to validate G1 and the full
`bundle install` → `up --manifest <sha>` boot.

## Proposed sequencing

- Slice A: DEFERRED — the G2 arch gate was reverted after code review. Placing
  it in `bundle_artifacts_for_sha` also blocked non-boot callers that legitimately
  resolve foreign-arch bundle artifacts without booting (`bundle export`,
  `manifest export-oci` both reach it via `template_artifacts_dispatched`). Redo:
  gate at the actual boot sites (`exec.rs` `resolve_image_artifacts` /
  `boot_session_vm`) and cover the plan-admission path
  (`plan_admission::admit_for_run`, which re-verifies a pinned bundle but not its
  arch); add a regression test asserting cross-arch `bundle export` still works.
- Slice B (needs aarch64 KVM): validate the correct Firecracker aarch64 console
  device, then thread target arch → console selection through the compat contract
  + cmdline builders (G1), with the full signed-bundle boot as the witness.
- Packaging (later): a runtime-only aarch64 `mvmctl` binary build (backend =
  Firecracker, no libkrun feature, embedded host bins cross-built for the Pi).

## Slice 3 (local aarch64 Firecracker validation) — progress

Environment (all done, on this M4 Max):
- `mvm-arm64` Lima VM: aarch64 + nested `/dev/kvm` (functional), `firecracker
  v1.10.1` installed, `/dev/kvm` opened to 0666 for the session.
- **3b done:** a stock Firecracker-CI `vmlinux-6.1.102` boots and emits a full
  kernel console log on `console=ttyS0` → G1 confirmed a non-bug.
- **aarch64 `mvmctl` cross-build done + validated:** `cargo zigbuild --target
  aarch64-unknown-linux-gnu --bin mvmctl` (MVM_SKIP_EMBED_BINARIES=1) links a
  glibc-dynamic ELF; runs in the guest (`mvmctl 0.18.0`) and carries `bundle
  export/install` + `machine run --manifest`. Packaging gate passes.

3c remaining — the real mvm bundle boot (turnkey recipe):
1. On the Mac (native `mvmctl`, isolated `MVM_HOME`): `mvmctl machine build
   --flake <repo> --profile <pkg>` → aarch64 slot. (First run auto-bootstraps the
   HVF builder VM — large. Confirm the flake's valid `--profile` package name;
   the old `minimal`/`worker` doc examples are stale. Ensure the native `mvmctl`
   was built WITH embedded host bins, else the builder fails closed.)
2. `mvmctl bundle export <slot> --out /tmp/wl.mvmpkg` (signs with
   `~/.mvm/keys/host-signer.ed25519` under that MVM_HOME).
3. `limactl copy /tmp/wl.mvmpkg mvm-arm64:/tmp/` and copy the host-signer PUBLIC
   key into the guest MVM_HOME's `trusted-publishers/<key_id>.pub` (else install
   fails closed).
4. In guest: `/tmp/mvmctl bundle install /tmp/wl.mvmpkg` → capture
   `bundle_sha256=<sha>`, then `/tmp/mvmctl machine run --manifest <sha>` → assert
   the guest boots and the console shows output. Wire this as the first `@live
   @firecracker` scenario (the gate for it already landed in #1872).

Gotchas: no `sudo` on the host (all privileged steps in-guest); building the
guest from a worktree can write temp files into the main checkout.

### 3c update (validated on this M4 Max)

- **The aarch64 mvm guest BUILDS.** `mvmctl machine build --flake examples/sleeper
  --builder hvf` (isolated `MVM_HOME`) ran end-to-end: HVF builder VM
  auto-bootstrapped, pulled the kernel via the host substitution/egress endpoint
  (148 MB from cdn.kernel.org), compiled the guest agent, and emitted a **sealed
  aarch64 sleeper `rootfs.ext4`** (208 MB) with `mvm-meta.json`
  (`sealed:true`, `agentBinary:"real"`, busybox init). So the whole aarch64
  build path works on this Mac.
- **Blocker for the bundle path:** `machine build --flake` produces a *dev
  build* (cached under `dev/build-cache/<sha>`), **not** a registered slot.
  `bundle export <TEMPLATE>` needs a manifest **slot** (`manifest ls` shows "No
  built slots"), and slots come from a **manifest (`mvm.toml`) build**, not a
  flake. There are **no `mvm.toml` examples** in-repo (all workloads are flakes).
- **Corrected next step:** scaffold a *manifest* project — `mvmctl init --preset
  python` or a hand-written `mvm.toml` (the `minimal`/flake presets scaffold
  `flake.nix`+`baseline.nix`, NOT an `mvm.toml`, so they only produce dev
  builds). Then `machine build <manifest-dir>` → slot → `bundle export <slot>
  --out x.mvmpkg`.
- **Two real blockers for the in-guest boot witness, both now understood:**
  1. **No `mvm.toml` on this branch.** `mvmctl init` (`minimal` *and* `python`)
     scaffolds flakes, not manifests, and there are no in-repo `mvm.toml`
     examples — they are being added by **PR #1870** ("add mvm.toml examples and
     manifest parser fixture tests"), currently in the merge queue. Rebase on it
     (or hand-write an `mvm.toml` from `mvm_core::domain::manifest`) to unblock
     the slot path.
  2. **The guest needs the full aarch64 host-side runtime, not just `mvmctl`.**
     `machine run --manifest` (Firecracker path) spawns the per-VM
     supervisor/broker/host-signer/audit-signer subprocess bins (mvm-hostd's
     `[[bin]]`s — the process moat) plus the firecracker driver. Those are
     separate binaries not embedded in `mvmctl`; they must be cross-built for
     aarch64 and placed on the guest `PATH` alongside `mvmctl` + firecracker.
  Net: build + CLI + KVM env + G1 all proven; the boot witness is a bounded
  runtime-deployment step gated on #1870 + cross-building the mvm-hostd bins.

### 3c end-to-end walkthrough (first real aarch64 FC bundle boot) — DONE to admission

Executed the full path locally (Mac build → guest boot in `mvm-arm64`): cross-built
`mvmctl` + all 6 mvm-hostd bins for aarch64; `machine build` a slot; `bundle
export`; deployed to the guest (bins via the read-only virtiofs mount; bundle +
host pubkey copied); `bundle install` **verified + installed** against the trust
store; `machine run --manifest --entrypoint` **admitted a signed ExecutionPlan
(claim 8: sign→verify→audit→dispatch=firecracker)** and started the session VM.

Being the first to exercise this path surfaced a **vein of x86-centric bugs**,
each blocking the next:

1. **HVF builder ignores `artifact_out` — FIXED.** `run_build` wrote artifacts to
   the VM's own `output_dir` and called `finalize_flake_job(output_dir,
   output_dir, ...)`, never mirroring to the caller's `mounts.artifact_out`, so
   manifest/slot builds (and silently the flake dev-build) found an empty dir.
   Fix in `crates/mvm-runtime/src/builder_runner/hvf_builder.rs` (mirror
   `output_dir` → `artifact_out`, then `finalize_flake_job(output_dir,
   artifact_out, ...)`). **Verified: slot + bundle now build.** Uncommitted;
   PR-worthy on its own.
2. **`bundle export` omits the `mvm-meta.json` sidecar.** The boot refuses a rootfs
   with no adjacent `mvm-meta.json` (used to confirm `/mvm/runtime` overlay
   support); the exported bundle carried only kernel+rootfs (2 artifacts).
   Worked around by copying the build's `mvm-meta.json` next to the guest rootfs.
3. **FC path spawns the substitution endpoint with no egress + no secrets.** The
   sleeper plan has `egress:None, secrets:None` — libkrun has
   `substitution_not_spawned_when_no_secrets_and_no_egress`, but the FC path
   spawns it anyway, and it fails the ready handshake in-guest. Worked around with
   an `MVM_SUBSTITUTION_ENDPOINT_PATH` stub emitting the empty `{}` handshake.
4. **FC kernel-prep assumes an x86 ELF `vmlinux`.** aarch64 kernels are the flat
   ARM64 `Image` (PE) format; `file` confirms the bundle kernel and the
   firecracker-CI kernel that booted raw in 3b are the SAME `Image` format.
   Firecracker aarch64 loads `Image` natively (3b proved it), but mvm's "extract
   FC-loadable vmlinux" step rejects non-ELF/non-gzip → boot blocked here. Fix:
   pass ARM64 `Image` kernels through to firecracker unchanged. (current blocker)

Remaining after #4: the guest kernel boot itself, then the guest-agent
vsock readiness handshake (unexercised). This is an **aarch64 workload-boot
hardening workstream** (bugs 2–4 + agent handshake), not a single fix — worth a
dedicated plan. Admission + the whole packaging/deploy pipeline are proven.

### BOOT WITNESS ACHIEVED (2026-07-28)

With #4 fixed and Firecracker upgraded to **v1.14.1** (mvmctl's
`FC_VERSION_DEFAULT`; v1.10.1 predates `--enable-pci` and failed arg-parsing),
the **aarch64 mvm guest boots end-to-end under Firecracker** in `mvm-arm64`.
Console (`vms/<vm>/console.log`) shows the whole path:
- Firecracker loads the ARM64 `Image` kernel (via the #4 passthrough).
- Guest kernel up: virtio-blk (vda rootfs / vdb overlay / vdc secrets), PL031
  RTC, `PF_VSOCK registered`, EXT4 root mounted read-only.
- `Run /init as init process` → `mvm-init: mounted runtime overlay /dev/vdb at
  /mvm/runtime (ro)`.
- `mvm-guest-agent: profile=Dev` → `control plane ready (45ms)` →
  `listening on vsock port 5252`.

**Fixes that made it boot:** #1 HVF builder artifact mirroring (PR #1884) and #4
ARM64 `Image` kernel passthrough (applied here; extract-to-own-PR). Worked around
#2 (meta sidecar) and #3 (FC substitution over-spawn) as documented.

**Last open gate — a raw host↔agent vsock connect, NOT the boot.** `machine run`
retries `connect_to_port(fc_vsock_uds, GUEST_AGENT_PORT=5252)` (a plain
Firecracker-vsock CONNECT, `vsock/connection.rs::try_connect_once`, no RPC) for
60s and times out — while Firecracker stays running (the loop's `is_vm_running`
never trips) and the guest agent is listening on AF_VSOCK 5252 (port matches).
So the host's CONNECT to the guest agent never completes: a **vsock-transport**
issue, most likely the nested-Lima Firecracker-vsock path (firecracker running
*inside* a KVM guest) or a UDS/CID config detail — best confirmed on real,
non-nested aarch64 hardware (a Pi/Graviton) where firecracker-vsock isn't nested.

### Bug #5 — FINAL root cause: the guest init had no cmdline fallback

Two earlier readings of this were wrong; recording both so nobody re-walks them.

- **Wrong theory 1:** "`driver/fc.rs` omits the `mvm.host_signer_pub=` token."
  It does not. The FC path routes through the shared assembler
  (`workload_runner/cmdline.rs::workload_cmdline` → `hvf_bootargs::grant_tokens`),
  which emits all three grant tokens.
- **Wrong theory 2:** "the kernel cmdline is silently truncated at 1000 chars."
  It is not. Reading `boot_args` out of the VM's own `firecracker.log` shows the
  host sent a **complete 1925-char cmdline** with `mvm.verb_grant` (full 1636
  hex chars = the entire 818-byte JSON), `mvm.require_grant`, and
  `mvm.host_signer_pub` all present and intact. The ~1000-char cut observed in
  the guest's `Kernel command line:` line is the **kernel `printk`
  line-length limit (`LOG_LINE_MAX`, ~1024) truncating the log line**, not the
  cmdline. Never diagnose cmdline contents from that printk — read
  `firecracker.log`'s `boot_args`, or `/proc/cmdline` inside the guest.

**Actual root cause:** `nix/lib/mk-guest.nix` stage 2.475 read the host-signer
pubkey *only* from `/mnt/config/host-signer.pub`, and the vsock-only Firecracker
workload path **attaches no config drive at all** (no live code creates one:
`create_dev_config_drive` has zero callers, and `workload_blocks` has no config
slot — `/dev/vdb` there is the runtime overlay). So the key never reached
`/run/mvm/host-signer.pub`, the agent logged `host-signer pubkey absent …
refusing control RPCs`, and the host's readiness probe timed out.

**Fix (applied here):** stage 2.475 now falls back to reading
`mvm.host_signer_pub=<hex>` from `/proc/cmdline` when
`/mnt/config/host-signer.pub` is absent (the agent accepts the 64-char hex
form). This is the complete fix for the observed failure.

### Latent, separate: the cmdline is at 94% of its budget

Not what bit us, but real. The assembled cmdline is 1925 chars against arm64's
`COMMAND_LINE_SIZE` of 2048 — 94% consumed. The bloat is an encoding artifact:
`VerbGrant.sig` is a `Vec<u8>` that serializes as a **JSON array of 64 decimal
numbers** (~230 chars), and the whole envelope is then **hex-encoded, doubling
it** (818 bytes → 1636 chars). A full 16-verb grant pushes the token alone to
~1739 chars. Cheap, contained fixes, in order of value:
1. **Fail closed** — the FC path has no cmdline length guard at all
   (`artifacts/validate.rs` knows `COMMAND_LINE_SIZE`; `kvm/x86_boot.rs` guards
   only its own path). Refuse to boot on overflow instead of relying on luck.
2. **Shrink the encoding** — base64 instead of hex, and a compact `sig`
   encoding rather than a 64-number JSON array. Roughly halves the token and
   takes the budget from ~94% to ~50%.
3. Moving the grant to a block-device carrier is a much larger change (there is
   no config-drive infrastructure on this path, `/dev/vdb` is already the
   runtime overlay, and both guest inits would need new mount/read code). Worth
   it only if 1+2 prove insufficient.

Superseded analysis retained below for context — the truncation reading it
describes is incorrect:

```
..."verbs":["protocol-hello","ping","readiness-status","worker-status","sleep-prep"   <-- cut, invalid JSON
```

Token census on that boot: `mvm.verb_grant` PRESENT (but corrupt) and
`mvm.runtime_source_policy` PRESENT, while **`mvm.require_grant`,
`mvm.host_signer_pub`, and `mvm.vsock_egress` are all MISSING** — precisely the
tokens the assembler appends *after* the oversized blob. `require_grant` is
derived from the same sidecar file as `verb_grant`, so it cannot legitimately be
absent; that asymmetry is the proof of truncation rather than a missing emit.

Why it matters beyond this boot:
- The grant arrives as **invalid JSON**, so grant verification can never succeed.
- **`mvm.require_grant=1` — the token telling the guest to *enforce* grant
  checking — is itself droppable.** Here the guest failed closed ("refusing
  control RPCs"), but a silently-droppable enforcement flag is a fail-open shape.
- It is **silent**: nothing warns on the host, and the visible symptom is an
  unrelated-looking agent-readiness timeout.

Where the gap is: `artifacts/validate.rs` knows about `COMMAND_LINE_SIZE`
(assumes 2048) and `kvm/x86_boot.rs` guards its own boot path, but the
**Firecracker driver path has no length guard at all**, and the observed cap
(1000) is far below the 2048 the validator assumes.

Fix shape (not yet implemented):
1. **Fail closed** — refuse to boot when the assembled cmdline exceeds the
   backend's real limit, instead of letting it be truncated.
2. **Stop carrying a ~400-byte JSON grant on the cmdline.** Immediate
   mitigation: emit the small critical tokens (`require_grant`,
   `host_signer_pub`, `vsock_egress`) *before* the large blob so they survive.
   Real fix: move the grant to a proper carrier (config drive / vsock hand-off).
3. Keep the `mk-guest.nix` fallback applied here — `mk-guest.nix` stage 2.475
   now reads `mvm.host_signer_pub=<hex>` from `/proc/cmdline` when
   `/mnt/config/host-signer.pub` is absent (the agent accepts the 64-char hex
   form). A vsock-only guest has no config drive, so the cmdline is its only
   carrier for that key. Necessary but **not sufficient** — the token has to
   survive truncation first. Then the guest side (copy mvmpkg + host pubkey into
  trusted-publishers → `bundle install` → `machine run --manifest <sha>`) is
  unchanged. This is the remaining focused step; everything upstream of it
  (build, cross-built guest `mvmctl`, KVM env, G1) is proven.
