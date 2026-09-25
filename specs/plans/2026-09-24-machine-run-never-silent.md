# `machine run` is never silent

Backing: shipped-source
Validation: none

**Status:** IN PROGRESS. Status reporting, lock waits and progress streaming
have landed on `feat/run-progress-visibility`. The items still open are listed
below.

## Problem

`mvmctl machine run --image rust -it -- /bin/bash`, run from a source checkout
on macOS 26 (HVF), went quiet for between 28 seconds and many minutes. The
user saw no output while:

- the Stage 0 builder image built;
- the workload kernel compiled;
- the guest runtime cross-compiled;
- the image pulled;
- the process waited on locks held by concurrent `mvmctl machine build`
  sessions.

Two things made this worse:

- **`-v` suppressed the Stage 0 spinner.** It assumed the in-guest build log
  was being streamed, which only libkrun did. On HVF, `-v` meant no output at
  all.
- **Stage 0 locks failed immediately under contention** and told the user to
  delete the lock file. That advice is always wrong for an `flock` lock: the
  kernel releases it when the holder exits.

## Goal

From the moment the command starts until the guest shell appears:

- The terminal is never silent for more than about 2 seconds, at the default
  verbosity.
- Every wait says what it is, why it is happening, and how far along it is
  where that is knowable.
- Status goes to stderr, so stdout still carries only command results and
  JSON envelopes.

## Mechanism

- `mvm_vmm::host::ui::activity` holds one process-wide status board.
  - On a TTY, the innermost phase is redrawn in place as a single line: a
    spinner, the elapsed time, and a detail.
  - A phase still running after 2 seconds prints `[mvm] <phase>…` and, when it
    ends, `[mvm] <phase> — done in …`.
  - Off a TTY there is no live line. Instead a heartbeat line prints every 15
    seconds.
  - `ui::spinner` renders through the same board, so nested spinners cannot
    fight over the cursor.
- `mvm_build::nix::build_log` condenses a `nix build` log into a summary such
  as `building <drv> (n/N) · fetched n/N paths`. `BuilderRunner` feeds it the
  console lines it already tails to detect a halt. With `-v` it also echoes the
  raw lines above the live line.
- `mvm_build::builder_vm_runtime::acquire_lock_waiting` is the single
  queue-behind-the-holder primitive.
  - It records the holder's pid, command and start time in the lock file, and
    names them in `waiting for <what> — held by pid N (`cmd`) since HH:MM:SS`.
  - It keeps waiting (up to `MVM_BUILDER_LOCK_WAIT_SECS`, one hour by default)
    and then continues.
  - A holder that dies releases its `flock` with it, so the waiter reclaims the
    lock on its next poll. Nothing ever has to be deleted.

## Audit: steps on the path that can take more than 2 seconds or block

Line numbers refer to `origin/main` at `9ebb81b459`. The Stage 0 steps apply
on a cold cache; "[pair]" marks steps that apply only when a sibling
`mvm-images` checkout is selected.

1. **Workload kernel**, `crates/mvm-cli/src/commands/env/builder_vm/default_microvm.rs:24`
   `ensure_workload_kernel`.
   - Cold source build: `kernel.rs:325` `build_kernel_via_stage0`, which runs a
     Stage 0 VM `nix build` (tens of minutes).
   - Download: `crate::update::download_kernel`.
   - Lock: `stage0_cache.rs:122` `stage0.lock`, which used to try once and
     fail.
   - [pair] `local_pair.rs:101` → `ensure_pair_built` (a builder VM job).
2. **Stage 0 VM**, `crates/mvm-runtime/src/builder_runner/stage0_vm.rs:105`.
   - It fetches the bootstrap kernel, materializes the seed root, and takes the
     lock on `nix-store-stage0-<arch>.img.lock` (`image_lock.rs:419`), which
     already waited with a report.
   - `BuilderRunner::stage0` → `runner.rs:211` `run_to_completion` then polls
     for up to 120 minutes. Nothing on HVF streamed the console.
3. **Builder image bootstrap** [pair / explicit], `bootstrap.rs:944`.
   - Stage 0 of the builder image under `builder-vm/stage0.lock`, which used to
     try once and fail.
4. **OCI guest runtime compile**, `crates/mvm-client/src/launch/runtime_overlay.rs:92`.
   - `cargo zigbuild` of the guest binaries (2–6 minutes cold).
   - Blocking, silent `FileLock` on `<layout>/build.lock` (`guest_agent_build.rs:551`).
5. **OCI pull**, `crates/mvm-cli/src/commands/image/pull_core.rs:312` `pull_image_ref`.
   - Manifest and config fetch.
   - Sequential layer fetch and unpack at `:389`, which reported no byte
     progress.
   - Tree lock at `:377` (`run_image.rs:214`: tries, then blocks silently).
6. **Base-image CVE scan**, `pull_core.rs:419` → `base_image.rs:56`.
   - One OSV request per matched advisory, in sequence
     (`base_image_scan.rs:428-455`). On a Debian image this can take minutes.
7. **Rootfs materialization**, `materialize.rs:311` → `run_image.rs:296`.
   - In-process ext4 and verity writer.
   - Tree and output locks (try, then block silently).
8. **Prepared boot tree**, `materialize.rs:~356` `prepare_rootfs_only_tree`.
   - Copies the whole unpacked tree on the first run.
9. **Runtime overlay compile**, `crates/mvm-build/src/runtime_overlay.rs:333`.
   - A second zigbuild (2–6 minutes cold) with its own build lock
     (`guest_agent_build.rs:652`).
10. **Universal initramfs**, `crates/mvm-build/src/initramfs.rs:191`.
    - A third guest-binary build on a cold cache.
11. **Admission**, `crates/mvm-client/src/admission/mod.rs:336`.
    - `sha256_file_cached` over a fresh `rootfs.ext4` (1–3 seconds on first
      use).
12. **Warm claim**, `crates/mvm-cli/src/exec/transient.rs:84` → `commands/pool.rs:1011`.
    - Blocking `claim.lock` / `warm.lock` (`standby_pool.rs:107,151`). This is
      normally milliseconds.
13. **Cold boot**, `transient.rs:123` `backend.start`.
    - HVF supervisor contract probe (up to 10 seconds).
    - Codesign lock (`mvm-hvf-supervisor.rs:124`).
    - PID file wait (up to 5 seconds) and agent socket wait (up to 10 seconds).
    - Host-agent spawn lock (`host_agent_spawn.rs:158`).
14. **Agent wait and console**, `crates/mvm-cli/src/exec/guest_run.rs:42`.
    - `wait_for_agent_timed(30s)`.
    - A fixed 200 ms sleep before the PTY attaches.

## Work

- [x] Status board with TTY and plain rendering, deferred announcement, a live
  detail source, and stderr-only output (`mvm-vmm/src/host/ui/activity.rs`).
  `ui::spinner` renders through it.
- [x] Condense the nix build log (`mvm-build/src/nix/build_log.rs`).
- [x] `BuilderRunner` streams console progress for both Stage 0 and ordinary
  builds, and echoes raw lines at `-v` (`builder_runner/console_progress.rs`,
  `halt_watch.rs`).
- [x] Replace the Stage 0 `BuildHeartbeat` and the kernel-compile heartbeat
  thread with activities. `-v` no longer turns the status line off.
- [x] `acquire_lock_waiting` with owner record, holder-naming status line,
  bounded wait, and automatic reclaim of a dead holder. The builder image locks
  go through it.
- [x] Stage 0 locks (builder image, kernel, SDK sidecar) queue behind a live
  holder instead of failing. The builder bootstrap re-checks its cache after the
  wait.
- [x] Guest-runtime and runtime-overlay build locks queue with a report.
- [x] The OCI tree and output lock waits show a status line.
- [x] OCI pull reports bytes against the manifest's declared total
  (`LayerFetchOptions::progress`).
- [x] Phases for:
  - the base-image scan, with advisory progress;
  - rootfs materialization;
  - the prepared boot tree;
  - the runtime overlay build;
  - the initramfs build;
  - the kernel download;
  - the pair build;
  - admission;
  - boot;
  - the agent wait.
- [ ] Re-check the kernel cache after waiting on the kernel's Stage 0 lock.
  This is deferred because `build_kernel_via_stage0` also serves an explicit
  `mvmctl kernel build`. A re-check there would change that command's
  semantics, so it needs a caller-side flag.
- [ ] Route the tracing subscriber's writer through `activity::println_above`
  so `-vv` debug lines never land on the live line. The fmt layer writes to
  stdout today.
- [ ] The zigbuild tool-cache lock (`guest_agent_build.rs:901`), OCI index lock
  (`cache.rs:200`), lineage lock and host-agent spawn lock still block without a
  line. Each is held for seconds at most today, but they should report through
  `acquire_lock_waiting` like the rest.
- [ ] Deduplicate the three guest-binary builds on a cold source checkout: the
  OCI runtime, the runtime overlay and the initramfs each build the same
  binaries into their own target directory.
- [ ] Live verification on macOS 26 HVF against a scratch `MVM_HOME`: a cold
  Stage 0 run, and a concurrent `machine build` holding the Stage 0 lock.
