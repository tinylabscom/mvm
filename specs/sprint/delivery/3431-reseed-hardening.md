# #3431 — reseed helper hardening, and a plain resume that did not reseed is refused

Follow-up to #3378 (`3378-restore-reseed.md`): five items from its security
review that were not in the branch when it merged, plus one decision.

## What shipped

- **No executable memory in the helper.** Its seccomp allowlist now permits
  `mmap` only without `PROT_EXEC`, by the same masked-equality rule `mprotect`
  already had. With `mremap` unable to change protection and `pkey_mprotect`
  not allowed, the helper has no syscall that maps or marks memory executable.
  The comment that claimed this before it was true is corrected. Unit tests fork
  a child, install the real filter, and assert an executable `mmap` and an
  `mprotect` to `PROT_EXEC` both end in `SIGSYS` while a read-write `mmap`
  survives. They run natively on the x86_64 and aarch64 test lanes.
- **A slow connection no longer wedges the listening helper.** Each accepted
  connection gets one second in total (`CONNECTION_DEADLINE`), counted from
  accept across all its reads and writes: before every call the remaining time
  is set as that call's receive or send timeout, and once it is spent every call
  fails. A per-call timeout alone was not enough, because a peer that sent one
  byte just inside each timeout could hold the one-at-a-time loop indefinitely.
  A connection that runs out of time is dropped and the helper keeps accepting.
  `std` sets the timeouts with `setsockopt`, so the allowlist gains `setsockopt`
  restricted to `SOL_SOCKET` with `SO_RCVTIMEO` or `SO_SNDTIMEO`; a filter test
  checks both are allowed and `SO_RCVBUF` is not. An accepted Unix socket does
  not inherit timeouts from its listener, and a timeout on the listener would
  bound `accept` too, so this could not be done before the filter goes on. The
  socket-pair helper PID 1 starts has one peer and no deadline. Because the
  helper now closes connections the agent keeps between restores, the agent
  resends a request once on a fresh connection when a kept one turns out to be
  gone; a connection opened for the request gets no second try. Tests: an idle
  connector and a connector trickling one byte per 100 ms, each followed by a
  served reseed, over a real socket in the protocol unit tests; the idle case
  also through the confined listening helper in the privileged integration
  test.
- **Privileged tests cannot pass without privilege.** Both gates (the helper
  integration test and the `guest_mount` privilege witnesses) now use
  `geteuid()` and panic when `MVM_GUEST_PRIVILEGED_TESTS=1` is set without
  root, instead of returning early. The decision is a pure function with a
  unit test. It is written twice, once per site, because a `cfg(test)` helper in
  the library is not visible to an integration test. The CI step now expects
  exactly `test result: ok. 4 passed` from the helper suite.
- **The helper's threat model is stated correctly.** A compromised agent can
  have the helper reseed as often as it likes, and each request adds 16 chosen
  bytes credited as 128 bits. That is accepted: the host token is the reseed's
  only fresh input and pre-5.18 kernels skip a forced reseed without the credit;
  chosen bytes cannot cancel what the pool holds; and the count only matters
  before the generator first initializes, long before any restore. Corrected in
  `crng_reseed/mod.rs` and in `3378-restore-reseed.md`.
- **A failed reseed still mixes the token.** When the helper is missing or
  fails, the agent writes the token to `/dev/urandom`, which needs no
  capability. That mixes it into the input pool but leaves the generator on its
  old key until the kernel's own reseed, so the guest still reports
  `reseeded: false`; the reason now says whether the mix happened.
- **A resume refuses a guest that does not confirm a reseed.** A plain resume
  can restore the same sealed memory image more than once — the epoch check
  refuses only an older snapshot, and a resume reloads it into a fresh VMM
  whether or not the last one is running — so a guest that did not reseed would
  reuse random state it has already used. Every way of not confirming a reseed
  is refused alike: a reported shortfall (with the fork path's words from
  `describe_missing_reseed`: rebuild the image for a missing helper, retry for a
  failed one), an agent that never became reachable, a failed or
  unacknowledged post-restore signal, a clock that did not resync, and an
  exchange that has not finished by the admission deadline. The
  workload shares its agent's uid and could stall the agent on purpose, so an
  error that skipped the refusal would have left it running on reused state
  with the registry saying resumed.

  A refusal stops the VMM, keeps the machine paused (it is marked resumed only
  after the guest confirms the reseed), keeps the sealed snapshot, and records a
  `ResumeRefused` entry. On Firecracker the stop is the verified one the driver
  uses (`terminate_firecracker_pid`: SIGTERM, then SIGKILL, and an error if the
  pid survives), and its failure is reported in the refusal instead of a claim
  that the VMM was stopped; before, `teardown_paused` ignored the kill's result
  and always returned `Ok`. It signals a recorded pid only once
  `is_firecracker_for_socket` confirms it is the Firecracker serving this VM's
  API socket; only a positively different answer (the process is gone, is not
  Firecracker, or serves another socket) makes the pid a stale marker, and an
  identity it cannot confirm is an error. The per-VM network endpoint is left alone, as it is
  for a paused machine, so a retried resume still has it. A warm resume that
  did not rotate goes through the same refusal, stopping the VM through the
  backend's `stop`; no backend completes a live-memory warm start today (every
  `warm_start` falls through to the trait default, which fails), so that arm
  is not reachable yet.

- **A resumed guest ends admitted or stopped, however the resume ends.**
  - *A bounded window.* The post-restore exchange runs on its own thread and
    the resume waits for it no longer than 15 seconds (5 for the agent to come
    up, 10 for the exchange); a guest that has not answered by then is refused.
    Before, the bound was the transport's: a 10-second read timeout and up to
    four connect attempts after the 5-second readiness wait. The abandoned
    thread ends when its own connect retries and read timeout run out.
  - *One decision.* The resume and its interrupt cleanup share an
    `AdmissionClaim`; whichever settles it first acts. An interrupt after the
    admission stops nothing, and a refusal is recorded once. The admission is
    settled while the `fc.admitted` record is written, so no interrupt lands
    between the two.
  - *SIGINT, SIGTERM, SIGHUP.* A new `mvm_runtime::interrupt_cleanup` module
    holds cleanups registered with `on_interrupt`, and the CLI's signal
    handler (`termination_handler`) runs them all with `run_all` before it
    exits. The self-pipe handler now serves SIGTERM and SIGHUP too (the byte it
    writes is the signal number; exit status is 128 plus it), so a terminate
    request or a closed terminal cleans up like Ctrl-C. The console's Ctrl-C
    forwarding still applies to SIGINT only. The handler writes to stderr
    without `eprintln!`, which panics on the EIO a closed terminal returns and
    would skip every cleanup.

    `interrupt_cleanup` replaces `handle_registry`: nothing had populated its
    attached-handle map since May, and after the rebase onto the change that
    removed the module's only caller, no signal path ran its sweep at all. This
    change is now the only user of the mechanism, so it carries just the
    cleanup registry and not the attached-handle registry. A test drives the
    handler closure the CLI installs, so dropping the cleanup call from it
    again fails a test rather than passing silently, as the rebase briefly did.
  - *SIGKILL and out-of-memory kills* cannot be caught. The guest keeps running
    until the next state-touching command, whose reconcile pass on entry stops
    it.
  - *An admission record reconcile can trust.* A Firecracker VM's state
    directory now carries `fc.admitted`, written only after the guest confirmed
    its reseed and removed by the next pause, beside `fc.paused`. Each marker
    holds the pid it describes and counts only while `fc.pid` names that pid.
    Reconcile stops a paused record's live Firecracker that neither marker
    accounts for. The registry's `paused` flag is still a precondition — a
    machine that was never paused has no marker either — but it is no longer
    trusted alone: a registry write that failed after an admission cannot make
    an admitted guest look unadmitted. This is the smallest design that covers
    both halves, because the marker lives next to the pid it describes and is
    written by the same process in the same step as the decision.
  - *Authoritative registry writes.* `set_registry_paused` and
    `set_registry_resumed` take the registry lock through a new
    `update_registry` helper and return their errors, and so does the pause
    marker, since reconcile now acts on their absence. Reconcile holds the
    registry lock for its whole pass, so it never saves a stale copy over
    another process's change.
  - *Check, then lock, then check again.* Reconcile classifies without the
    resume lock. Once it holds it, it re-reads the registry and the markers
    and stops nothing if the machine is no longer paused or the guest has been
    admitted in the meantime.
  - *Paths by name.* Reconcile derives the state directory from the machine's
    name under the `vms` root, not from the record's `vm_dir`, which some
    registrations leave empty.
  - *One lifecycle change per machine.* `resume_machine` and `pause_machine`
    hold a per-machine lock (`instances/<name>/resume.lock`, the existing
    `FileLock`) for the whole operation, and reconcile skips a machine whose
    lock is held.
  - *Interrupt coverage.* The sealed restore arms an interrupt cleanup that
    stops the VMM and records the refusal. A warm or non-sealed resume arms
    none yet: interrupting one leaves the guest running with the registry
    still saying paused, found only by the next reconcile pass (and reconcile
    today only reconciles Firecracker machines).
  - *Only a paused machine is restored.* A sealed resume refuses unless the
    registry records the machine paused. Otherwise `resume` on a running
    machine would restore an old snapshot over it, and a resume whose process
    was killed would leave a guest reconcile cannot see, since reconcile acts
    only on paused records. A machine with no registry record is refused for
    the same reason.
  - *A registry write that fails after admission* is reported with the
    instruction not to resume again: the registry still says paused, so a
    resume would restore the sealed snapshot over the running, admitted guest.
  - *Markers are written atomically* (temporary file and rename).
  - *A failed resume request.* `guard_and_resume` tears the VMM down when
    `resume` errors, since a request that timed out on the client side can
    still have been applied.
  - *This VM's Firecracker only.* The restore teardown and the restore's stop
    of a previous VMM signal a recorded pid only if `/proc/<pid>/cmdline`
    passes this VM's socket to `--api-sock`. A pid left from before a reboot
    that now names another VM's Firecracker is treated as a stale marker.

- **An encrypted snapshot can be resumed again.** A resume used to decrypt the
  sealed artifacts in place, but the HMAC seal covers the ciphertext, so the
  next resume failed verification ("snapshot file size mismatch"), and
  decrypted guest memory stayed on disk. A resume now copies the artifacts into
  a private staging directory beside the sealed snapshot (`.restore-<pid>-*`,
  mode 0700, files 0600), decrypts them there, loads from there, and removes
  the directory when the load returns, whether it succeeded or not. The sealed
  files are never modified. An interrupt exits without running destructors, so
  the restore also registers an interrupt cleanup that removes the directory.
  A SIGKILL, an out-of-memory kill or an abort (release builds abort on panic)
  leaves it on disk; every restore, encrypted or not, and every reconcile pass
  remove a staging directory whose owning process is dead.

- **What a refusal does not undo.** A refused guest has run: until it answers
  or the 15-second deadline passes, and then for as long as stopping its VMM
  takes, with its
  egress endpoint up, so traffic the network policy admits can leave the VM
  carrying values derived from the reused state. Each retry runs the same state
  for that window again. An admitted guest also runs briefly on the old state
  before its reseed takes effect. And the reseed re-keys the kernel's generator
  only: user-space generators seeded before the snapshot are not re-keyed.
  `snapshots.md` says all of this.

  An admitted resume prints its reseed outcome, and the local backend records
  it in the `WorkloadWake` entry for plain and warm resumes alike. That entry
  used to be written by the CLI's resume command only; it is now written where
  the resume happens, so a resume through any client surface records it. The
  stale `ResumeOutcome::reseed` and `ResumeOutcome` docs are fixed.

  **Where this is recorded.** `ResumeRefused` and `WorkloadWake` go to the local
  audit log (`log/audit.jsonl`), which is unsigned and written best-effort: a
  failed write is logged and the resume proceeds. Neither goes to the
  chain-signed per-tenant log. So the refusal is enforced by the code path, but
  its record is not tamper-evident, and it must not be cited as an enforced
  claim. A chain-signed refusal entry is W1b.8 in the plan, open.

Reconcile sweeps abandoned staging only under each registered machine's
instance directory. Fork and template restores stage beside their own sealed
directories, which reconcile does not visit; their abandoned staging is removed
only by the next restore from the same place.

## Upgrade impact

`mvmctl machine resume` of a sealed snapshot now **fails** on a guest built
before the reseed helper existed (#3378). Such a guest reports
`helper_missing`; the resume is refused with the rebuild instruction and its
VMM is stopped. Rebuilding the image with this release and booting it fresh is
the only fix — a snapshot taken from the old image carries the old `/init` and
can never reseed. Before this change the same resume succeeded with a
`VMGenID NOT rotated` warning. A resume through a backend that resumes vCPUs in
place (no sealed snapshot) is unaffected.

## Not verified here

The Linux-only paths (the filter tests, the listening helper, the privileged
suite) were type-checked and linted locally through `just check-gated` and
run on the CI test lanes; they were not executed on a Linux host by hand. The
live Firecracker witness for the resume refusal (W1b.7) is open: no test boots
an image without the helper, snapshots it, and resumes it.

The interrupt, reconcile and admission-record paths are tested against the
real filesystem — an isolated `MVM_HOME`, the real resume and registry locks,
real marker files, a snapshot sealed and verified through the real HMAC path —
with a fake guest agent and, for reconcile, a recording VMM stop in place of
killing a process. None of them has been exercised against a running
Firecracker, and no test delivers a real SIGTERM or SIGHUP to `mvmctl`; the
signal routing is tested by installing the dispositions in a forked child and
by driving the self-pipe servicer.
