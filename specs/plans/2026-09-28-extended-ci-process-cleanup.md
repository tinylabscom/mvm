# Extended CI process-group cleanup

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS**

Issue: #3773. Worktree: `mvm-3773-extended-ci`.

Scheduled run 36379924152 fails the macOS fresh-install smoke after a child
has exited: the initial SIGTERM to its former group raises EPERM. Preserve
the original outcome when the child has exited; keep permission failures
fatal when the owned child remains alive. A deterministic injected EPERM
regression covers successful exits, failed exits, and a live child.

The same run also fails SDK guest activation on Linux and macOS. PR #3780
already supplied the missing SDK host library; PR #3792 subsequently attached
the universal initramfs to in-process boots. Those changes need live
verification together with this fix before the issue can close.

- [x] Reproduce the process-group failure with deterministic injected errors.
- [x] Preserve exited-child outcomes and retain live-child permission failures.
- [x] Pass host workspace Clippy with warnings denied.
- [x] Pass all 47 focused integration tests and final host workspace Clippy.
- [ ] Pass full workspace tests and Linux builder Clippy.
- [ ] Verify both live SDK lanes and the macOS release lane on the final branch.
- [ ] Pass PR checks, merge, and verify issue closure.

The extracted Python regression failed before the fix and passed afterward.
The Cargo integration suites are pending.

The full integration run passed 46 tests but exposed a one-second cold-start
race in the existing lock-holder fixture; an isolated retry reproduced it.
The fixture now allows five seconds for startup and bounds cleanup at fifteen
seconds, still below the holder's thirty-second lifetime. Both direct lock-holder
attempts passed; the full Rust integration rerun remains pending.

The complete local regression rerun passed 46 tests but exposed an additional
fixture timing mismatch: output-stream cleanup used the default five-second
grace period while asserting total execution below five seconds. The fixture
now requests a one-second grace and allows cold startup within fifteen seconds,
still below the descendant's thirty-second lifetime. Direct compilation of the
updated Rust integration suite passes all 47 tests; the output-stream fixture
also passes directly in 4.28 seconds.

The first complete workspace run failed an unchanged agent execution-deadline
test (4.80 seconds against its tighter bound). A full rerun with four test
threads is pending. The Linux builder cannot finish initialization, so its
required Clippy gate remains blocked. The live Extended CI run passed Apple,
SDK and no-KVM lanes; the documented Linux Firecracker lane remains active.
