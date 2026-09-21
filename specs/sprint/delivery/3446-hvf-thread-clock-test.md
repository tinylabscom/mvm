# HVF vCPU accounting test no longer races Mach teardown

Issues #3446 and #3452 describe the same macOS-only flaky assertion. The test
correctly required a busy vCPU thread to publish non-zero CPU time before it
exited, but then also required a retained Mach thread send right to become
unreadable immediately after `JoinHandle::join`. macOS may keep that thread
object readable while the send right exists, so the second assertion depended
on kernel teardown timing rather than product behavior.

The witness now retains the production contract only: the vCPU samples its own
clock while alive, publishes the duration on its exit path, and the host can
read that published non-zero value after the join. No production accounting
code or trust boundary changes.

Validation on native Apple Silicon macOS:

- focused `a_vcpus_time_survives_the_thread_that_earned_it` regression: pass;
- `cargo fmt --all --check`: pass;
- `cargo check --workspace`: pass;
- `cargo clippy --workspace -- -D warnings`: pass;
- serial workspace product tests: pass; the monolithic run reproduced the
  pre-existing final `xtask` nested-Cargo harness exit, and the complete
  isolated `xtask` suite passed (10 library, 812 binary, 1 integration test);
- workspace documentation tests: pass;
- all 74 repository policy and structure gates: pass.
