---
title: Killing one surviving claim-witness mutant quickly
author: Anna
date: 2026-10-16
branch: test/4464-mutation-witnesses-a
touches:
  - xtask/mutation-witness-baseline.json
  - xtask/src/check_mutation_witnesses/runner.rs
  - crates/mvm-agentd/src/vsock/verb_grant.rs
  - crates/mvm-backends/src/fc/host.rs
  - crates/mvm-client/src/admission/mod.rs
  - crates/mvm-contract/src/policy/network_policy.rs
---

## Decided

- Prove a witness with one scoped run, not the whole surface: `cargo mutants -p <pkg> --file <path> --re '<function name>' --timeout-multiplier 5 --minimum-test-timeout 60 --output <scratch>` with `HOME` and `MVM_HOME` pointed at an empty scratch directory and `RUSTUP_HOME` set explicitly (rustup otherwise resolves through the redirected `HOME` and finds no toolchain). `--re` matches the mutant description text, so the enclosing function name is enough. The gate's own flags live in `xtask/src/check_mutation_witnesses/runner.rs` and `types.rs`; mirror them.
- A witness for a `-p <pkg>` mutant has to live in that package. `NetworkPolicy::intercepted_route_hosts` was already asserted in `mvm-runtime`'s spawner tests, and the `&&`→`||` mutant still survived because `cargo mutants -p mvm-contract` never runs them.
- For a function that only reads a Firecracker API socket (`rootfs_from_vm_config`), test it end to end against a `UnixListener` serving one canned `GET /vm/config` response under an isolated `MVM_HOME` (`TestEnv::isolate_mvm_home` + `HOME_TEST_LOCK`, as the neighbouring tests do), rather than extracting the parser: the mutant description keeps its name, and the function-replacement mutants get a witness for free.
- Deleting entries from `accepted_misses` when the gate prints `is now caught — drop it`: `json.dumps(indent=2, ensure_ascii=False)` round-trips the baseline byte for byte, so a scripted removal leaves no formatting diff.

## Tried and ruled out

- `--test-tool nextest` as CI uses it: `.config/nextest.toml` pins `required = "0.9.143"` and an older installed nextest refuses the whole run before the baseline, which cargo-mutants reports as a failed unmutated tree. Plain `cargo test` (the default test tool) is the fallback; the mutants are the same.
- Catching `||`→`&&` in `program_identity_refusal`'s ancestor check with a world-writable fixture: that trips both halves (`uid != 0` and `mode & 0o022 != 0`), so the mutant passes too. The fixture that catches it is owned by a non-root user and writable by nobody else (0o755); as root the test skips, because every file it could create would be root-owned.
- Catching `&`→`|`/`^` in the execute-bit check with a directory or a missing path: `!is_file()` refuses those before the bit test runs. It needs a regular file with mode 0o644, and the assertion must be on the reason (`not an executable regular file`) because the later ownership check refuses the same fixture for a different reason.

## Watch out

- Every scoped run rebuilds the package's tests in cargo-mutants' copy of the tree; four packages in sequence is tens of minutes, not seconds. Run them in the background in one job.
- `cargo mutants` exits nonzero whenever a mutant survives; read `mutants.out/caught.txt` and `missed.txt` under `--output`, not the exit code.
