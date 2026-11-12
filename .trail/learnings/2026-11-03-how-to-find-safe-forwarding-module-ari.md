---
title: "How to find safe forwarding-module and dead-script cleanups, and what the tools wrongly flag"
author: Ari
date: 2026-11-03
branch: main
cost: { minutes: 94, tokens: 1280117 }
id: l-771debb1
scope: repo
status: active
src: agent
touches:
  - crates/mvm-cli/src/doctor/security_checks.rs
  - crates/mvm-client/src/audit/mod.rs
  - crates/mvm-client/src/audit/normalize.rs
  - crates/mvm-client/src/audit/prune.rs
  - crates/mvm-client/src/explain.rs
  - crates/mvm-contract/src/verify.rs
  - crates/mvm-hostd/src/audit/emitter.rs
---

## Decided
Dead forwarding modules and dead scripts can be found mechanically, and removing them is safe when no caller names the path. Delete the file, point the one real consumer (or the parent module's re-export) at the source crate, then run workspace check, clippy and the owning crate's tests.

In the code:
- A forwarding module is a file whose only code is `pub use ...`. Scan every `.rs` file for 3 or fewer non-comment lines containing `pub use`.
- Dead scripts: for each file under scripts/, `git grep -lF <basename>` excluding itself, third_party, CHANGELOG and .trail. Zero hits means unreferenced.
- Landed this way: mvm-hostd broker/control.rs, mvm-runtime driver/spec.rs, and two linux-gate-mvm-vmm-*.sh scripts.

## Tried and ruled out
- `cargo machete --with-metadata` reports `mvmctl` in mvm-conformance as unused. It is a false positive: the manifest documents it as deliberate (the cucumber examples need the library facade linkable). Do not remove it.
- Duplicate-version cleanup: `check-duplicate-majors` already carries a reason for each of the 18 allowlisted crates, all upstream constraints (vmm-sys-util, criterion, gix's sha1, sigstore vs p256). Nothing is unifiable without forking.
- Unreferenced scripts that are really unittest-discovered tests (test_*.py) or operator tooling added days earlier look dead by filename grep but are not. Do not delete them.
- `mvm_runtime::vsock_transport` is a forwarding module but has about a dozen callers, so removing it is a wide migration, not a one-file delete.

## Watch out
- BSD sed on macOS: `sed -i 'expr' file` treats the expression as the backup suffix and fails. Use python for edits.
- `.trail/` is gitignored here, so a note cannot ship with the code change.
- Full-parallel `cargo nextest run -p mvm-hostd` can fail `host_agent_restart::daemon_crash_mid_flight_loses_at_most_one_call_and_preserves_chain` once under load. It passes in isolation, so it is a timing flake, not a regression.
- Pre-commit runs workspace clippy, so a commit takes minutes. Run it as a background command.
