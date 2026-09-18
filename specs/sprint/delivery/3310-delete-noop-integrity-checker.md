# Delete the always-accept integrity checker and a test that cannot pass

Issue #3310; `specs/plans/2026-09-15-the-big-cleanup.md` A3.2, plus A3.3/F2.

`NoopChecker` in `crates/mvm-hostd/src/supervisor/services/binary_integrity.rs`
was a `pub`, ungated `IntegrityChecker` whose `verify` returned `Ok(())` for
any binary, in the module that gates subprocess binary integrity. Its doc said
never to register it in production, and nothing enforced that.

The issue proposed gating it behind `cfg(test)`. Its only caller was
`noop_checker_accepts_anything`, a test asserting that the double accepts
anything, which exercises no production code. Gating would have preserved a
test that tests nothing, so both are deleted. The trait doc no longer names it,
nor the `AlwaysFailingChecker` it also cited, which never existed.

The other two doubles the issue listed, `NoopSubstitution` and `NoopScan`,
were already removed with the host-side scan layer. The adjacent
`#[allow(dead_code)]` sweep the issue suggested folding in (49 sites today) is
not part of this change; it stays open on #3310.

No production behavior changes: the spawn site's checker is only ever
`SignedBinaryChecker`.

## A3.3 / F2: the live-attach test that could never pass

`crates/mvm-hostd/tests/prelaunch_live.rs` carried
`valid_attach_boots_and_agent_reachable`, marked `#[ignore]` with a body of
comments plus `unimplemented!()`. Run with `--ignored` it panicked; otherwise
it was skipped. Either way it proved nothing. The file's own comment said the
refusal test beside it and the unit ladder cover the security logic, so it is
deleted and the module doc now describes the one scenario that exists. A real
attach-and-boot harness would be new feature work, not cleanup.
