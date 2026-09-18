# Delete the always-accept integrity checker

Issue #3310; `specs/plans/2026-09-15-the-big-cleanup.md` A3.2.

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
