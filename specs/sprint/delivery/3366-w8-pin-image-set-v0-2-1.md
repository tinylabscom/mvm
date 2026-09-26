# W8 Wave 0.5a — pin image-set/v0.2.1 and require its initramfs

Backing: shipped-source
Validation: cargo nextest run -p mvm-core image_set

Issue #3366, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md`
Wave 0.5a.

`images.lock` advances from `image-set/v0.1.1` to `image-set/v0.2.1`, the first
set whose signed root carries a per-architecture `initramfs` member. The lock
edit is the one `update-image-pin.yml` produced (run 36215594537): it verified
the root's keyless signature against
`release.yml@refs/tags/image-set/v0.2.1` and rewrote the lock through
`xtask repin-image-lock`. The run could not open this pull request because the
repository does not yet let GitHub Actions create them, so the pushed branch
was opened by hand.

The set was produced in order: the role entered `mvm-core` first (#3740),
`mvm-images` advanced its `mvm` pin to that commit (tinylabscom/mvm-images#30),
and the release built every member on both architectures before publishing.
Root `cbe19a17…d58a`, `mvm_source_commit` `8c5f064f28`, compatibility
unchanged (guest-agent protocol 2, builder cache contract 4).

`current_train()` now requires `Initramfs` on both architectures. A set without
it is refused as incomplete, naming each missing member.
