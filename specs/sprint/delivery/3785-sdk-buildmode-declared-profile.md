# SDK live launches report build_mode from the declared profile

Backing: shipped-source
Validation: cargo test -p mvm-hostlib (73 tests, including
`declared_build_mode_follows_the_dev_guest_grant`); live repro below.

Issue #3785's fix (#3792) made the in-process `machine.run` boot attach the
universal initramfs; with the machine actually booting, the v0.18.2 release's
macOS e2e lane exposed the next layer: the run reply's `build_mode` resolved
from host accessibility (`runtime_meta.accessible`), and the local boot is
always unsealed — so a plain `run --mode live` machine reported `dev` and the
SDK's client-side DevOnly guard let `files.write` through, failing the suite's
"refused DevOnly surfaces under a ProdSafe grant" scenario (the launch exited
where the suite expects a `SandboxDevOnly` refusal).

## The fix

`build_mode` now answers the admitted profile's `dev_guest` grant — the same
declaration the guest agent's own DevOnly refusal keys on. Only a profile
whose grants carry the dev guest (`dev`, `permissive`) reports `dev`; no
profile, an unrecognised name, or a profile without the grant reports `prod`,
even though the local boot itself is unsealed. Accessibility and the guest's
dev profile answer different questions; the guard's contract is the declared
profile. Fail closed, matching the host library's existing
"no accessible runtime is dev" test, now profile-driven.

## Evidence

- Unit: `declared_build_mode` maps `dev`/`permissive` to `dev` and
  `standard`/`restrictive`/unknown/absent to `prod`.
- Live on this Mac, `crates/mvm-conformance/fixtures/e2e/sandbox_script.py`
  through `mvmctl run --mode live`: plain → `SandboxDevOnly` raised at
  `files.write` (the suite's expected refusal); `--profile dev` → exit 0.
