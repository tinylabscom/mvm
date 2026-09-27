# The Linux first-run lane, proven before a tag depends on it

`release.yml`'s `first-run-smoke` gates `promote-release` with two lanes: HVF on
the self-hosted Apple Silicon runner, and Firecracker on a hosted
`ubuntu-latest` runner. The Linux lane had never run. It only runs on a tag
push, so its first run would have been v0.18.0 itself, and a red lane leaves
the tag staged until a new tag fixes it.

## What was run

A temporary push-triggered workflow on a throwaway branch mirrored the lane on
`ubuntu-latest`. Every job ran `scripts/smoke-fresh-install.sh` unchanged: a
throwaway `HOME`, `env -i`, the checkout's `install.sh` piped into `sh` with its
default bootstrap, then `mvmctl machine run --image alpine -- echo <token>`
with stdin from `/dev/null`.

- **The lane as written, against `v0.18.0-rc.1`.** Install, signature check,
  Firecracker install through passwordless `sudo` under `env -i`, and the
  bootstrap all passed in 28 s. The first command then failed in 2 s with
  `initramfs version mismatch: expected 0.18.0-rc.1, got Some("0.18.0")`,
  the known rc.1 defect that #3510 fixed on main. Nothing failed earlier.
- **rc.1 with that one defect repaired.** Same lane, with rc.1's own initramfs
  repacked under `VERSION` `0.18.0-rc.1` and served through
  `MVM_INITRAMFS_BASE_URL`. **PASS**: install in 39 s, token printed in 4 s.
  The kept `HOME` shows the alpine pull by digest, the chain-signed plan
  entries, and `doctor` reporting the Firecracker backend.
- **main built as the release builds it.** `cargo zigbuild --profile
  release-min --target x86_64-unknown-linux-musl` with the release feature set,
  plus the per-VM host binaries, with the workspace version set to
  `0.18.0-rc.1` so the build resolves published artifacts. Installed into a
  fresh `HOME` and run through `mvmctl bootstrap` and the first command under
  the same harness. **PASS**: bootstrap in 20 s, which installed Firecracker
  v1.17.0 and fetched and verified the image set. Token printed in 3 s.

No fix was needed in the runner setup, the smoke script, `install.sh`, or
mvmctl.

## What is and is not proven

This proves that the hosted runner gives the lane what it needs: `/dev/kvm`
after the `chmod` step, passwordless `sudo` under `env -i` for the Firecracker
install, working registry and GitHub egress, and a Firecracker boot of the
published guest stack. It proves main's install and first-run code works on
that runner.

It does not prove v0.18.0's own artifacts. The branch-built binary ran rc.1's
runtime overlay, initramfs, and kernel. The initramfs `VERSION` comes from
`nix/images/version.nix`, which `just release` rewrites and
`check-runtime-overlay-version` holds equal to the workspace version, so the
rc.1 defect cannot recur unless that gate is bypassed.

## Repeatable before the next tag

The lanes moved into `.github/workflows/first-run-smoke.yml`, which runs on
`workflow_call` (used by `release.yml`, whose job keeps its name, `needs`, and
`if`) and on `workflow_dispatch` with a required `tag`. A maintainer can run the
real lanes against a published candidate before tagging. The self-hosted-runner
guard now reads a matrix `runner:` value as a runner target, so it sees that
both the new workflow and `release.yml` reach the `m1` runner.
