# The first-run smoke boots twice, then once with the SDK

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test smoke_fresh_install --test release_assets

The release gate's fresh-install smoke booted one microVM. That cannot see a
class of bug in how a release binary uses the artifacts it downloads. It needs
the runtime overlay, the initramfs and the SDK sidecar from the pinned image
set to carry a `VERSION` equal to its own. The first boot runs whatever it has
just fetched, so a mismatch shows only later: the overlay is fetched again on
every boot, the initramfs fails from the second boot on, and the SDK sidecar
is refused. CI's e2e lanes run from a source checkout, which builds all three
locally, so they miss it as well.

## What changed

- **A second boot.** After the first command, `scripts/smoke-fresh-install.sh`
  runs `mvmctl machine run --image alpine -- echo <token>-second` from the same
  `HOME`, with its own budget (`MVM_SMOKE_SECOND_RUN_BUDGET_SECS`, default
  300 s). It must print its token.
- **Nothing fetched again.** After the first and second boots the smoke records
  every file under `~/.mvm/cache/runtime-overlay` and `~/.mvm/cache/initramfs`
  as inode, size and path. Both installers stage a new directory and rename it
  into place, so a re-fetch gives every file a new inode even when the bytes
  are identical. A file the first boot cached that the second replaced or
  removed fails the smoke and is named. Dotfiles are left out: they are the
  resolver's validation stamps and staging files, which it may rewrite without
  fetching. A first boot that caches nothing fails too, because otherwise the
  check would have nothing to compare.
- **An SDK boot.** The documented way to give a workload the SDK needs no
  Python or npm: `--host-service host.time.v1` binds an SDK-served host service,
  and a release binary downloads the published sidecar on a cold cache. The
  third boot runs that with `sh -c` and prints its token only if the guest can
  read `/mvm/sdk/lib/libmvm_host_services.so`. Its budget is
  `MVM_SMOKE_SDK_RUN_BUDGET_SECS`, default 300 s.
- The transcript times every boot, keeps both cache listings beside itself, and
  keeps each boot's console and supervisor logs. `first-run-smoke.yml`'s job
  timeout rose from 45 to 50 minutes so that it stays above the summed default
  budgets, and a test holds it there.

## What was run

On macOS 26 Apple Silicon (HVF), with `just smoke-fresh-install`:

- `v0.18.0-rc.1`: installed in 40 s, then the first command failed in 4 s with
  `initramfs version mismatch: expected 0.18.0-rc.1, got Some("0.18.0")`, the
  known rc.1 defect. That is the expected result.
- `v0.18.0-rc.2`: **PASS**. Installed in 44 s, first boot 3 s, second boot 0 s
  with all eleven overlay and initramfs files keeping their inodes, and the SDK
  boot 2 s. It downloaded the musl sidecar and the guest found the library.
- In rc.2's kept `HOME`, the cached overlay's `VERSION` was rewritten to
  `0.18.0` before another boot. mvmctl fetched the overlay again without saying
  so and still printed its token. The inode comparison named all six replaced
  overlay files. This is the case the second boot now fails, and a token check
  alone would have passed it.
- `v0.18.0` has no published `mvmctl-aarch64-apple-darwin.tar.gz`, so it could
  not be installed.

The Linux Firecracker lane has not run the new steps.
