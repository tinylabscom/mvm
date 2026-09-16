# Versioned installs, atomic upgrade, the full host-binary set, and an uninstaller

Issues #3270, #3342 and #3271, plan
`specs/plans/2026-09-15-install-lifecycle-and-packaging-polish.md` WS3 and WS4.

## Layout

`install.sh` unpacks each release whole into `<lib>/<n>-<version>/`
(`<lib>` defaults to `<MVM_INSTALL_DIR>/../lib/mvm`), points `<lib>/current` at
it, and makes every `PATH` entry a link through `current`. An upgrade stages
and verifies the new directory, then renames `current` — one step, so `mvmctl`
and the host binaries it spawns are never from different releases. A failure
before the install is reported restores the previous `current`; a failure after
the switch (the new `mvmctl` failing through its `PATH` entry) rolls it back,
including any link of the user's that an entry replaced. Three complete
releases are kept by default (`MVM_INSTALL_KEEP`).

Both the release directory and the install dir hold the full set on purpose.
`std::env::current_exe` reads `/proc/self/exe` on Linux, which resolves every
link, and `_NSGetExecutablePath` on macOS, which does not. The adjacent-binary
resolver therefore looks in the release directory on Linux and in the install
dir on macOS. Canonicalizing `current_exe` in one helper and linking only
`mvmctl` was considered and not done: the adjacency lookup is spread over
`aux_bin`, `hvf_process`, `broker_services_spawn`, the host agent's signer
helper, `artifacts.rs`, `image.rs`, `health_probe` and the dashboard locator,
across six crates, and a missed site would fail only on macOS at VM launch.

## What counts as the installer's

Only directories carrying a marker are the installer's: `<lib>/.mvm-lib`, which
also records the install dir, and `<release>/.mvm-release`, which reads
`staging` until the release is verified and `complete` after. Listing,
numbering, pruning and removal all look at the marker, never at a name. A
library directory that already holds files without the marker is refused. A
staging release left by a crashed run is removed and never counted toward the
kept releases. An entry in the install dir that is a file or directory the
installer did not make is refused, not replaced.

An install from the previous `install.sh` (binaries copied into the install
dir) is carried into `<lib>/<n>-unversioned` by its known names (`mvmctl`,
`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`, `mvm-network-endpoint`,
`assets`), and a run that fails after adopting reuses that directory next time.

## Host binaries

The installer links every executable the archive carries instead of naming two,
so it cannot fall behind `release.yml` again. The test reads
`REQUIRED_HOSTBINS` out of the workflow. Only `mvm-libkrun-supervisor`, which
older releases bundled, is excluded. On macOS each binary is signed with the
profile its role needs: `mvmctl` with `mvmctl.entitlements`,
`mvm-hvf-supervisor` with `mvm-supervisor.entitlements`; the rest touch neither
framework and keep their linker signature.

## Uninstaller

`uninstall.sh` (served beside `install.sh`) and `mvmctl env uninstall`, which
runs the same script embedded in the binary and passes itself as the checker
and its library directory. The previous `env uninstall` removed `/var/lib/mvm`
and `/usr/local/bin/mvmctl` with `sudo` — neither is where `install.sh` puts
anything — so it was replaced rather than extended, and its
`MVM_UNINSTALL_PATH_PREFIX` test hook went with it.

`env uninstall` now runs before CLI startup creates configuration, signing keys
and the `cmd.*` audit envelope, so neither it nor the `--quiesce` check creates
the state directory it may remove, and `--dry-run` leaves no trace. The local
`Uninstall` audit entry is written after the script succeeds, where a kept state
directory will hold it; a script-only uninstall writes none.

When a state directory exists, the script asks mvmctl (`env uninstall
--quiesce`) to refuse if any machine is running, through the same
`running_vms_at` probe the cleanup guard uses, and to stop the host-agent
daemons. A daemon PID is signalled only if its executable is an installed
`mvm-host-agent` by full canonical path; on Linux the check and the signal go
through one pidfd. One unconfirmable PID aborts the whole uninstall. An mvmctl
from before the check exits 2 on the unknown flag, and the script then says to
stop machines and re-run with `--force`. Without a state directory there is
nothing to check.

The state directory goes only with `--purge` or an interactive yes, and only if
it is not `/`, not `$HOME` or an ancestor, and — judged on the resolved path,
never the name as written — is a directory named `.mvm` or holds
`keys/host-signer.ed25519`, `state/log/audit.jsonl` or an `audit/*.jsonl` chain.
That is checked before anything is removed and again immediately before the
state directory is. A symlinked state directory is only unlinked, and an empty
`HOME` counts as unset. The uninstaller exits nonzero when it finds nothing to
remove.

The older-install rule — `mvmctl` must report itself as mvmctl, `assets/` may
hold only the two entitlement profiles — is one shell function,
`unversioned_install_entries`, carried verbatim by both scripts (each is
published standalone, so neither can source the other) and held equal by a
test. `install.sh` checks for conflicts against it before adopting anything.

## `mvmctl env update`

It used to overwrite `mvmctl` and its `RELEASE_HOST_BINS` (including
`mvm-libkrun-supervisor`) in place beside the running binary — on an
`install.sh` install, inside the active release directory. It now refuses there
and points at `install.sh`.

## Not done

- A running persistent builder VM is not part of the refusal; only workload
  machines under `vms/` are.
- The Linux pidfd path of the guarded signal is exercised only on Linux CI.
