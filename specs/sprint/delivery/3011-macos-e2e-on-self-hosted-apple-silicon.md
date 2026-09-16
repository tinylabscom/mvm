# #3011 — run the macOS documented-surface lane on a self-hosted Apple Silicon runner

No GitHub-hosted macOS image can boot an mvm guest. On arm64 Hypervisor.framework
is nested and reports `HV_UNSUPPORTED`; on Intel `mvm-hvf-supervisor` links as a
stub. The macOS half of the release gate has therefore been a hand-recorded
evidence file, re-recorded before every tag and invalidated by nearly every merge
that touches `crates/`, `nix/` or `scripts/`.

Both macOS jobs in `e2e-docs.yml` now target `[self-hosted, macOS, ARM64, m1]`,
an Apple Silicon laptop registered on this repository. The host check still
probes `uname -m` rather than trusting the label, so the evidence job retires
itself with nothing to flip back.

## What had to change besides the label

Pointing `runs-on` at the runner was not enough on its own. Three things would
have failed the first run, none of them visible on a hosted image:

- **The job budget.** The macOS job inherited the suite's 3600s default under a
  90-minute timeout — the same shape that killed the Linux job three runs
  running. It now pins `MVM_E2E_TIMEOUT_SECS=7200` under 180 minutes, and the
  budget test covers both live jobs instead of Linux only.
- **`sudo` in the zig install.** The runner user is unprivileged, so the
  action's `sudo tar` stops at a password prompt. It now skips when the pinned
  zig is already installed; the operator installs it once.
- **`tomllib`.** The action read the Rust pin with `import tomllib`, which needs
  Python 3.11. The system `python3` on macOS is 3.9. It now reads the pin with
  `awk`.

The job also keeps its suite log — the script deletes its own on exit — and
uploads it with the per-VM console and supervisor logs on every run, green or
red. Nobody logs in to the runner to read a failure.

actionlint rejects unknown runner labels, so `.github/actionlint.yaml` now
declares `m1`.

## Behaviour change to know about

While the runner is offline the host check waits in the queue instead of
reporting `supported=false`. The evidence fallback therefore does not run, and a
release blocks until the runner returns. That is deliberate: the fallback exists
for hardware that *cannot* boot a guest, not for hardware that is switched off.

## Not changed

The job still fetches the published builder image and workload kernel
(`MVM_BOOT_IMAGE=fetch`, `MVM_KERNEL_SOURCE=download`). Stage 0 on HVF landed
on main without a live boot on any backend; switching acquisition in the same
change as the runner would make a red first run ambiguous between the two.
Whether that env can be dropped is a follow-up that this runner can answer.

## Operator steps

Registering the runner, the unprivileged user, the one-time zig install and the
power settings are machine setup, not repository state, and are not recorded
here.
