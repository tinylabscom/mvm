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

## First live run

The first trusted run after the merge was the release workflow on `main` at
`d530f731b9` (run `35151392843`). On `m1-runner` the host check reported
`supported=true`, the evidence job was skipped, and the documented surface
passed: 75 features, 310 scenarios, 309 passed and 1 skipped, in 39 minutes on
a warm artifact home. Twenty scenarios did not run, each for a reason on the
script's macOS allow-list (4 `@wip`, 5 Firecracker, 6 TLS-tunnel client, 2
bundle fixture, 1 perf-budget host, 1 warm claim, 1 unenforceable wall clock).
#3011 is closed.

## The gate refuses a red macOS lane

A `release.yml` dry run could not show this: `dry_run=true` skips
`initramfs-image`, and the release job requires its success, so every dry run
is refused regardless of macOS — a witness that passes for the wrong reason.

Run `35164778251` instead called the real `e2e-docs.yml` the way `release.yml`
does, from a throwaway branch where only the live macOS job was forced red. On
`m1-runner` the host check passed and the live job failed at the forced step;
the evidence job was skipped rather than substituting; and a job gated on the
release job's own `e2e-docs` clause was skipped. The branch was deleted after.

## Fork isolation

`tests/github_actions_self_hosted_runner.rs` fails if any workflow that can
place a job on `m1`, directly or through a reusable workflow, is started by an
event that runs unmerged code. It was checked against a mutation: adding
`pull_request` to `ci-full.yml` turns it red.

It cannot stop a fork PR that edits a workflow to name the label. Today that is
stopped by the `all_external_contributors` approval policy — a person, not a
mechanism. The mechanism is a runner group limited to selected workflows, which
GitHub documents for the Team plan; the organization is on Free.
