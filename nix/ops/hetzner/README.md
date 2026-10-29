# `ops/hetzner/` — provision a Hetzner Cloud test box

Cloud-init scaffolding for a one-shot Linux+KVM host that can run the
full mvm workspace test suite — including the live-KVM smokes that
a macOS host can't (the `mvmctl machine console` data-port path,
real `nix build` of microVM images, the seccomp functional probes,
longer `cargo fuzz` runs).

| File             | Purpose                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| `cloud-init.yaml`| Hetzner first-boot config — installs deps, Rust, Nix, Firecracker, clones the repo, creates the `mvm` user. |
| `run-tests.sh`   | The pinned suite the box runs (fmt, clippy, workspace tests, seccomp functional, cargo deny / audit). |
| `job-cleanup.sh` | The always-run last step of every CI job that can land on the self-hosted KVM runner. |
| `disk-sweep.sh` + `mvm-disk-sweep.{service,timer}` | Hourly box-side sweep of stale test and runner temporary directories. |

## Working on the shared box

The self-hosted KVM runner (`mvm-hetzner`) is one persistent machine shared
by CI and by every person and agent who logs in to it. Nothing on it is
cleaned up for you between sessions, so leave it as you found it.

**By hand.** Work only inside a private directory, `/srv/mvm/<name>`, with
`<name>` unique to you and your task (for example `/srv/mvm/alice-4198`). Put
the checkout, `CARGO_TARGET_DIR`, `MVM_HOME` and `TMPDIR` under it, never under
`/root` or directly in `/tmp`. `/srv/mvm` is the large data disk; the root
disk is small. Before you finish, stop every VM and process you started, by
PID (`mvmctl machine stop`, then `kill <pid>` for anything left; never
`pkill` by pattern on this host, because other sessions' processes match
too), then `rm -rf /srv/mvm/<name>`. Nothing else on the box is yours to
delete.

**In CI.** Every job that can run on the KVM pool points `HOME`, `MVM_HOME`
and `TMPDIR` at `$RUNNER_TEMP/mvm-w-<run>-<attempt>-<shard>` and ends with an
`if: always()` step running `job-cleanup.sh`. That step kills, by PID, every
process whose command line names a path the job owned (a VMM started through
`sudo setsid` is outside the job's process tree, so the runner does not reap
it), then removes the isolated directories and the extracted test archive.
`RUNNER_TEMP` is disk-backed; `/tmp` is a small tmpfs on the GitHub-hosted KVM
runner and cannot hold the duplicate OCI trees some live witnesses prepare. The
workspace `target/` stays warm for the next job until it passes
`MVM_TARGET_BUDGET_GIB` (40 GiB). `tests/github_actions_self_hosted_runner.rs`
fails the build when a job that can reach the pool lacks that last step.

**Safety net.** `mvm-disk-sweep.timer` runs `disk-sweep.sh` hourly. It removes
test and temporary directories in `/tmp` (`.tmp*`, `tmp.*`, `mvm-w-*`,
`mvm-workspace-*`, `mvm-sock-*`, `mvm-test-*`), and, while no runner job is
running, the runner's `_work/_temp` and `.mvm-test` leftovers, but only when
no process has anything under the directory open and nothing in it changed in
the last six hours. It never kills a process: a VMM that outlived its job is
logged as `leaked-vmm` for a person to decide. Every removal is logged to the
journal and to `/var/log/mvm-disk-sweep.log`. It does not touch `/srv/mvm`.

Install or update it on the box, from a checkout of `main` in your private
directory there:

```sh
cd /srv/mvm/<name>/mvm
install -m 755 nix/ops/hetzner/disk-sweep.sh /usr/local/sbin/mvm-disk-sweep
install -m 644 nix/ops/hetzner/mvm-disk-sweep.service \
  nix/ops/hetzner/mvm-disk-sweep.timer /etc/systemd/system/
DRY_RUN=1 /usr/local/sbin/mvm-disk-sweep | tail
systemctl daemon-reload && systemctl enable --now mvm-disk-sweep.timer
```

`journalctl -u mvm-disk-sweep` shows each run.

## Pick the right instance shape

Hetzner Cloud doesn't expose `/dev/kvm` on every instance type:

| Line | KVM? | Notes                                                                 |
| ---- | ---- | --------------------------------------------------------------------- |
| CCX  | ✅   | Dedicated x86\_64 CPUs — the default recommendation. CCX23 (4 vCPU, 16 GB) is plenty. |
| CAX  | ✅   | Dedicated ARM CPUs — cheaper; `cloud-init.yaml` detects arch at boot. |
| CPX  | ❌   | Shared CPU — no nested virt. Don't use.                               |
| CX   | ❌   | Same.                                                                 |

For dedicated bare metal (AX line) `/dev/kvm` is always available, but
that's overkill for test runs.

## Provision via `hcloud` CLI

```sh
# One-time: create / select an SSH key in the Hetzner web console
# (or via `hcloud ssh-key create`). The key is what the cloud-init
# `users:` block will trust on the new box.

# Bring up the box. Adjust --type / --location to taste.
hcloud server create \
  --name mvm-test-1 \
  --type ccx23 \
  --image ubuntu-24.04 \
  --location nbg1 \
  --ssh-key <your-key-name> \
  --user-data-from-file nix/ops/hetzner/cloud-init.yaml
```

Cloud-init takes ~3–5 minutes to finish. Watch with:

```sh
ssh root@<server-ip> 'cloud-init status --wait'
```

When `status: done`, you're good.

## SSH in and run the suite

```sh
ssh root@<server-ip>
su - mvm
bash ~/warm-cache.sh        # one-time, ~5 min on CCX23 (cargo fetch + build)
bash ~/run-tests.sh         # full suite; stops at first failure
bash ~/run-tests.sh --continue   # power through failures
```

The MOTD prints these paths on every login.

## What the suite covers

`run-tests.sh` is the canonical pinned set of invocations:

1. `cargo fmt --all -- --check` — formatting.
2. `cargo clippy --workspace --all-targets -- -D warnings` — full clippy under real x86\_64-linux (catches Linux-only and arch-gated warnings, such as `unnecessary_cast` in the seccomp syscall table, that a macOS host misses).
3. `cargo test --workspace --no-fail-fast` — every test, including the Linux-gated ones.
4. `cargo test -p mvm-agentd --test seccomp_apply` — the [seccomp functional probes](../../../crates/mvm-agentd/tests/seccomp_apply.rs) (PR #75) that need `/dev/kvm`-class isolation to validate.
5. `cargo deny check` — supply-chain audit (deny.toml).
6. `cargo audit` — RUSTSEC scan, with the same allow-list as `.github/workflows/security.yml`.

What it deliberately doesn't cover yet:

- **Live-KVM Firecracker smoke** — `mvmctl run` against a real Nix-built rootfs. Requires per-PR setup (a built artifact). Add to `run-tests.sh` once the V2 trait extraction (PR #77) merges and we've decided on a fixture rootfs.
- **`cargo fuzz`** — `fuzz_authed_path` etc. Run by hand: `cd crates/mvm-agentd && RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_authed_path -- -max_total_time=600`.

## Tearing the box down

```sh
hcloud server delete mvm-test-1
```

The cloud-init isn't designed for long-lived state — treat each box
as ephemeral.

## When to bump

| Bump                            | Trigger                                                                 |
| ------------------------------- | ----------------------------------------------------------------------- |
| `cloud-init.yaml::FC_VERSION`   | When `crates/mvm-core/src/config.rs::FC_VERSION_DEFAULT` moves.         |
| `cloud-init.yaml::packages:`    | New system dependency in the workspace (rare).                          |
| `run-tests.sh::cargo audit --ignore` | Same advisory exclusions as `.github/workflows/security.yml`. Keep them in sync. |

## Why a separate doc and not just CI?

A self-hosted GitHub runner on Hetzner is the eventual home for this
(see ADR-001's claims ledger — fuzz cadence wants a beefier box than
`ubuntu-latest`).
But:

- It's a bigger lift: runner registration, secret management, auto-reconnect.
- We don't yet have data on which checks meaningfully benefit from real KVM.

This `ops/hetzner/` setup is the cheap predecessor: spin a box on
demand, run the suite, capture timings and gaps, *then* decide what
deserves to live in CI.
