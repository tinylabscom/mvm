# `ops/hetzner/` — provision a Hetzner Cloud test box

Cloud-init scaffolding for a one-shot Linux+KVM host that can run the
full mvm workspace test suite — including the live-KVM smokes that
Lima on macOS can't (the V2 `mvmctl console` data-port path,
real `nix build` of microVM images, the seccomp functional probes,
longer `cargo fuzz` runs).

| File             | Purpose                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| `cloud-init.yaml`| Hetzner first-boot config — installs deps, Rust, Nix, Firecracker, clones the repo, creates the `mvm` user. |
| `run-tests.sh`   | The pinned suite the box runs (fmt, clippy, workspace tests, seccomp functional, cargo deny / audit). |

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
  --user-data-from-file ops/hetzner/cloud-init.yaml
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
2. `cargo clippy --workspace --all-targets -- -D warnings` — full clippy under real x86\_64-linux (catches the aarch64-only `unnecessary_cast` warnings on the seccomp `syscall_nr` table that Lima/macOS misses).
3. `cargo test --workspace --no-fail-fast` — every test, including the Linux-gated ones.
4. `cargo test -p mvm-guest --test seccomp_apply` — the [seccomp functional probes](../../crates/mvm-guest/tests/seccomp_apply.rs) (PR #75) that need `/dev/kvm`-class isolation to validate.
5. `cargo deny check` — supply-chain audit (deny.toml).
6. `cargo audit` — RUSTSEC scan, with the same allow-list as `.github/workflows/security.yml`.

What it deliberately doesn't cover yet:

- **Live-KVM Firecracker smoke** — `mvmctl run` against a real Nix-built rootfs. Requires per-PR setup (a built artifact). Add to `run-tests.sh` once the V2 trait extraction (PR #77) merges and we've decided on a fixture rootfs.
- **`cargo fuzz`** — `fuzz_authed_path` etc. Run by hand: `cd crates/mvm-guest && RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_authed_path -- -max_total_time=600`.

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
(see ADR-002 §W4 — fuzz cadence wants a beefier box than `ubuntu-latest`).
But:

- It's a bigger lift: runner registration, secret management, auto-reconnect.
- We don't yet have data on which checks meaningfully benefit from real KVM.

This `ops/hetzner/` setup is the cheap predecessor: spin a box on
demand, run the suite, capture timings and gaps, *then* decide what
deserves to live in CI.
