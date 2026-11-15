# Live adversarial workload probes (HVF/Firecracker) — what the 2101 probe run learned

**Date:** 2026-11-13 · **Context:** closing #2101 (workload capability posture) with elevation-attempting in-guest probes.

## Working recipe

- Probe shape: `bin/dev machine run --name <probe> --profile dev --image python:3.12 --cpus 1 --memory 256M --timeout 240 --hypervisor hvf|firecracker -- /bin/sh -c '<probe>'`. Use a **named** run (transient cold boot) so a warm-pool standby built before your edit can't serve stale guest code. `python:3.12` (Debian) is the right probe image: it ships nine real setuid binaries, so setuid inertness is exercised against actual setuid-root executables. Alpine ships none.
- Base64 the probe script (`base64 -d | /bin/sh` as the guest command) to survive multiple quoting layers (ssh → bash -lc → bin/dev → mvmctl → guest sh).
- On macOS HVF, after changing guest sources, if launch refuses with "no source runtime matching this checkout" / "prepared runtime overlay differs from the selected archive": a stale `cache/runtime-overlay/<version>` dir in the pair home (`~/.local/state/mvm/pairs/<digest>/home`) holds bytes for an older source fingerprint. Delete that dir and relaunch with `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build`. A full cold guest-runtime build takes ~25 min on an M-series; the launch cache re-seeds cheaply afterwards.
- If HVF then refuses with "existing HVF runtime evidence requires confirmed cleanup before reuse", the instance state is wedged from a failed run. Don't hand-delete dirs (races the host-agent daemon); just use a **fresh machine name**.
- The `STALE embedded host binaries` cargo warning after `payload::refresh` is about host-side helpers; guest-side mvm-agentd changes still ride the source-built runtime. Harmless for privilege-posture probes.

## Firecracker on the Lima test VM (owner-approved KVM provider)

`rvproxy-firecracker-lima` (Lima, vz, nestedVirtualization, Ubuntu 24.04 arm64) works end to end for Firecracker probes and avoids GCP auth/billing entirely:

- Needs the repo-pinned Firecracker: `scripts/locked-firecracker.sh tarball|tarball_sha256|binary|binary_sha256 aarch64` (GitHub release URL is `https://github.com/<repository-shorthand>/releases/download/<version>/<tarball>`; the lock's `tarball` field is just the filename). Install `firecracker` + `jailer` to /usr/local/bin; the VM's preinstalled v1.14.1 fails the pin.
- mvmctl refuses Firecracker as **root**, and launch needs a **systemd user session** for cgroup delegation — the repo pattern is `.github/actions/user-session/action.yml`: `loginctl enable-linger <user>`, `systemctl start user@<uid>.service`, wait for `/run/user/<uid>/bus`, then run with `XDG_RUNTIME_DIR=/run/user/<uid>` and `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus`. Same wrapper works for ad-hoc KVM hosts.
- Admission additionally rejects the runtime namespace if any ancestor dir is group/other-writable and not sticky (`mvm-runtime/src/runtime_evidence/namespace.rs`). Lima's `~/.local` chain defaults to `drwxrwxr-x`; `chmod g-w` the ancestors.
- Launch long probe builds with `nohup ... &` writing to a log **inside the VM**, and poll the log with short `limactl shell` calls — a 3600s client timeout kills a streaming foreground run mid-build and the output is lost.
- The VM's 40GB disk fills fast (guest-agent-build target ~5GB, OCI trees ~3GB); `rustup toolchain uninstall` old nightlies to free space. Build dirs on the virtiofs mount persist across VM restarts.
- Full first-build (mvmctl + guest runtime) in the VM: roughly an hour under host contention; later boots are seconds.

## GCP runner notes

- `just lab::gcp-kvm --dry-run ...` does NOT forward `--dry-run` to the script (the recipe inserts `--` before the program) — call `scripts/run-gcp-kvm-test.sh --dry-run -- ...` directly or it creates a real billable VM named `mvm-test-...`.
- If a script instance outlives a killed client, delete it immediately with the printed `gcloud compute instances delete` command.
- gcloud SSO sessions expire; "Reauthentication failed ... non-interactive" needs an interactive `gcloud auth login` by the operator — the Lima path above is the fallback.

## What a green probe looks like (both backends, after the six-site strip)

uid 901; `CapInh/CapPrm/CapEff/CapAmb = 0`; `CapBnd = 0x2000020` (agent's narrowed set, inherited residue — inert under NoNewPrivs); `NoNewPrivs: 1`; setuid exec exits non-zero without euid change; `unshare -r`/`mount`/`chown 0:0`/`security.capability` plant all EPERM; `/etc/passwd` read-only; `/proc/1/root` denied.
