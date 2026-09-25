# `mvm-gpu-endpoint` is a shipped per-VM helper

Backing: shipped-source
Validation: cargo run -p xtask -- check-per-vm-host-binaries-sync

The `v0.18.0-rc.2` release train's macOS documented-surface lane ran 329
scenarios and failed one: the GPU-over-vsock witness stopped at `machine start`
with `mvm-gpu-endpoint not found`. The endpoint is a per-VM host process like
`mvm-network-endpoint`, but it was absent from `PER_VM_HOST_BINARIES`, so
nothing built or shipped it: `just build-supervisors` and `just embed` built
`mvm-hostd`'s binaries only, and `release.yml` neither built nor packaged it. A
downloaded `mvmctl` could not start any guest launched with `--gpu`. The
scenario runs only in the release-time documented-surface lanes, so the merge
queue never saw it.

The endpoint is now an `Always`-scoped registry entry — it needs no GPU on the
host, answering through its deterministic stub without a driver — and
`release.yml` builds it on every target and requires it in each tarball, which
`check-per-vm-host-binaries-sync` now counts (seven entries).
`build-supervisors` and `embed` build it beside the other helpers, and the
documented-surface script refuses to start without it.
