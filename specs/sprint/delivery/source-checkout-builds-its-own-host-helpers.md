# A source checkout builds its own per-VM helpers

On macOS 26 Apple Silicon, `cargo build --release` followed by
`mvmctl machine run --image rust -it -- /bin/bash` failed with
`mvm-hvf-supervisor not found … run cargo build --bins`. A root `cargo build`
builds the root package, which is `mvmctl` alone; every per-VM helper is a
`[[bin]]` of another package (`mvm-hostd`, `mvm-gpu`). The hint was wrong as
well: a root `cargo build --bins` builds no helper either.

The helpers stay separate executables — the process moat and the HVF
supervisor's own code signature carry security claims — but a separate
executable no longer means a separate command:

- `mvmctl` declares `aux_bin::allow_helper_builds_from_source` at startup when
  its compiled channel permits automatic builds. A release build never
  declares it, and a library embedder is refused even if it were declared.
- When a helper that belongs in the running binary's own `target/<profile>/`
  is missing, or any source recorded in its cargo dep-info file (plus
  `Cargo.lock`) is newer than it, the resolver announces the build, runs
  `cargo build [--release] -p <package> --bin <helper>` into that directory
  under a status line showing cargo's progress, signs it with its entitlement
  (the HVF and libkrun supervisors: `com.apple.security.hypervisor`), then
  probes its contract version. Freshness is read from the dep-info rather than
  by invoking cargo on every spawn, which would also have rebuilt helpers the
  `just` recipes had already made current under a different cargo config.
- This covers the probed helpers (`resolve_verified`: HVF and libkrun
  supervisors, network and GPU endpoints) and the unprobed ones
  (`resolve_subprocess_bin_to_spawn`: host agent together with its signer
  helper, broker, audit signer). An env override, `MVM_AUX_BIN_DIR`, and a
  binary outside its checkout's `target/` are never built over.
- HVF availability (`is_available`, used by backend selection and the egress
  validation) counts a helper this process would build as available.
- The macOS signing code moved from `mvm-runtime` to `mvm_vmm::host::codesign`
  so the resolver can sign what it builds; `mvm_runtime::codesign` re-exports
  it and keeps the backend-dependent `collect_sign_targets`.

Live, in a throwaway `MVM_HOME`, with `target/release/mvm-hvf-supervisor`
deleted and `cargo build --release --features dev` at the root:

```
[mvm] mvm-hvf-supervisor has not been built for this binary yet; building it from this checkout with `cargo build --release -p mvm-hostd --bin mvm-hvf-supervisor`.
[mvm] Building mvm-hvf-supervisor — done in 4m17s
[mvm] mvm-network-endpoint has not been built for this binary yet; building it from this checkout with `cargo build --release -p mvm-hostd --bin mvm-network-endpoint`.
[mvm] Building mvm-network-endpoint — done in 40s
```

and the built supervisor carried an ad-hoc signature with the hypervisor
entitlement.
