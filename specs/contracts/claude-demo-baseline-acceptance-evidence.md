# Claude demo baseline acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles the acceptance criteria of [#4508](https://github.com/tinylabscom/mvm/issues/4508)
against landed code and the runs the issue's comments record. The issue owns
status. "Witnessed" names a test that exists and passed on current main
(`cargo nextest run -p mvm-cli --test agent_workload_example`, 7 passed); every
limit is stated rather than implied. Runs recorded only in issue comments were
made on a contributor machine with scratch evidence under `/tmp`, which no longer
exists, so they are historical and were not reproduced for this document.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| Task-local current CLI, global install untouched | Recorded run: an offline `--locked` build of `mvmctl` into a task-local target directory, ad-hoc signed with `assets/mvmctl.entitlements`, binary reporting 0.24.0 from a clean source revision | Recorded in the issue comments only; no test pins it and it was not reproduced. |
| Revision, guest architecture, base-image set, runtime inputs, toolchain | Recorded run: source revision `4a6143996fba21c31605a0a35266f00a8155d938`, Darwin arm64 / macOS 26.6.2, native HVF; builder probe reported Linux aarch64, Nix 2.31.5, Firecracker 1.13.2, no `/dev/kvm`; seal carries image `cdeefef561df65b783397febf6b79df24038bb37b45ce6cb65130b471b2f0359` and kernel `0f97f109154a173352c07db223ecff48d44b38514b500f39cd9897701dbac0b6` | Revision predates #4524. Runtime inputs came from a source-mode bootstrap (`MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build`); the signed release path is not witnessed (below). |
| Approved builder VM boundary; no host Nix, no Lima | Recorded run: the prod image build ran through the HVF builder VM (`machine build --flake examples/agent-workload --prod --no-persistent-builder --builder hvf`, exit 0, rootfs sha256 `af266f4277eb419aee040471fad1c11a8b1fc44f476be970b27889eba5b3c931`, sealed, rootless UID 901). Host-Nix and Lima absence is a repository invariant enforced elsewhere (`xtask check-no-vz`, the host-Nix rule in `CLAUDE.md`) | The invariant is not re-proved by this issue's run. An earlier builder-shell `EINVAL` did not reproduce and its root cause is not established. |
| Isolated mutable state; temporary outputs outside the checkout | Recorded run: task-local `MVM_HOME`, with only the builder cache linked to the shared one under operator approval; evidence kept under `/tmp` | Operator-approved sharing of the builder cache means the state was not fully isolated. No test witnesses it. |
| `examples/agent-workload` offline smoke prints placeholder-present and the pinned `claude --version` | Recorded run on native HVF with explicit operator permission: output `agent-workload smoke: placeholder-present` and `2.1.273 (Claude Code)`, exit 0, no real credential and no model request. Static side witnessed by `agent_workload_smoke_uses_the_per_call_input_path`, `agent_workload_declares_a_placeholder_secret_and_tight_egress` and `both_agent_examples_reuse_the_one_pinned_binary_recipe` | The boot was not reproduced after #4524. The KVM box was not used: the run is an HVF one and the issue does not ask for Firecracker. It proves startup only. No portable bundle, live network enforcement or model access is demonstrated. |
| Audit chain verified, exact commands and results captured | Recorded run: `mvmctl trust audit verify sha256:e7c71d1b241d24bef201e2039741544edc098d4fb281cf6c9cb48b541408b983 --json` returned VERIFIED, 10 events, one seal, no late entries, exit 0; signed entries cover plan admission, launch, exit, a 151-chunk transcript anchor and `session.sealed` | The verdict file and chain tail were scratch artifacts and are gone. Verifier behaviour has its own tests (claim 8); this criterion rests on the recorded run. |
| 2048 MiB sizing resolved against the 4096 MiB recommendation, with no capacity claimed from metadata | #4524 aligned the flake, `mvm.toml` and both IR documents at 4096 MiB and 2 vCPUs. Witnessed by `agent_workload_uses_the_same_initial_resources_for_smoke_and_real_requests`; the README states the figure is an allocation, not measured capacity | Sizing is resolved. Measured capacity is deliberately not claimed. The recorded smoke ran with `--memory 4G`, but no run measured headroom under a real workload. |

## What closes this

The sizing criterion is met by a passing test. The remaining criteria were met by
a recorded run that was not reproduced on current main, and the issue's own
latest comments say fresh baseline and runtime witnesses are outstanding: the
signed `mvm-guest-bins-v0.24.0.tar.gz` runtime returns HTTP 404, so a release
binary cannot yet assemble its guest runtime. A fresh native smoke plus audit
verification on current main, against a published runtime asset, is what closes
the issue.
