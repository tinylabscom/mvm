# Ad-hoc exec image environment

Issue #2951 exposed a split in the guest's execution contract. OCI entrypoints
and console sessions resolved the image's declared environment, while
streaming ad-hoc exec inherited only the guest agent environment. The official
Python image installs its interpreter in `/usr/local/bin`, so a documented
`run --runtime python -- python ...` launch exited 127 even though the same
image's entrypoint could find Python.

Streaming exec now uses the existing `WorkloadEnvironment` builder. Agent
variables are inherited first, image variables override them, `HOME` remains
forced to the writable workload home, and the image working directory is
honored. The spawned shell receives only this resolved environment. If the
runtime configuration is absent or unreadable, exec logs the non-sensitive
read error and falls back to the prior inherited environment.

The focused regression creates an executable that is reachable only through
the image-declared `PATH` and proves a bare command runs. A second regression
proves an unreadable configuration retains the agent's `PATH`. The existing
live service-plane scenarios provide the end-to-end Python witness.

Validation:

- `cargo test -p mvm-agentd exec_stream::tests`
- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace` (all unit and integration targets passed; the
  transient `mvm-cli` rustdoc artifact lookup was rerun directly and passed)
- `cargo test -p mvm-cli --doc`
- `cargo check -p mvm-conformance --test conformance --features bdd`
- `cargo run -p xtask -- check-declared-backing`
- `cargo run -p xtask -- check-sprint-append`
- `cargo run -p xtask -- check-single-workload-env`
- `cargo run -p xtask -- check-no-spec-refs-in-comments`
