Backing: shipped-source
Validation: check-sprint-append

# Ad-hoc exec image environment

`mvmctl run --runtime python -- python script.py` reaches the guest through
the streaming exec path. That path inherited the guest agent's environment and
forced only `HOME`; unlike the OCI entrypoint and interactive console paths, it
did not read the image runtime configuration. A bare command therefore could
not resolve an interpreter installed outside the agent's own `PATH`.

The repair keeps ad-hoc exec's existing inheritance semantics, applies the
image environment and working directory through the shared
`WorkloadEnvironment` resolver, and then clears the child command before
installing the resolved values. An unreadable or absent image configuration
retains the previous agent-environment behavior rather than refusing exec.

## Delivery

- [x] Add a regression that executes a bare command available only on the
      image-declared `PATH`.
- [x] Resolve streaming exec through the existing workload-environment builder
      with image values taking precedence over inherited agent values.
- [x] Preserve graceful fallback when the image runtime configuration cannot
      be read.
- [x] Pass the focused tests and repository validation gates.
- [x] Record the repair in the sprint, delivery note, and refactor rollup.

The existing live `host.kv.v1` and `host.time.v1` scenarios remain the
end-to-end witnesses: both launch the official Python runtime and invoke
`python /work/fixtures/kv_roundtrip.py` by its bare image command.
