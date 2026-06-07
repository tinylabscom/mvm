Update the mvm multi-tenant agent-workload worker fleet design to include MINIMUM RUNTIME policy.

Constraints:
- Enforce minimum runtime in the HOST AGENT (not in guest metrics).
- No SSH. Use vsock guest agent for work state and sleep-prep ACK.
- Preserve mounted drive model: rootfs immutable, config+secrets via ro drives, data via rw drive.

Implement:

1) Policy fields (per WorkerPool with instance inheritance):
- min_running_seconds
- min_warm_seconds
- drain_timeout_seconds
- graceful_shutdown_seconds
- allow override on memory pressure and manual force flags

2) State tracking (per instance):
- entered_running_at
- entered_warm_at
- last_busy_at / last_work_at
- eligible_for_warm_sleep booleans derived from policy + timestamps

3) Reconcile integration:
- If desired state requests sleep/stopped but min runtime not satisfied:
  - defer transition (do not violate) unless memory pressure override triggers
- Ensure idempotence and auditable decisions:
  - write audit log entries when deferring or overriding

4) Sleep/wake correctness with mounted drives:
- On run/wake:
  - attach config drive (ro) and secrets drive (ro, refreshed)
  - guest agent loads config and copies secrets into tmpfs
- On sleep:
  - agent requests sleep_prep via vsock
  - guest must ACK only after the agent workload is idle/checkpointed and data flushed
  - enforce drain_timeout_seconds

5) Documentation:
- Explain minimum runtime semantics, exceptions, and how it supports the agent workload's safety/security.

Do not add unrelated features.