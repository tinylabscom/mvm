- [~] SDK host-service sidecar boot failure — **plan 325**. Guest-console
      evidence showed that the dedicated SDK disk was also entering the
      generic user-volume manifest, whose allowlist correctly rejects
      `/mvm/sdk`; PID 1 then exited and both HVF and libkrun reported a
      downstream 30-second agent-readiness timeout. The launcher now partitions
      the reserved disk from user volumes, both guest boot paths mount it
      read-only through `mvm.sdk_dev`, and legacy block discovery excludes it
      from ordinary user disks. A follow-up live run exposed that invoking the
      worktree binary from the main checkout paired the fixed host with the
      main checkout's stale guest `/init`; executable-path source discovery now
      keeps worktree host and guest artifacts together. A second attempt proved
      the source key changed but exposed Cargo outputs shared across worktrees;
      cross-build target dirs are now source-isolated and both affected cache
      generations are advanced. OCI injection also pre-creates `/mvm/sdk`
      before sealing, so fixed PID 1 does not attempt to mutate a read-only
      dm-verity root. Agent-readiness failures now print a bounded, PII-redacted
      guest-console tail before transient teardown removes the evidence.
      The captured guest console then exposed a second, independent issue:
      `/wheels` is outside the guest volume allow-roots (`/data`, `/work`,
      `/mnt`). Directory-share parsing now rejects that path during host
      preflight instead of booting a guest that can only panic and time out.
      Hermetic BDD coverage exercises the corrected `/mnt/wheels` plus SDK
      sidecar attachment and proves the user mount remains in `mvm.uvols`
      while `/mvm/sdk` does not; a companion scenario proves `/wheels` fails
      before boot. The host-service follow-up builds the host agent and signer
      helper beside source-built `mvmctl`, threads the exact signed-plan service
      set into the broker, implements `host.time.v1::now`, and adds a framed
      broker/SDK BDD round trip. The original Python-wheel command now passes on
      native HVF. Focused regressions and the full 176-scenario/732-step BDD
      suite pass; native libkrun acceptance remains.
