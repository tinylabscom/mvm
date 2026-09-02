# Cold-boot guest wall clock

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2956](https://github.com/tinylabscom/mvm/issues/2956)

## Outcome

An RTC-less workload guest consumes the host's positive Unix epoch while the
universal-initramfs agent is still PID 1. The clock is synchronized before
signed-grant timestamp validation, network setup, or workload activation, so
TLS certificate validation observes a current clock on the first cold boot.

## Delivery checklist

- [x] Trace the host epoch from workload cmdline construction to the active PID
      1 and identify the missing universal-initramfs consumer.
- [x] Put strict host-epoch decoding in the shared host/guest contract.
- [x] Reuse the guest agent's existing narrow clock-sync syscall path.
- [x] Refuse missing, malformed, zero, duplicated, or unrepresentable epochs
      before starting the workload control plane.
- [x] Cover accepted epochs, boundary refusals, and kernel-sync failures.
- [x] Pass workspace tests, gated checks, and zero-warning Clippy.
- [ ] Merge the tested pull request and close #2956 through its linkage.
