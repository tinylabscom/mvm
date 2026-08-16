# A launch that asked for no host service is not a degraded launch

Twelve consecutive `machine run --image alpine -- /bin/true` launches on a
Linux/Firecracker host all came back `degraded: ["host_services"]`, and the
lane validator refuses any non-empty `degraded` list, so no sample from that
host could enter a launch report. The open question was whether the broker was
simply unregistered on that box — host configuration — or whether the flag was
wrong.

It was the flag.

## The guard answers a narrower question than the flag asks

`RealBrokerRegistrar::register` returns a defused `BrokerGuard`
(`ServicesGuard::None`) in two cases: the plan binds no host service, or the
launch is unadmitted. A registration that is attempted and *fails* returns
`Err` and fails the launch closed — it never reaches the flag. So on the runner
path `is_registered()` is false only when there was nothing to register, and
`degrade_unless("host_services", broker_guard.0.is_registered())` reported
every workload that binds no host service as having lost something.

Nothing binds one by default. `plan.services` is populated only by the
repeatable `--host-service` flag; `synthesize_plan` copies the caller's vector
verbatim and no later code appends to it (`AdmittedPlan` keeps the field
private precisely so nothing can). A plain `machine run` therefore carries an
empty service set, and every such launch on every backend was marked degraded.

`is_registered()` is a two-state answer to a three-state question, and the
missing third state is the request set. `BrokerGuard::services_healthy` takes
it: a launch is healthy when it bound no service, or when the services it did
bind registered. The call site passes the same `services` vector it handed the
registrar a few lines earlier.

Nothing pinned the old behaviour. Every test in the file uses a recording
registrar that returns a defused guard unconditionally, so all of them saw
`is_registered() == false` and none of them looked at `degraded`. The three new
tests cover the three states directly.

The witness that separates the two diagnoses is live, on the host that produced
the twelve degraded samples, with the unpatched binary: the same command with
`--host-service broker.v1` returns `degraded: []`. The broker registers fine on
that box. Nothing about it was misconfigured.

## The dispatch window is over budget, and it is not the disk

The same host measured a `prepared_cold` dispatch window of 545 ms against a
200 ms budget. It is a rotational md-RAID box — `fsync` there costs tens of
milliseconds — so the reasonable first hypothesis was that the overage was
storage tax that would disappear on NVMe.

It is not. Running the identical binary against a tmpfs `MVM_HOME` (RAM-backed,
same host, same artifacts, `prepared_cold` shape preserved and every work flag
still false), 12 samples each:

| phase (p50) | rotational | tmpfs | delta |
| --- | --- | --- | --- |
| `admit_ms` | 453.2 | 105.7 | −347.5 |
| `backend_start_ms` | 539.1 | 506.7 | −32.4 |
| `teardown_ms` | 138.0 | 69.8 | −68.2 |
| `total_ms` | 1183.7 | 757.5 | −426.2 |
| **dispatch window** | **540.9** | **508.1** | **−32.8** |

The ~350 ms of rotational-disk tax is real and it is nearly all in `admit`,
which sits *outside* the dispatch window. Nine `fsync`/`fdatasync` calls occur
across a whole launch (counted with `perf stat`); per-call enter→exit deltas
from `perf record` run 54–298 ms each, and the five that precede the VMM boot
land in the admit span.

On RAM-backed storage the dispatch window is still 508 ms p50 against a 200 ms
budget — 2.5x, versus 2.7x on spinning disk. Inside it, the Firecracker
driver's own debug spans attribute the residual almost entirely to the guest:
process spawn + API socket ~17 ms, API config sequence ~20 ms, `InstanceStart`
~12 ms, and **guest boot to serving agent ~430 ms**. That last span is 89% of
`driver_boot` and does not move with storage class.

No launch report is published from any of these samples: they are still over
budget, and the storage substitute is a diagnostic instrument rather than a
representative host.
