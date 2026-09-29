# #3714 — say so when a failed run had no network

The egress-refusal notices report what the per-VM network endpoint refused. A
run with no egress grant and no secret starts no endpoint at all
(`ClaimGuards::spawn_endpoint` omits it), so the guest has no channel to ask
for a destination on and nothing is ever refused — `mvmctl run -- curl
https://example.com` failed with only curl's `Could not resolve host`.

Now a transient `run` / `machine run` that had no network access and exits
nonzero prints one line after its output, through the same notice writer:

```
[mvm] this run had no network access (the default); if the workload needed it, allow destinations with --allow-host HOST:PORT
```

Nothing on exit 0. Under `--json` nothing prints; the summary's new `network`
field is `none` (or `granted`). "No network" is the endpoint's own spawn test —
no outbound admission (egress or peer route) and no secret — so the hint and
the endpoint cannot disagree about whether one was running. A transient run
publishes no port, so ingress never enters into it.

Printed at one site per path (after the outputs are closed, before a nonzero
exit ends the process), so it appears once.
