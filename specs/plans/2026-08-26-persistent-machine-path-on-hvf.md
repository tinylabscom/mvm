# Persistent-machine path fails on HVF after the guest boots

Backing: shipped-source
Validation: check-claim-catalog

## Status

Open — tracked as #2885. Found by the new end-to-end launch suite
(`features/suites/s31_launch_e2e/`) on 2026-08-26, on macOS 26 / Apple Silicon
with the HVF backend.

This is **not** the launch regression fixed alongside it. That one — a cold
universal-initramfs cache silently producing a guest with no runtime overlay —
is fixed and witnessed in #2884. It had masked this defect completely: before the fix no
guest booted at all on this host, so nothing ever reached the persistent path's
post-boot steps.

## Symptom

The README's documented persistent flow starts a guest that really is running,
but the CLI never completes the step:

```
mvmctl machine create e2e-web --image alpine --cpus 2 --memory 512M   # ok
mvmctl machine start  e2e-web                                          # never returns
```

`mvmctl machine ls` meanwhile reports the machine `running` on backend `hvf`,
so the VM itself came up. Against an already-running machine:

```
mvmctl machine exec e2e-web -- uname -s
failed to spawn: I/O error (os error 5)
```

The SDK's live transport rides the same path — `_LiveTransport.for_source`
shells `machine run -d --up-json --name <id> --image <ref> --ttl <n>s` — so
`mvmctl run --mode live` fails with it. That invocation likewise leaves a
running VM behind while the command hangs.

## What is unaffected

Every transient shape works and is witnessed live by the same suite: `machine
run --image`, multi-word argv after `--`, `--env`, `--mount`, `--allow-host`
(egress reaches the target), default-deny without it, guest exit-code
propagation, and `--cpus` / `--memory`. Warm dispatch measures 185–188ms,
inside the 200ms budget. `mvmctl run --mode plan` admits a signed plan without
booting.

So the break is specific to the persistent/named path's post-boot handshake, not
to booting.

## Scenarios that currently fail

Left red on purpose rather than deleted or tagged away. A suite that goes green
by dropping the scenario it cannot pass is how the initramfs regression survived
to a release.

- `s31_launch_e2e/cli_launch_modes.feature` — "the documented persistent machine
  lifecycle operates one guest"
- `s31_launch_e2e/sdk_and_library_modes.feature` — "a runtime-SDK script boots a
  real guest in live mode"

## Where to start

- `os error 5` is `EIO`. It surfaces from the spawn attempt against the running
  guest, so the agent channel is reachable enough to try and not enough to
  carry a command — look at the persistent path's agent socket handoff rather
  than at boot.
- The transient path reaches its agent fine on the same host and backend, so
  diff the two: transient holds the supervisor for the command's lifetime,
  persistent detaches and reconnects.
- `mvmctl machine ls` reading `running` means the liveness probe and the agent
  channel disagree; the shared five-marker probe is the thing that says
  `running`.

## Checklist

- [ ] Reproduce against `machine start` alone, separated from `machine create`
- [ ] Establish whether the agent socket is ever bound on the persistent path
- [ ] Fix the handshake, or fail closed with a message naming the real cause
- [ ] Turn the two red scenarios green without weakening them
- [ ] Confirm `mvmctl run --mode live` recovers with them
