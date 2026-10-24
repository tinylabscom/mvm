---
title: Native local demo
description: Prepare a pinned image once, then run a bounded transient microVM without mvmd.
---

This demo runs a real Linux microVM on your own machine through `mvmctl`.
It does not use `mvmd`, a remote API, provider credentials, persistent volumes,
or the website's browser-based QEMU-Wasm demo.

MVM still starts its normal local runtime helpers as needed; those are not a
separately deployed fleet service and require no manual daemon setup.

Use a supported host: macOS 26+ on Apple Silicon, or Linux with `/dev/kvm`.
Install the published CLI using the [installation guide](/getting-started/installation/).
No source build, host Nix, or Docker is needed for this image-backed workflow.

## Prepare once

Run these commands in the same terminal:

```bash
mvmctl doctor --workflow cli-run
mvmctl bootstrap
mvmctl image pull alpine
MVM_DEMO_IMAGE="$(mvmctl image inspect alpine --digest-ref )"
printf '%s\n' "$MVM_DEMO_IMAGE"
```

Preparation downloads and materializes the runtime and OCI image. It can take
longer than launching an already-prepared workload; do not include it in a
startup-latency claim.

If a preparation command fails, resolve that error before launching. Do not
continue by disabling a verification or admission check.

The tag `alpine` is used only to discover an image during preparation.
`--digest-ref` prints its cached, canonical digest-pinned reference for this
host's architecture. Subsequent launches use that reference rather than
re-resolving a moving tag. Keep the terminal open, or save the printed reference
to reuse it later. Preparing a newer image does not update a previously saved
digest.

If the prepared source was already pinned to a multi-architecture index,
`--digest-ref` preserves that index pin; it does not silently replace it with
the selected platform manifest's digest.

A digest identifies content; it does not authenticate its publisher.
This is a local **development-profile** demonstration, not a sealed production
workload or a replacement for the production OCI trust policy. Runtime artifact
verification and normal launch admission remain enabled.

## Launch with one command

```bash
mvmctl machine run --name local-demo --profile dev \
  --image "${MVM_DEMO_IMAGE:?Run preparation in this terminal first}" \
  --cpus 1 --memory 256M --timeout 30 \
  -- /bin/sh -c 'printf "hello from a microVM\n"; /bin/uname -s'
```

The workload output is:

```text
hello from a microVM
Linux
```

The command exits with the workload's exit status. This named foreground run
is transient: it boots cold, does not request a warm standby, and tears down
the workload VM on exit. It does not create a persistent machine spec.
The name makes the run easy to identify; if `local-demo` is already in use,
choose another unused name rather than stopping somebody else's machine.

The demo requests no host mounts, secrets, ingress ports, or outbound network
access. Existing operator policy still applies; this workflow does not disable
security checks or silently switch to another backend if the native backend
is unavailable.

Only preparation acquires the image. `machine run` is cache-only: a missing
image or required artifact produces a preparation error rather than a hidden
download or build in the launch step.

## Check teardown

```bash
mvmctl machine ps --all --show-expired --json
```

After a completed run, the inventory should not contain `local-demo`.
Other machines are unrelated; do not use `machine stop --all` to clean up a
demo. Downloaded images, runtime artifacts, and audit history remain available.
Transient workload cleanup does not mean deleting the local cache.

For warm-launch demonstrations, use the existing
[OCI happy path](/getting-started/happy-paths/#cli-image-user) and warm pool
explicitly. Report cold and warm measurements separately. This starter does
not claim a warm-start latency.

## Contributor smoke test

From a source checkout, with Python 3 and the image prepared:

```bash
python3 scripts/smoke-local-demo.py --image "$MVM_DEMO_IMAGE"
```

This is an opt-in **live** test. Run it inside the project builder VM on Linux,
or as an explicit native HVF lifecycle test on a supported Mac. It uses the
installed `mvmctl`; `--mvmctl` can select a particular built binary.
Python is needed only for this contributor witness, not for the demo itself.

The test launches uniquely named cold transient workloads and checks output,
successful and intentionally nonzero exit statuses, and absence from the
complete inventory after exit. It does not bootstrap, pull, build, or start
`mvmd`. Missing runtime prerequisites, timeouts, and leaked machines fail the
test; they are not reported as successful skips. Its elapsed time includes the
whole run and teardown, not just startup.

## If preparation or launch fails

- **Unknown `--digest-ref`:** use a CLI version containing this option. Do not
  replace the captured digest with a mutable tag to hide the mismatch.
- **Image is missing:** run the preparation step. If you deliberately removed
  the cached image, pull the saved digest reference to prepare those same bytes.
- **Signature, scan, or admission refusal:** follow the named policy error;
  do not disable verification for the demo.
- **Unsupported host/backend:** use a supported native host. The browser demo
  is a different execution environment, not a transparent fallback.
