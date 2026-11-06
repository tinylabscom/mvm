---
title: Native local demo
description: Run a bounded transient microVM directly, without mvmd or a separate bootstrap.
---

This demo runs a real Linux microVM on your own machine through `mvmctl`.
It does not use `mvmd`, a remote API, provider credentials, persistent volumes,
or the website's browser-based QEMU-Wasm demo.

MVM still starts its normal local runtime helpers as needed; those are not a
separately deployed fleet service and require no manual daemon setup.

Use a supported host: macOS 26+ on Apple Silicon, or Linux with `/dev/kvm`.
Install the published CLI using the [installation guide](/getting-started/installation/).
No source build, host Nix, or Docker is needed for this image-backed workflow.

## Launch with one command

```bash
mvmctl machine run --name local-demo --profile dev \
  --image alpine \
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

The first run downloads the kernel and image and caches them for later runs.
The guest runtime shipped with the CLI is prepared by `mvmctl bootstrap`, not
by the launch: a release binary that has not bootstrapped refuses the launch
and names that command. The first run may take longer than
launching an already-prepared workload; keep that acquisition time separate
from prepared-startup measurements. This is a local **development-profile**
demonstration, not a sealed production workload or a replacement for the
production OCI trust policy. Verification and normal launch admission remain
enabled.

## Prepare the runtime and pin the image

Run `mvmctl bootstrap` once per installed version, then save a digest-pinned image reference:

```bash
mvmctl bootstrap
mvmctl image pull alpine
MVM_DEMO_IMAGE="$(mvmctl image inspect alpine --digest-ref)"
printf '%s\n' "$MVM_DEMO_IMAGE"
```

Replace `--image alpine` with `--image "$MVM_DEMO_IMAGE"` for a later run.
`--digest-ref` prints the cached canonical pin for this host's architecture
and preserves a multi-architecture index pin when the source had one.
The tag may move; a previously saved digest does not. A digest identifies
content, not its publisher. Do not bypass a verification or admission refusal.

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

From a source checkout, with Python 3 and the image prepared and pinned as above:

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
- **Image acquisition fails:** check the reported network or registry error.
  If you deliberately removed a pinned image, pull its saved digest reference
  to prepare those same bytes.
- **Signature, scan, or admission refusal:** follow the named policy error;
  do not disable verification for the demo.
- **Unsupported host/backend:** use a supported native host. The browser demo
  is a different execution environment, not a transparent fallback.
