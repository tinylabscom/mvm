# #3757 — one answer to "does this run boot an OCI image"

## Problem

A `mvmctl run --manifest mvm.toml` whose manifest names an OCI `image` booted
the built OCI slot without `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` in the
workload. An image's own init knows nothing of the guest egress proxy (a
`mkGuest` image exports it from `/init`), so the launch has to hand it over,
and the launch decided that from `args.image.is_some()`. An unmodified client
in that VM could not reach even an admitted destination.

The same question was asked four ways: `--image` was passed (backend
selection, workload env, receipt and dry-run), and "a prebuilt with an
unpacked OCI tree" (`resolve_launch`). A manifest-built OCI slot answered no
to all of them.

## What landed

- `GuestSidecar::is_oci_materialized` reads the sidecar the OCI
  materialization already writes beside every rootfs (`hypervisor = "oci"`,
  now a named constant and no longer described as informational).
- `crate::exec::boots_oci_image` is the single resolution point. It takes an
  `ImageNaming` (an `--image` reference, a `--manifest`, an already-resolved
  `ImageSource`, or nothing) and answers from what the run boots: the slot's
  current or pinned revision sidecar, or the sidecar beside a prebuilt rootfs.
  `LaunchNames` / `RunArgs::image_naming` map a launch's flags to it in the
  launch's own precedence.
- Every consumer reads it: backend selection and the workload proxy env in
  `build_exec_request`, backend selection in the admitted run, `resolve_launch`,
  receipt input and the dry-run preflight. `oci_proxy_env` replaces the two
  `oci_vsock_proxy_env_*` helpers.
- A `--manifest` that does not resolve answers `false`; the launch resolves it
  again and refuses with its own message before anything boots.

## Tests

`--image` and a manifest-built image slot (built through
`template_build_from_image`) produce identical proxy env; current, pinned and
prebuilt sources; a `mkGuest` slot, an unbuilt slot, a missing manifest and the
bundled image answer no; the flag precedence; the sidecar predicate.
