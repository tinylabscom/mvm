# The mission node image

The workload for the mission demo's production-profile run. It does, by itself
and on a fixed schedule, what a compromised workload would try (see
`mission-node.sh`), so the demo does not depend on a model misbehaving.

- `Dockerfile` copies the script onto a digest-pinned Alpine base. It carries no
  mailbox client: `/mvm/runtime/mailbox-client` comes from the signed runtime
  overlay.
- `.github/workflows/mission-node-image.yml` builds a multi-architecture index,
  pushes it to `ghcr.io/tinylabscom/mvm-mission-node` and signs the index digest
  keyless. It runs only when dispatched by hand, because it creates a public
  package.
- `oci-policy.toml` is the registry policy a production run needs: one registry,
  one signer, that workflow on `main`.
- `mission-node.test.sh` checks the script's sequence against a fake client.

A production run executes the image's own command; there is nothing to pass after
`--`:

```sh
MVM_OCI_POLICY=examples/mission-node/oci-policy.toml \
  mvmctl machine run --prod --image ghcr.io/tinylabscom/mvm-mission-node@sha256:<digest> \
  --mailbox <64 hex> --mailbox-retention-ms 60000
```

`--prod` verifies the signature with the `cosign` binary, so it must be on PATH.
Whether this runs end to end under `--prod` is not yet shown; see #5353.
