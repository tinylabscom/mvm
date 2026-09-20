# Agent workload

This example runs the native Claude Code CLI in a sealed mvm guest. The API
key remains in the host secret store. The guest receives an opaque
`mvm-secret-…` placeholder for `ANTHROPIC_API_KEY`; the host substitutes the
real value only on an admitted request to `api.anthropic.com`.

The image has no guest NIC and no general network access. `mvm.toml` admits
only the Anthropic API and enables AI usage metering. `workload.json` carries
the secret reference because secret bindings are signed workload intent, not
image-build configuration.

## Run it

Store the key and its destination binding. Piping the value keeps it out of
the process list and shell history:

```bash
printf '%s' "$ANTHROPIC_API_KEY" | \
  mvmctl secret set anthropic --provider anthropic --value -
```

Then send a prompt to the baked per-call entrypoint:

```bash
printf '%s\n' 'Summarize the security boundary in this repository.' | \
  mvmctl machine run --flake examples/agent-workload --entrypoint \
    --from-workload-ir examples/agent-workload/workload.json \
    --allow-host api.anthropic.com:443 --stdin - --timeout 120
```

`--from-workload-ir` is required. It lowers the `SecretRef` into the signed
execution plan and gives only the per-call entrypoint the placeholder and
proxy environment. A plain image boot receives neither.

## Offline smoke check

The documented-surface suite runs the same guest without contacting Anthropic.
It uses a test-only secret address and a non-secret smoke marker in
`workload-smoke.json`; the wrapper verifies that it received a host-minted
placeholder and prints the pinned CLI version:

```bash
printf '%s' 'not-a-real-key' | \
  mvmctl secret set agent-workload-smoke --provider anthropic --value -
printf '' | \
  mvmctl machine run --flake examples/agent-workload --entrypoint \
    --from-workload-ir examples/agent-workload/workload-smoke.json \
    --allow-host api.anthropic.com:443 --stdin - --timeout 120
mvmctl secret rm agent-workload-smoke
```

The smoke path makes no outbound request and never transmits the test value.

## Audit trail

A real model request produces metadata-only, chain-signed entries:

- `secret.substituted` names the secret address, destination, and auth type
  when the substituted credential is handed to the forward leg.
- `secret.forward_outcome` records whether that forward completed or failed.
- `ai.usage` records provider-reported token counts when they are present.

None of those entries contains the key or the placeholder. Verify the chain
and inspect the recent records with:

```bash
mvmctl trust audit verify
mvmctl trust audit tail --chain --lines 50
```

The guest can use the credential through the governed proxy; a compromised
guest could still spend it against its bound destination. Use provider-side
budgets and revocation in addition to mvm's destination binding and audit.
