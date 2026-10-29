# Agent workload

This example runs the native Claude Code CLI in a sealed mvm guest. The API
key remains in the host secret store. The guest receives an opaque
`mvm-secret-…` placeholder for `ANTHROPIC_API_KEY`; the host substitutes the
real value only on an admitted request to `api.anthropic.com`.

The image has no guest NIC and no general network access. `mvm.toml` admits
only the Anthropic API and enables AI usage metering. `workload.json` carries
the secret reference because secret bindings are signed workload intent, not
image-build configuration.

The flake, project manifest and both workload documents request 2 vCPUs and
4096 MiB. This is an initial allocation, not measured capacity or a guarantee
that a real prompt fits. Record peak memory and completion for the actual
prompt before reducing it; the offline version check is not a capacity test.

## Contributor execution boundary

Run Nix builds/evaluations and ordinary workload commands inside the approved
project builder VM, not directly on macOS or in Lima. A builder without
`/dev/kvm` can build the image but cannot supply a nested Firecracker workload
witness. Stop there and record the missing capability; native macOS HVF
workload smoke needs separate explicit operator permission.

Build the current checkout CLI without replacing the global installation.
Source `scripts/dev-env.sh` and use task-local state and build outputs; keep
evidence logs and temporary archives under `/tmp`. Record the source revision,
CLI version, guest architecture, toolchain, accepted base-image identity and
runtime origin before interpreting smoke results. Never reuse another run's
scratch path as evidence unless its actual bytes are still available.

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
    --allow-host api.anthropic.com:443 --timeout 120
```

The pipe is the complete input for this invocation. The baked entrypoint reads
it directly; `--stdin -` would instead request an interactive streaming grant,
which sealed workloads deliberately do not receive.

`--from-workload-ir` is required for this secret-bearing workload. It lowers
the `SecretRef` into the signed execution plan; the host endpoint mints an
opaque placeholder and PID 1 exports it before launching the image workload.
A plain image boot receives neither a binding nor a placeholder.

## Offline smoke check

The documented-surface suite runs the same guest without contacting Anthropic.
It uses a test-only secret address and a non-secret smoke marker in
`workload-smoke.json`; the wrapper verifies that it received a host-minted
placeholder and prints the pinned CLI version:

```bash
printf '%s' 'not-a-real-key' | \
  mvmctl secret set agent-workload-smoke --provider anthropic --value -
printf '%s' 'mvm-agent-smoke' | \
  mvmctl machine run --flake examples/agent-workload --entrypoint \
    --from-workload-ir examples/agent-workload/workload-smoke.json \
    --allow-host api.anthropic.com:443 --timeout 120
mvmctl secret rm agent-workload-smoke
```

The non-secret marker uses the same bounded per-call input path as a real
prompt. The smoke path makes no outbound request and never transmits the test
value.

Save the actual version output, `agent-workload smoke: placeholder-present`,
exit status and the correlated session identifier. Verify that session with
`mvmctl trust audit verify` and retain the verification result and signed
records before removing task-local state. A successful offline smoke proves
startup and placeholder provisioning only: it proves neither a real model
response nor allow/deny network enforcement.

For a session-specific verdict, read the identifier from that run's output
or signed session records, then supply it explicitly:

```bash
read -r SESSION_ID
test -n "$SESSION_ID" && mvmctl trust audit verify "$SESSION_ID" --json
```

## Portable artifact prerequisite

A source-flake smoke is not an installable application archive. Portable
export must retain the complete boot closure and the independently verified
signed guest-runtime release matching the CLI version. An unavailable release
is a blocker, not permission to relabel a source build, disable verification,
enroll a signing key or publish a release.

For CLI version `0.24.0`, inspect the release and its actual assets before
attempting canonical export:

```bash
gh release view v0.24.0 --repo tinylabscom/mvm --json tagName,url,assets
```

The expected archive is `mvm-guest-bins-v0.24.0.tar.gz`, accompanied by its
checksum and signature proofs. Release metadata or an HTTP success alone is
not signature verification. If any required input is unavailable, record the
exact missing asset and acquisition error in the tracking issue and stop;
release publication needs separate approval.

After export, record the final `.mvmpkg` digest, size, publisher identity,
base/runtime inputs and architecture. Verify and boot that archive in empty
application state without the author checkout, Nix or original application
download endpoint. Only that run can witness source-free installation.
Live requests require separate consent and a budget-limited key; paired
allow/deny runs must use the same archive, prompt and secondary destination,
with Anthropic still authorized. Preserve correlated request/refusal evidence,
not only the model's assertion.

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
