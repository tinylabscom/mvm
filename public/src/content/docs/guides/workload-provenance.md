---
title: Workload provenance
description: Connect a workload's artifact identity, signed admission, run receipt, and audit decisions without exposing its payload.
---

Provenance answers four different questions: which bytes were selected, which
policy admitted them, what one run returned, and which host decisions occurred
along the way. Keep the evidence for those questions distinct. A readable
history is not automatically a verified one.

## Start with an immutable source

Pin a production OCI image by digest, or use a pinned flake input and the
recorded build revision. The selected artifact identity and policy references
feed a signed `ExecutionPlan` at launch. The plan binds the workload identity,
resources, validity window, and fresh replay nonce; it is not an invitation to
rebuild or follow a mutable tag at verification time. For source-to-artifact
details, see [Workload IR to image](/guides/ir-to-image/) and
[Nix and OCI](/guides/nix-and-oci/). Image construction and publication are
owned by the [image repository](https://github.com/tinylabscom/mvm-images/);
this runtime consumes and verifies the result.

## Keep proof for one run

Request a receipt when starting a transient workload:

```sh
mvmctl run --receipt /tmp/run-receipt.json -- python task.py
mvmctl trust receipt verify /tmp/run-receipt.json
```

The receipt carries invocation and output hashes, exit status, timing, and
signature metadata, rather than raw arguments, environment values, stdout,
stderr, or host paths. Verify its signature before passing it to CI or another
party. A valid receipt proves its signed contents, not that an operator's
chosen destination or tool was wise.

## Verify host decisions

The host's signed audit chain records admission and subsequent lifecycle and
policy events. Inspect and verify it separately from the receipt:

```sh
mvmctl trust audit tail --chain --tenant local -n 20
mvmctl trust audit verify --tenant local
```

Use the plan ID to correlate a run with its session. `mvmctl trust audit
sessions` and `mvmctl trust audit show <plan-id>` expose the session's events;
`mvmctl trust audit verify <plan-id>` checks its seal and the containing chain.
An unsealed session is not proof of a complete run. The audit records decision
metadata, not guest payload bytes; treat ordinary guest logs separately as
sensitive data. See [Audit and receipts](/guides/audit-and-receipts/) for seal
verdicts and retention limits.

## Export a view, then check its source

For analysis or compliance tooling, export decision records or a PROV-O view:

```sh
mvmctl trust audit decisions export --tenant local
mvmctl trust audit provenance export --tenant local -o provenance.ttl
```

Each export is a **read-only view** of recorded decisions. The exported
representation is not a substitute for verifying the underlying audit chain;
verify the chain before relying on the export. The TIBET-compatible decision
export does not contain a new host signature, so its `signature` field must
not be presented as one. Keep the original receipt and chain evidence when
sharing a derived report.
