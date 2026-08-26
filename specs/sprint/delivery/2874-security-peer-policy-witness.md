# Security peer-policy mutation witness

Issue #2874 reported the failed scheduled Security run 32931995875. Its only
red job was the `mvm-contract` mutation shard: replacing
`NetworkPolicy::peers()` with an always-empty slice survived, so the claim-10
peer-policy accessor lacked a direct witness.

The focused test now attaches one validated peer binding to both policy shapes
and requires the accessor to return that exact binding. It separately preserves
the deny-all empty default. This distinguishes the real stored policy from the
surviving fail-closed-looking replacement without weakening the mutation
baseline.

Validation:

- focused `mvm-contract` peer-policy test: green;
- exact `NetworkPolicy::peers` mutation selection: two generated mutants,
  one caught and one unviable;
- the repository's static mutation-surface gate, contract suite, check, and
  Clippy run before the repair branch is submitted.

Issue #2875 is the independent scheduled-evidence tracker. It remains open
until scheduled Security history contains the repaired witness; manual evidence
does not replace that cadence assertion.
