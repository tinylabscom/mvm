# #3714 — egress refusals shown on the host

A workload whose connection the per-VM network endpoint refused got a refusal
inside the guest and a chain-signed audit entry, and the person who ran it saw
nothing. This delivers the first PS-04 item: live, deduplicated refusal notices
with the remedy for each reason, an exit summary, the same records in
`run --json`, and a finished run's refusals in `mvmctl explain`.

## Source of truth

The chain the endpoint already writes. Nothing new is added to the egress
path, and the endpoint stays the single decision point; the CLI reads what it
recorded. The existing `trust audit tail --chain -f` loop was lifted into a
shared follower (`vm/audit_follow.rs`) and both it and the new watch use it.
The follower now survives segment rotation — it drains the renamed file and
reads the new one from its start — which the old tail did not.

The one change on the recording side: the endpoint's entries are unbound (it
holds no plan) and every machine shares the tenant chain, so no reader could
tell whose refusal an entry was. The endpoint config now carries the machine
name (`instance_id`, a field that existed and was never set), and the
endpoint's recorder stamps `vm_name` on every entry it writes
(`Recorder::with_vm_name`).

## Reasons and remedies

Every label the endpoint records on this tree, plus the restricted-address
classes and route outcomes that open PRs add, maps to a description and a
remedy. Metadata, loopback, link-local and the other absolute classes, and
TCP/22, get no remedy at all. Private ranges (and the other re-admittable
classes) say they are admitted only by naming the exact address and are kept
out of the summary's allow command. A gate that records a restricted address
under the generic `policy_denied` — this tree's gate records metadata that way
— is still read by its address, so no path offers an allow for the metadata
service.

`connect_failed` is not shown: the flow was admitted and the upstream did not
answer.

## Surfaces

- foreground `mvmctl run` / `mvmctl machine run` (transient): watch armed by
  the admission closure, which runs after the machine is named and before the
  endpoint spawns; summary before outputs are collected and before a nonzero
  exit;
- `machine run` attaching to a persistent machine: watch started before the
  boot;
- `machine logs -f`;
- `run --json`: `egress_denials` array, nothing printed live; `--pty` runs are
  quiet live (raw terminal) and summarize after the session;
- `mvmctl explain <run>`: refusals joined by machine name and bounded by the
  run's own admission and terminal entry, or the next admission under the same
  name.

`vm/host_notices.rs` is the one serialized stderr writer, with a `hold()`
guard so a runtime approval prompt can keep notices off the terminal while it
waits for an answer.

## A deny-all run has nothing to report

A run with no egress at all — no `--net`, `--allow-host`, secret or published
port — spawns no network endpoint (`ClaimGuards::spawn_endpoint` omits it by
design), so the guest has no channel to name a destination on and the host
records no refusal. Nothing prints, and the docs say so. Whether such a run
should say "this run had no network" when it fails is a product call left
open; guessing from an exit code would print on every offline failure.

## Live

HVF on macOS 26, `run --image curlimages/curl:latest --allow-host
api.github.com:443` reaching `example.com` twice and `169.254.169.254` once:
two live notices (the metadata one with no remedy — this tree's gate records it
as `policy_denied`, and the address backstop caught it), the summary with
`2×` / `1×` and `--allow-host example.com:443`, the allowed host answering 200,
and `mvmctl explain <vm>` listing the same two refusals from the chain.

## Not done here

The Grant / Skip policy-draft selector and `mvmctl why` — the other two PS-04
items.
