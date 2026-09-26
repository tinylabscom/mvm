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

Every label the endpoint records on this tree, plus the route outcomes an open
PR adds, maps to a description and a remedy. Restricted-address classes are
read through the gate's own `RestrictedClass` (now with `ALL` and
`from_label`), so the CLI and the gate cannot name a class differently. Metadata, loopback, link-local and the other absolute classes, and
TCP/22, get no remedy at all. Private ranges (and the other re-admittable
classes) say they are admitted only by naming the exact address and are kept
out of the summary's allow command. A refusal of a restricted literal recorded
under the generic `policy_denied` is still read by its address, through the
same classifier, so no path offers an allow for the metadata service.

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
api.github.com:443` reaching `example.com` twice, `169.254.169.254` once and
`10.0.0.5:8080` once: three live notices — the metadata one with no remedy, the
private one saying it is admitted only by naming it — then the summary with
`2×` / `1×` / `1×`, `--allow-host example.com:443` as the only allow, and the
private address listed apart. The allowed host answered 200. The chain carried
`cloud_metadata` and `private_range` as the gate recorded them, each stamped
with the machine's `vm_name`. An earlier run, before the private-range gate
landed, recorded the metadata refusal as `policy_denied`; the address backstop
read it as metadata all the same, and `mvmctl explain <vm>` listed the same
refusals from the chain.

## Not done here

The Grant / Skip policy-draft selector and `mvmctl why` — the other two PS-04
items.
