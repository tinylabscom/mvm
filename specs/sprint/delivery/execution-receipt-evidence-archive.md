# Execution-receipt evidence archive

Delivered 2026-08-22.

## What was wrong

`mvmctl trust audit receipts export` printed signed receipts derived from the
chain-signed audit log, and looked complete. It was not.

`map_event_to_receipt_type` matched thirteen event names and returned `None`
for everything else. The caller wrote `None => continue`. So every one of these
left no trace in the output:

| Event family | Carries |
|---|---|
| `flow.egress.allowed` / `flow.egress.denied` | the claim-10 decision per outbound connection |
| `stream.subscribed` | who attached to workload output, and from which seq |
| `stream.input_granted` | who was admitted to workload stdin |
| `gateway.transcript_sealed` | the sealed transcript manifest root |

An export containing no egress was byte-indistinguishable from an export whose
egress entries were skipped. Separately, a receipt carried no digest of the
audit line it came from, no leaf index, no proof, and no root — so it could not
be checked away from the host that produced it, even though the RFC 6962
machinery to do so already existed and was simply unwired.

## What shipped

Eight tasks, each TDD with a mutation check that the test goes red for the
right reason.

- **`mvm_contract::merkle::verify_membership`** — the four-step membership
  composition (signed root, right tenant, self-consistent proof, proof bound to
  *this* root) moved out of a private `mvm-cli` function so the archive
  verifier and the existing `verify-inclusion` verb cannot drift. The CLI's
  seven pre-existing `composition_*` tests pass untouched, which is the
  evidence the move preserved behaviour.
- **`EntryMapping`** — two arms instead of an `Option`. The match is
  exhaustive, so an event added later cannot fall out of an export. An attempt
  to reinstate the old behaviour as a guarded arm fails to compile (`E0004`).
- **Self-locating receipts** — `mvm.audit_digest`, `mvm.audit_root`,
  `mvm.tree_size` inside the signed payload; one root per export pass.
- **`.mvmev` archive + verifier** — signed manifest, one inclusion proof per
  leaf, raw chain lines, citations. Three independent results with a 1/2/4 exit
  bitmask.

## Two things only running it found

**Citations were bound to nothing.** Proofs were originally per-receipt. The
first real round trip produced a legitimate archive whose in-scope entries were
all citations, and the verifier rejected it for having no proofs. Relaxing the
check would have hidden the actual problem: a citation carried a leaf index and
a digest with no binding a verifier could check independently of the host's
signature over the manifest. Proofs are now per leaf.

**A caveat nobody saw.** The attested-completeness warning used `ui::info`,
which is verbosity-gated chatter — the export printed nothing at all by
default. It moved to `ui::notice`, and now keys off the resolved scope rather
than the `--full-chain` flag.

## The property worth remembering

A proof for the wrong leaf still verifies against the signed root. It is valid
arithmetic attesting the wrong entry. Mutating the writer to build every proof
for leaf 0 leaves a "every proof verifies against the signed root" test green;
only `proof.leaf_index == leaf.index` catches it. Both the writer's tests and
the verifier check that binding.

## Left open

- Transcript chunk embedding (`--with-transcripts`), blocked on which of two
  transcript stores is authoritative — see ADR-110's open question. The flag is
  not advertised and the writer refuses it.
- WS5, the mvmd blob store and index, specced in the mvmd repo, not started.
