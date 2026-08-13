# 2398 — the docs described seven claims; the ledger has eighteen

`public/src/content/docs/security/` framed the security posture around seven
CI-enforced claims. ADR-001's table runs to fifteen numbered claims plus three
`Preview` rows, and the highest claim number appearing anywhere in that
directory was 3. A reader arriving at claim 13 or claim 15 found nothing that
substantiated it.

This surfaced during the website redesign: the homepage security cards wanted
to cite claim numbers, found no docs page that carried them, and shipped
witness identifiers instead. That was a workaround for the gap, not a fix.

## Delivered

- `ci-claims.md` rewritten as a mirror of ADR-001's table — fifteen numbered
  claims, the three preview claims each with the reason it is still preview,
  and the three out-of-scope non-goals. The page says outright that the ADR's
  table is the source of truth and this page is the copy, so the next drift has
  a defined direction of repair.
- `matryoshka.md` claim table extended to match, and the two kinds of claim it
  conflated are now separated: the layer-defending claims, which is what the
  per-backend tier matrix actually measures, and the supply-chain/admission
  claims (6, 7, 8, 9, 11, 12, 14), which hold identically across every backend
  because they gate what is allowed to run before a backend is chosen. The
  Firecracker row's "All seven claims hold" became "every layer-defending claim
  holds"; the QEMU row gained its claim-10 exclusion.
- `claim-ledger.md` link text and the Starlight sidebar label follow the
  retitle.

`sandbox-parity-status.md` kept its own "seven" — those are the sandbox-parity
claims, a different family against a different ADR. Only its cross-link to this
claim set was wrong, and it now states that the two numberings do not
correspond.

## Also in this change

Plan 316's implementation plan carried 110 unticked step checkboxes despite the
redesign having merged. Rather than tick them retroactively — nobody can verify
a step-level box after the fact — the plan gained a status header mapping
planned artifacts to what shipped. Five tasks named components that were never
created because a maintainer review restructured the page mid-flight, and two
stated goals were dropped by that review: the scroll-synced code walkthrough
and the SDK/CLI tab block as its own section. `specs/REFACTOR-STATUS.md` records
the merge and the reconciliation.

## Witnesses

- `xtask check-doc-claims`, `check-no-overclaim`, `check-witness-citations`,
  `check-claim-catalog`, `check-honesty`, `check-adr-coverage` — all clean
- the site's own gates, `check-no-hardcoded-hex` and `check-sample-provenance`
  — both pass

No claim text was invented: every row's statement comes from the ADR-001 table
it mirrors, and mechanism detail is summarized rather than copied, so the page
cannot drift into asserting a mechanism the ADR no longer describes.
