# Plan 293 — stream plane follow-ups

**Status:** In progress — WS1 complete, WS2–WS4 outstanding.

Close the two reachability gaps plan 283 shipped knowingly, and add the two
gates that would have caught the classes of defect that cost it the most.

Predecessor: `specs/plans/295-workload-stream-plane.md` — note that `main`
carries a *different* plan 283, so refer to these by filename, not number.
Claim status: `specs/adrs/001-microvm-security-posture.md`, the Preview 17
limits note.

**Picking this up cold:** start from
`specs/plans/294-stream-plane-completion.md`. It carries the branch inventory,
the reason PR #2139 has never run CI, the number collisions, and the open
`replay_vectors` question. Tracking issue: tinylabscom/mvm#2152.

## Why these four together

Plan 283 shipped 22 tasks. Six of them were added mid-execution, and every one
was the same shape: correct, tested machinery with no production caller. Nine
separate times its prose asserted a security property the ledger did not back —
including a witness that existed nowhere in the tree, and five user-facing files
still stating a claim the ADR had already downgraded.

Both classes were caught only by review, which is not a control. WS3 and WS4
turn them into gates. WS1 and WS2 close the two holes that remain visible to a
user or an auditor.

## Workstreams

- [x] **WS1 — give the scan fingerprints, not plaintext, and close claim 17's
      last reachability limit.** Landed. `mvm_protocol::stream::secret_fingerprint`
      defines `(length, rolling hash, category)` and the rolling primitives;
      `mvm-hostd`'s substitution endpoint computes a fingerprint per resolved
      secret and reports them on its ready handshake; `spawn_substitution_endpoint`
      splits the handshake — placeholders persist to the guest env sidecar,
      fingerprints stay in this process — and `StreamPlane::open_input` installs
      the set before a writer's first frame. `KnownSecret` is deleted rather than
      deprecated, so no binding takes bytes. Two costs recorded rather than
      discovered: a collision refuses a legitimate frame (the refusal names what
      it compared and disclaims identity), and, unable to tell a live prefix from
      an innocent tail, the scanner withholds a fixed `longest_secret - 1` bytes
      on a secret-bearing VM. That second cost was first mispriced as latency
      and was a **stall**; it is closed by the idle release — see §"WS1
      follow-on: the blanket carry, and releasing it on silence". ADR-001's
      limit 1 is CLOSED, a new permanent limit 5 records the hash-match cost, a
      limit 6 records the blanket carry and its release, and ADR-035 §"What
      binding a fingerprint discloses" carries the length disclosure, the
      prefix-oracle argument, and why prefix fingerprints were rejected. Row 17
      stays `Preview`: the scan works now, it is not stronger.

  `InputGate::bind` has no production caller, so the cross-frame secret scan
  matches against an empty set on every real VM. The scan is correct and
  tested; it has nothing to scan for.

  **The obvious fix is wrong.** `KnownSecret` holds its value in the clear, and
  the stream plane is registered in `mvm-cli` — the CLI process — while the
  substitution endpoint that holds raw secrets runs as a separate process.
  Keeping that separation is the point. Binding plaintext into the gate would
  create a new plaintext location in a process that has none today, in order to
  close a limit on a different claim. That trade is not worth making.

  **Bind fingerprints instead.** The scan must find a secret split across frames
  at an arbitrary offset, which rules out comparing whole-buffer digests — but
  not a rolling hash. Bind `(length, rolling-hash)` pairs, roll the same hash
  over the window the scan already maintains, and confirm a candidate before
  refusing. The CLI never holds a secret value.

  Two consequences to state rather than discover. A hash collision is a false
  positive that refuses a legitimate frame — acceptable, because it fails
  closed, but the refusal reason must not imply a certainty it does not have.
  And the CLI learns secret *lengths*, a real if small disclosure that belongs
  in the ADR rather than in a comment.

  Two things not to lose. The scan is a backstop against a confused caller, not
  a defence against a determined one — encoding, derivation, and splitting
  inside a window boundary all defeat it, and the docs say so. A populated set
  must not turn that honest framing into an overclaim. And the window must still
  span frame boundaries: a secret split across two writes is the case the scan
  exists for.

  Then reassess claim 17. Two of its four limits closed when the channel gained
  an operator surface. This closes a third. State what remains rather than
  promoting on momentum.
- [ ] **WS2 — redact the console fallback.**

  The transcript is redacted; the console fallback is not. The fallback is what
  a detached run resolves to, which is the common shape rather than the corner.

  It is worse than a gap in coverage. The follower stops before `kill()`, so
  shutdown-time output — panics, the last thing a guest says, the most
  diagnostic material there is — lands only in the unredacted file. The moment
  most worth reading is the one least protected.

  Run the same `PiiRedactor` over console bytes on the read path, before they
  reach a consumer. Read-side, so the file the VMM owns is untouched.

  Keep the existing notice honest: it currently tells an operator the console
  merges streams, is unchained, and is unredacted. When the third stops being
  true, the notice must stop saying it.

- [ ] **WS3 — gate prose against the ledger.**

  `check-claim-catalog` reads the claims table in ADR-001. Nothing reads the
  prose around it, which is why nine drifts survived: `CLAUDE.md` cited a
  claim-12 witness that exists nowhere, `README.md` and four other files still
  asserted claim 15 in its absence form after the ADR had downgraded it, and
  ADR-035 contradicted the ledger it cites.

  Scan `README.md`, `public/`, `specs/`, and `CLAUDE.md` for claim-shaped
  assertions — "no interactive access", "there is no ... path", "cannot reach",
  "is not possible" — and require each to sit next to a citation of a ledger
  row. A phrase inventory is enough for a first cut; it would have caught eight
  of the nine.

  Prove it on the history: check out a commit from before each drift was fixed
  and confirm the gate fires. A gate nobody has seen fail is the defect it is
  meant to prevent.

- [ ] **WS4 — gate dormant controls.**

  Six times plan 283 shipped a security-relevant symbol with no production
  caller, each found by review rather than by CI. The failure mode is a control
  that reports present and cannot fire: an admission gate reading an argv nobody
  populates, a broker nothing constructs, a scan whose set is always empty.

  Hold a declared allowlist of security-relevant symbols that have no production
  caller. The gate fails when a symbol not on the list acquires that shape, and
  the allowlist may only shrink. Dormancy stops being an oversight and becomes a
  declaration with a name attached.

  Seed it from what is known dormant today and expect it to surface more. That
  is the point — the six found on plan 283 were the ones review happened to
  reach.

## WS1 follow-on: the blanket carry, and releasing it on silence

- [x] **Release the withheld tail after a short idle period.** Landed.
      `DEFAULT_IDLE_FLUSH_AFTER` = 50ms; `InputSession::refresh` releases on
      elapsed time alone, `InputRoute::refresh` carries what that produces, and
      the CLI's idle attendant visits every half-threshold.
- [ ] **Restore exact live-prefix coverage within a burst.** Not needed for any
      shape the plane serves today; costed as B and C below if it ever is.

WS1 traded exact live-prefix withholding for a fixed `longest_secret - 1`
carry, and the WS1 report priced that as latency. It was worse: with a 40-byte
bound secret the carry is 39, so `machine run --entrypoint --stdin -` against a
line-oriented workload delivered **zero** bytes of an 11-byte request line — the
workload never saw a line, never answered, the operator never wrote again, and
the tail shipped at EOF. A deadlock, on a shape ADR-035 names as a reason this
plane exists.

**The blanket carry is not the defect; it is the mechanism.** Withholding only
the tails that could still complete a secret makes the withhold-or-deliver
decision depend on content, and that decision is observable by anyone holding
the input grant: write one byte, see whether anything came out. That is a
**prefix oracle** — 256 tries per byte, so a 40-byte credential falls in about
40·256 probes instead of 256^40 — and it is a secret-extraction path against
what claim 13 protects, strictly worse than a stall. Because everything is
withheld unconditionally, the decision carries no information about content at
all. Any fix therefore has to leave the decision content-blind.

**Binding prefix fingerprints is the same mistake plus a disclosure.** Under the
polynomial hash in `mvm_protocol::stream::secret_fingerprint` the prefix hashes
are a literal encoding of the value: `h(k) = h(k-1)·BASE + s[k-1] (mod 2^64)`,
so each byte falls out by one subtraction and `h(1)` *is* the first byte — no
search at all. A different hash only converts that into a search: any function
the scanner can evaluate, code in the scanner's process can evaluate, so an
exact prefix-membership test over a 256-symbol alphabet is a decoder in 256·L
tries. Precision about a one-byte tail and secrecy of a one-byte prefix are the
same quantity. No hash, salt or truncation keeps both — a filter lossy enough to
blunt the oracle is lossy enough to false-positive on the common tail, which is
the stall again.

### What landed: E, the content-independent idle release

**E. Release the carry after T of writer silence.** The WS1 report listed this
and rejected it — "write half, wait T, write the rest — it defeats the scan for
precisely the patient caller it is aimed at". That rejection was wrong about who
the scan is aimed at. The scan is a backstop against a *confused* caller that
pasted the wrong thing (ADR-001 limit 4); it has never defended against a
determined one, because base64 defeats it outright. A caller patient enough to
pause mid-credential is a determined caller, and a determined caller does not
need the pause. The residual is therefore inside a limit that is already
permanent, while the stall was not inside any limit at all.

What landed:

- `DEFAULT_IDLE_FLUSH_AFTER = 50ms`, in `stream::input_gate`. The threshold sits
  between two gaps that differ by orders of magnitude: the gap inside one
  writer's burst (a buffer copy plus one vsock round trip — microseconds to low
  milliseconds, and the split a confused caller actually produces) and the gap a
  human or a request/response peer leaves. Roughly 50x the first and half the
  ~100ms perception floor.
- `InputSession::refresh` — already "the writer is idle but alive" — now also
  releases the withheld tail, on `elapsed >= threshold` and the withheld
  *length*, never on the bytes. `InputRoute::refresh` carries what that produces
  to the guest as one wire frame, and mints no frame when there is nothing to
  send. No new thread: the CLI's existing lease ticker became the idle
  attendant, ticking at half the threshold.
- `InputBinding::with_idle_flush_after` makes the threshold injectable, so both
  sides of the boundary are exercised with no sleeps and nothing to go flaky.

Witnesses: `an_idle_writer_gets_the_line_the_carry_swallowed` and
`a_line_the_carry_swallowed_reaches_the_guest_once_the_writer_goes_quiet` (the
deadlock, gate and route); `the_idle_release_does_not_depend_on_what_the_withheld_bytes_are`
and `what_is_withheld_is_a_length_and_never_a_verdict_about_the_bytes` (content
independence, driving a real live prefix against an innocent payload of equal
length); `a_secret_split_across_two_writes_inside_the_threshold_is_still_refused`
(coverage kept) and `a_secret_split_across_the_idle_gap_is_missed_and_that_is_the_price`
(the residual, pinned); `an_idle_release_cannot_hand_over_a_bound_secret` and
`a_writer_that_lost_its_lease_gets_no_idle_release_either`.

### Still available if exactness within a burst ever matters

**B. Anchor the carry to a delimiter the secrets provably lack.** The endpoint
already inspects each plaintext to fingerprint it; have it also report one bool
for the set — *does any bound secret contain `\n`*. If none does, no match can
straddle a newline, so the scanner may deliver everything through the last `\n`
in its buffer and carry only what follows, capped at `longest - 1` as now.
Sound with no false negatives: matches ending at or before the delimiter are
already found by the existing whole-buffer scan, and a secret with no `\n`
cannot span one.
*Buys:* a write ending in a newline delivers whole and immediately, carrying
nothing — so no idle wait at all for line-oriented input. *Costs:* one bit of
disclosure about the set, whose answer is "no" for essentially every credential;
a bound PEM key answers "yes" and falls back to the blanket carry (the
fail-closed direction). *Does not fix:* a workload reading length-prefixed
binary frames, which has no delimiter to anchor on. *Effort:* small.

**C. Move the scan into the substitution endpoint.** The gate forwards each
frame to the process that holds the plaintext; it does exact live-prefix
withholding and returns the cleared bytes.
*Buys:* everything, exactly — plaintext precision restored, and the CLI stops
learning lengths and hashes at all, so the WS1 disclosure closes too. *Costs:*
an IPC round trip per input frame, and a wedged endpoint now wedges stdin
instead of merely egress; the operator's input bytes start flowing through the
process holding the credentials, a new data flow into the most sensitive
process; the endpoint gains a byte-moving job it does not have. A residual
oracle survives — a caller opening one session per probe still learns one bit
per try, 256·L tries — but every try is chain-audited and the session latch
already stops within-session probing. *Effort:* medium-large.

**D. Cap the scanned window.** Carry at most N bytes and accept that a secret
longer than N can be split across the boundary. *Rejected:* regresses exact
cross-frame coverage unconditionally, where E regresses it only across a
deliberate pause.

**F. Ship it and document the hang.** *Rejected:* operators would meet it as a
hang with no error, on the shape the feature was built for.

## Sequencing

WS1 and WS2 first: both are visible to a user or an auditor today, and WS1 is
what a reader of claim 17 would reasonably assume already holds.

WS3 and WS4 after, cheap and preventive. WS4 subsumes WS1's failure mode, so
landing WS1 first gives the gate a real closure to record rather than a
hypothetical.

## Out of scope

VM-to-VM fan-out (`specs/plans/296-fleet-stream-fan-out.md`). The deferred
minors in plan 283's ledger — they are individually small and want triage, not a
workstream.
