# Promote the documented examples still proven only by parsing

`parse` proves that clap accepts an invocation. It cannot see a verb that parses
and then refuses at runtime — the shape `machine forward` had decayed into while
the docs still told a reader to run it. 65 of the documented command paths sit
there.

Every one carries a written reason, so the tier is honest about itself. What it
was not is stable: the count went 61 → 65 during a week of unrelated
documentation work, because an example whose tier nobody chooses lands on the
rung that asks least. The ratchet scenario (`the parse tier does not grow`) pins
it; this plan spends the pin down.

## Classification

Grouped by the reason already recorded against each entry.

### Promote — needs only the live journey guest (11)

`machine diff`, `fork`, `proc start`, `reconfigure`, `restore`, `snapshot rm`,
`volume create`, `volume lock`, `volume unlock`, `volume unmount`, `wait`.

`features/suites/s32_documented_surface/machine_journey.feature` already boots a
guest, so these cost one boot for eleven verbs — the largest single win here.
They are nested under `VmCmd` and flattened into `machine`, and are genuinely
documented (`machine wait api-dev --for all`,
`machine proc start <vm> -- <argv>`).

Order matters: `volume create/lock/unlock` are witnessed working by
`features/suites/s26_volumes/volume_lifecycle.feature`, so they are the safe
first batch. `fork`, `restore` and `snapshot rm` need a checkpoint staged first,
and `reconfigure` mutates the guest, so both belong after the read-only verbs.

### Promote — a fixture exists but is unwired (6)

- `bundle fetch` / `install` / `gc` — `scripts/make-bundle-fixture.sh` builds a
  signed `.mvmpkg`; the `@bundle` capability already gates on it.
- `deps inspect` / `deps audit` — `mvm-app-deps-fixture-tool` seals a volume.
- `trust add` — needs a publisher pubkey file staged.

### Investigate — the reason may be over-applied (12)

Recorded as "documented only as a placeholder template, so there is no concrete
invocation to execute". Several look runnable against an isolated home:
`secret ls`, `pool status`, `shell-init`, `prepare`, `env bootstrap`. Worth
re-reading each doc site before accepting the reason — a placeholder in one page
does not mean no page shows a concrete form.

### Keep, with the reason already written (36)

- 5 build a multi-hundred-megabyte artifact over the network; the runner does
  this once as setup, not as an assertion.
- 5 reach a package index, so the outcome tracks the index rather than mvm.
- 4 refuse without `MVM_GATEWAY_URL` — the `--remote` form targets a gateway
  that lives in mvmd, not this repo.
- 3 need a live persistent-builder session no scenario starts.
- 3 need a manifest slot only a real builder-VM build fills.
- 2 are interactive PTYs (`machine console`, `machine shell`) and need a pty
  harness rather than captured stdio.
- 2 never exit (`ops mcp stdio`, `watch`).
- `bench` is a measurement loop on a benchmark budget, not a test budget.
- the remainder name artifacts only a real build or launch produces.

`machine forward` is a separate case: retired at runtime, still in the clap
tree, no longer referenced by the docs. It should leave the manifest rather than
be promoted.

## Sequencing

- [ ] Journey batch A — the read-only and volume verbs (7)
- [ ] Journey batch B — checkpoint-dependent verbs (4)
- [ ] Wire the three existing fixtures (6 paths)
- [ ] Re-read the 12 "placeholder" doc sites and reclassify
- [ ] Drop `machine forward` from the manifest
- [ ] Lower `PARSE_TIER_PIN` with each batch

Lower the pin in the same change that promotes. A batch that promotes without
lowering leaves the ceiling where it was, and the next drift is invisible again.
