# Restore the sealed-dependency flow to the README

Backing: shipped-source
Validation: check-sprint-append

**Status: OPEN** — cut from the README on 2026-09-03 for the 0.18 release.

## Why this exists

The README documented a three-command dependency flow:

```bash
mvmctl deps install --lockfile uv.lock --language python
mvmctl deps capture-live HASH --vm dev-vm ...
mvmctl deps inspect HASH
```

None of it runs on macOS. Measured on 2026-09-03 against an artifact-warm home
on macOS 26 / Apple Silicon:

- `--builder hvf` (the auto-detect default on this tier) returns
  `BuilderVmError::NotYetImplemented`: "Stage 0 builder-VM bootstrap is
  implemented for the libkrun backend only; the hvf and Firecracker Stage 0
  paths are not wired yet."
- `--builder libkrun` gets further — it boots an install job VM, which exits
  cleanly and never writes `result.json`, so artifact extraction fails.

`capture-live` and `inspect` both read what `install` produces, so the whole
flow is unreachable from a Mac. The examples were cut rather than labelled,
because a label would have been an unverified claim in the other direction: the
Linux path was never measured.

The verbs themselves are unchanged and remain in `mvmctl deps --help`. The
sealed-volume machinery behind them is real and exercised — `security.yml`'s
`app-deps-audit` lane seals a fixture volume and drives `deps inspect` against
it, including the byte-flip refusal. What is missing is the arm that *produces*
a volume from a lockfile on this platform.

## What has to be true before the section goes back

- [ ] Measure `deps install` on Linux/KVM. If it works there, the failure is
      macOS-specific and the fix is scoped to Stage 0; if it does not, the
      install pipeline itself is the problem. This is the first step because it
      decides which of the next two matters.
- [ ] Wire the hvf Stage 0 builder-VM bootstrap, or make the builder
      auto-fallback (ADR-007) cover `NotYetImplemented` the way it covers a
      VM-create failure. Today the fallback does not trigger, because a stub
      returning "not implemented" is not the VMM-level failure the policy
      watches for — so the default macOS backend fails where the non-default
      one would at least have tried.
- [ ] Find why the libkrun install job VM exits 0 without writing
      `result.json`. A clean exit with no artifact is the worst shape available:
      the guest reports success and the host has nothing, so the failure is
      attributed to extraction rather than to the install.
- [ ] Give `deps install` an executed witness — a `@live` scenario against a
      real lockfile — and restore the three examples with `witness` entries in
      `features/suites/s8_readme_contract/readme_examples.toml`. The register
      currently holds 35 examples; these three bring it back to 38.

## What not to retry

Do not "cover" this by pointing the register at the `app-deps-audit` lane. That
lane hand-seals its fixture with `mvm-app-deps-fixture-tool`; `deps install`
never runs in it. The exemption that made exactly that claim survived for
months because nothing checks whether a cited lane exercises the command it is
cited for.
