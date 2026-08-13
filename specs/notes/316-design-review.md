# Plan 316 — Website and docs redesign design review

**Reviewed:** 2026-08-12  
**Branch under review:** `main` (redesign shipped in #2359)  
**Scope:** `public/` — homepage components, docs chrome, and shared primitives.

## Verification performed

- `cd public && pnpm install --frozen-lockfile` — clean.
- `cd public && pnpm build` — 131 pages built successfully.
- `cd public && pnpm check:tokens` — no hardcoded hex in components.
- `cd public && pnpm check:samples` — all 10 homepage samples resolve to real repo files.
- Static read of every landing component, primitive, `tailwind.css`, and `src/styles/custom.css`.

## Overall assessment

The redesign reads as a single designed system rather than a landing page bolted onto a docs theme. The token system is disciplined, motion is gated behind `prefers-reduced-motion`, and the prose stays tied to verifiable claims instead of marketing adjectives. The page is in good shape; remaining work is polish and a maintainer sign-off on the two deliberately dropped features.

## Strengths

1. **Token discipline is real.** Base palette tokens vary per scheme; role tokens are scheme-invariant. `pnpm check:tokens` enforces the rule, and the only sanctioned hex exceptions are the terminal-dot affordances.
2. **Motion is responsible.** `Bloom`, `Reveal`, `GlowCard`, the terminal cursor, and the boundary-pulse line all respect `prefers-reduced-motion: reduce`.
3. **Accessibility details are thought through.** Install-row copy buttons are real `<button type="button">` with visible focus rings. FAQ uses native `<details>`. Diagrams hide decorative SVGs and expose `aria-label` on the containing `<figure>`.
4. **Prose is anchored to evidence.** Security cards cite named tests and CI jobs; the credibility strip uses only license, platforms, and repo facts.
5. **Typography choice reads as technical.** Mono headings (`JetBrains Mono Variable`) plus Inter body differentiate the landing from generic SaaS templates.

## Issues and suggestions

### 1. `GlowCard` primitive is unused

`public/src/components/landing/primitives/GlowCard.tsx` exists but is not imported by any landing component. It was intended for feature/walkthrough cards that were cut in review. The current Security section uses plain bordered cards.

**Options:**
- Use `GlowCard` for the four Security claim cards to add the cursor-tracked sheen and consistent hover accent.
- Delete `GlowCard` if the design intent is to keep cards flat; dead primitives drift out of sync.

### 2. Quickstart "Result" tab is weak

The Quickstart tab panel uses `walk-define`, `walk-build`, `walk-run`, and `walk-result`. The Run tab already shows a terminal animation with the output. The Result tab shows only:

```bash
# expect: "hello ari"
```

This is a comment, not a result, and duplicates what the animation already conveys.

**Suggestion:** Drop the Result tab and keep three tabs (Define / Build / Run), or replace Result with a real output sample / success-state panel.

### 3. Hero install tabs duplicate the same command

The macOS and Linux tabs both render the identical `install.sh` one-liner. The Windows (WSL2) tab renders only prose and a link, with no command.

**Suggestion:** Either collapse macOS/Linux into a single "macOS / Linux" tab, or make the Windows tab show the WSL2 install command if it differs. As-is, the three-tab treatment promises platform specificity it does not deliver.

### 4. Credibility strip is underweight

The strip after the hero carries only "Apache-2.0", "macOS + Linux", and the GitHub link. Compared to the strong headline and diagram above it, the strip reads as an afterthought.

**Suggestion:** Add one more verifiable fact — e.g., "no daemon", "no SSH", or a link to the latest release — so the row has the same visual weight as the hero it follows.

### 5. Scroll-synced walkthrough and SDK/CLI tab block remain dropped

These were intentionally removed during maintainer review. The current implementation records that decision in `specs/plans/316-website-redesign-implementation.md`. No action needed unless the maintainer wants them restored.

## Recommended next steps

1. Decide whether to wire `GlowCard` into Security or remove it.
2. Simplify the Quickstart Result tab.
3. Revisit the install-tabs duplication.
4. Maintainer sign-off on the two dropped features (no code change required).

## Conclusion

The redesign is functionally complete and measurement-clean. The remaining items are small UX polish decisions, not structural problems. The site is ready for maintainer sign-off once the above options are chosen.
