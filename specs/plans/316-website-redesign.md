# Plan 316 — Website and docs redesign

**Status: IMPLEMENTATION COMPLETE — awaiting human browser verification**
**Last updated: 2026-08-11**
**Branch:** `feat/website-redesign`
**Scope:** `public/` only. No Rust crate, CLI, or doc *content* changes.

## Goal

Reshape the marketing homepage and the Starlight docs chrome so the whole site
reads as one designed system rather than a landing page bolted onto a docs
theme. The visual target, supplied by the maintainer as two reference sites, is:
near-black canvas, drifting gradient blooms, glass-edged cards, a
display/mono type pairing, numbered section eyebrows, generous vertical
rhythm — plus structural cues of large typographic statements, alternating
full-width feature blocks, and a four-up capability row.

We match the visual *language*. We do not copy either reference's stylesheet,
assets, markup, or copy. Every value in this plan is expressed as our own
token; every component is written from scratch.

Two things the homepage must do that it does not do today:

1. **Show code.** mvm is a CLI plus three SDKs. The current homepage has one
   static code block and one terminal animation. Neither shows what writing
   against mvm actually looks like.
2. **Reward scrolling.** The page is currently six static blocks. It should
   unfold.

## Decisions taken

| Question | Decision |
| --- | --- |
| Dark-only, like the reference? | **No — keep light + dark.** The existing `[data-theme="light"]` palette and Starlight's theme picker stay. Glow and glass motifs get an explicit light-mode treatment (below) rather than being dropped. |
| Mirror the reference's section order 1:1? | **No.** Adopt the visual system; keep mvm's own section set. No logo walls, no "trusted by" rows, no vector-store grids — we have nothing truthful to put in them. |
| Docs scope | **Chrome + prose styling. No content edits.** ~180 `.md`/`.mdx` pages keep their words. |
| Rebuild strategy | **Introduce a primitives layer, then rebuild the six landing components on it.** Retinting `className` strings in place would reproduce the current drift, where each component invents its own spacing and border alpha. |

## Current state

- Astro 5.18 + Starlight 0.37.6 + Tailwind 4, React 19 islands.
- Landing: `public/src/components/landing/` — `Landing.tsx` composes `Hero`,
  `Features`, `Architecture`, `CodeExample`, `CTABanner`, `Footer` (~750 lines
  total). UI primitives in `public/src/components/ui/` (`button`, `card`,
  `badge`, `tabs`, `code-block`).
- Docs chrome: three Starlight overrides (`Header.astro` 350 lines,
  `Hero.astro`, `MarkdownContent.astro`) plus `public/src/styles/custom.css`
  (781 lines).
- Tokens: `public/tailwind.css` (142 lines). Two-layer system — a base palette
  that varies per scheme, and scheme-invariant role tokens that reference it.
  Components consume role tokens only; hex codes in components are already
  banned by the file's own header comment. **This system is good and is kept.**

## Design

### 1. Tokens — `public/tailwind.css`

Extend the existing two layers. Do not restructure them.

**Base palette additions (dark values; light values in the `[data-theme="light"]`
block and the `prefers-color-scheme: light` block, which must stay in sync):**

- Deepen `--color-page` from `#0d1117` toward near-black. Raise
  `--color-surface` correspondingly so contrast is preserved.
- Add `--color-surface-2` — a second elevation, so a card can sit on a panel.
- Add `--color-accent-2` (cyan) and `--color-accent-3` (violet). The reference's
  identity comes substantially from rotating *three* accents across sections;
  we currently have one (`--color-accent`, blue) plus incidental
  green/amber/rust/nix.

**Role token additions (`@theme inline`, scheme-invariant):**

- `--color-glow-1/2/3` → `color-mix()` of the three accents against
  transparent. Dark: saturated, low alpha. Light: the same hues at a small
  fraction of the alpha, so blooms read as a faint tint rather than a smear.
- `--color-glass-border` → `color-mix()` of `--color-border` and
  `--color-heading`. Dark: a lifted hairline. Light: a slightly *stronger*
  hairline, because light mode loses the glow and needs the edge to carry the
  card.
- `--font-display` → a self-hosted variable sans, paired against the existing
  JetBrains Mono. Self-hosted, not a third-party CDN fetch.

Constraint carried forward from the file's existing rules: **no component may
hardcode a hex value.** The only sanctioned exception remains the terminal-dot
row. All new glow and glass values derive from base tokens via `color-mix()`,
so light mode tracks automatically.

### 2. Motion primitives — `public/src/components/landing/primitives/`

Four new files. Each is small, single-purpose, and independently testable.

- **`Section.tsx`** — max-width, vertical rhythm, optional hairline top rule.
  The single owner of section spacing.
- **`Eyebrow.tsx`** — the numbered mono label (`01 — Isolation`).
- **`GlowCard.tsx`** — bordered card; cursor-tracked radial highlight via CSS
  custom properties written from a pointer handler; accent-tinted border on
  hover.
- **`Bloom.tsx`** — the drifting background gradient layer. Takes which accents
  to use so sections can rotate through the three.
- **`Reveal.tsx`** — IntersectionObserver wrapper. Children fade and rise once,
  on first intersection, with a stagger index. Observer disconnects after
  firing; it does not re-animate on scroll-back.

**Reduced motion is a first-class path, not an afterthought.** Under
`prefers-reduced-motion: reduce`: `Bloom` renders static, `GlowCard` drops
pointer tracking and keeps a static border, `Reveal` renders children visible
immediately with no transition, and the scroll-synced walkthrough (below)
degrades to a plain stacked list of steps each with its own code block. Every
one of these paths must be verified, not assumed.

### 3. Homepage sections

`Landing.tsx` composes, in order:

1. **Hero** — `Bloom` backdrop, headline, subhead, copy-to-clipboard install
   command, primary/secondary CTAs, stats row. The existing animated terminal
   component is retained; it is the best thing on the current page.
2. **Install** — the one-liner, plus platform tabs (macOS / Linux / WSL2).
3. **`01`–`04` numbered feature walk** — `GlowCard` four-up, rotating accents,
   `Reveal`-staggered.
4. **Scroll-synced walkthrough** — *the new centrepiece.* Steps scroll on the
   left; a code panel sticks on the right and swaps as each step enters view.
   Walks one real task end to end: define a workload, build it, run it, read
   the result. Implemented with IntersectionObserver against step markers —
   no scroll hijacking, no pinning library, native scrolling throughout.
5. **SDKs and CLI** — the explicit ask. One tabbed block, four tabs — Python,
   Node.js, Rust, CLI — showing *the same task* four ways, so the choice of
   surface is legible at a glance. Builds on the existing `ui/tabs` and
   `ui/code-block` primitives rather than a new mechanism.
6. **Architecture** — the host → builder VM → microVM diagram, restyled.
7. **Security** — the claims, presented as cards linking into
   `docs/security/`.
8. **CTA + Footer.**

**All code samples on the homepage must be real.** Every snippet is taken from
a working example under `examples/` or from the CLI's own `--help` surface, not
written to look plausible. A sample that does not run is worse than no sample.

### 4. Docs chrome and prose — `custom.css` + the three overrides

- Header: sticky, backdrop blur, hairline bottom edge instead of a solid bar.
- Sidebar: group labels as mono uppercase; quiet indent rail; the current
  item-spacing rules retuned to the new rhythm.
- Right-hand TOC restyled to match the sidebar.
- Prose: type scale and measure retuned against the new display font.
- Tables, callouts, and Expressive Code frames adopt the `GlowCard` border
  colour and radius, so a docs page and the homepage read as one system.

No `.md` or `.mdx` file under `public/src/content/` is edited.

### 5. Files touched

| File | Change |
| --- | --- |
| `public/tailwind.css` | Extend tokens (both palettes) |
| `public/src/styles/custom.css` | Docs chrome + prose restyle |
| `public/src/overrides/Header.astro` | Sticky/blur header |
| `public/src/overrides/{Hero,MarkdownContent}.astro` | Align to new tokens |
| `public/src/components/landing/primitives/*` | **New** — 5 files |
| `public/src/components/landing/*.tsx` | Rebuilt on primitives |
| `public/src/components/ui/*.tsx` | Retuned to new tokens |
| `public/package.json` | Self-hosted display font dependency |

## Verification

The repo has no visual regression tests for `public/`, and this plan does not
add them — that is a larger piece of infrastructure than the redesign itself
and would be its own plan.

What must pass before this is called done:

- [x] `pnpm build` in `public/` completes with no errors and no new warnings
      (Task 20 verification, 2026-08-11 — `pnpm build`, 131 pages, clean).
- [ ] Homepage screenshotted in **dark** and **light**, both at desktop and at
      a narrow mobile width. **Awaits human browser verification** — no agent
      in this pass can drive a browser; see the checklist in the Task 20
      report (`.superpowers/sdd/316-website-redesign-implementation/task-20-report.md`).
- [ ] A representative docs page (long prose + code + table + callout)
      screenshotted in dark and light. **Awaits human browser verification.**
- [ ] `prefers-reduced-motion: reduce` pass: blooms static, no reveal
      transitions, walkthrough degraded to the stacked fallback. **Awaits
      human browser verification** — this is also where the JS-enabled
      hydration check for the `html.js` reveal gate must run; see report.
- [ ] Keyboard traversal of the SDK tab block and the header nav. **Awaits
      human browser verification.**
- [x] No hardcoded hex outside the sanctioned terminal-dot exception —
      grep-checked (Task 20 verification, 2026-08-11 — `pnpm check:tokens`
      passes).
- [x] Every homepage code sample traced to a real `examples/` file or a real
      `--help` output (Task 20 verification, 2026-08-11 — `pnpm check:samples`
      reports 9/9).

## Explicitly out of scope

- Any change to Rust crates, the CLI, or its help text.
- Rewriting docs page content or restructuring the sidebar's information
  architecture.
- Visual regression test infrastructure.
- Blog layout (`public/src/layouts/BlogLayout.astro`) beyond whatever it
  inherits from the token changes.
