# Plan 316 — Website and docs redesign

**Status: COMPLETE — merged behaviour verified by measurement; design review with the maintainer is ongoing**
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

**What survived, and what didn't.** The numbered eyebrows, the card grids and
the multi-bloom treatment all shipped and were then removed: uniformly applied,
they were exactly what made the page read as machine-generated. One bloom
remains, in the hero. The mono/sans pairing survived but inverted — mono
headings, sans body. A later direction change replaced the whole section set
with the arrangement recorded below.

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
- `--font-display` → **JetBrains Mono Variable**, and `--font-body` → **Inter
  Variable**. Both self-hosted; the previous CDN fetch is gone. The plan
  originally specified a display *sans* against a mono; that inverted during
  the visual-language pass — mono headings are what give the page its
  character, and Inter body is what keeps long prose readable. The two are
  separate tokens because `--sl-font` had been aliased to `--font-display`,
  so repointing the display face silently took all docs body copy with it.

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

> **Superseded during implementation.** The eight-section list this plan
> originally specified shipped, was reviewed by the maintainer as reading
> "like an agent built it", and was then restructured twice more. What
> follows is what actually shipped. The original list is in git history.

`Landing.tsx` composes, in order:

1. **Hero** — badge row (licence, platforms, repo), headline with one accent
   word, subhead, platform install tabs, primary + secondary action and a
   tertiary text link, and `HeroStackDiagram` as the visual anchor.
2. **Credibility band** — label left, verified facts right. Deliberately not
   a customer-logo wall: there are no adopters we can name, and inventing
   them would defeat the section's purpose.
3. **Quickstart** — heading and supporting line left, a tabbed
   Define/Build/Run/Result panel right. The scroll-synced walkthrough was
   folded in here; the fixed-panel block shape left it no slot.
4. **Positioning** — a marker-highlighted statement heading, then a zig-zag
   of three alternating rows: CLI, Declare, Runtime. Replaces the earlier
   single tabbed block, which the maintainer called worthless — as three
   full rows each surface gets room to say what it is *for*.
5. **Why a microVM** — a positive case built on `ContainmentDiagram`, the
   nested machine ⊃ hypervisor ⊃ microVM ⊃ kernel ⊃ workload model from
   `security/matryoshka.md`. An earlier revision framed this as "why not a
   container" with a side-by-side comparison; the positive framing replaced
   it at the maintainer's direction.
6. **Split feature panel** — the backend-selection prose and chips left, the
   `1 kernel per workload` figure right.
7. **Security** — all four claims as cards, wording verbatim from the gated
   claims table, each with its witness identifiers.
8. **FAQ** — two columns, first row open by default.
9. **Closing band + footer.**

Two diagrams carry the visual identity, both inline SVG built from role
tokens so they work in either scheme: `HeroStackDiagram` (where the boundary
sits in the stack) and `ContainmentDiagram` (what encloses what).

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
- [x] Homepage rendered in **dark** and **light** at 1440 / 1024 / 390 and
      reviewed screenshot-by-screenshot through the redesign passes
      (2026-08-11, headless Chromium via playwright-core).
- [x] A representative docs page (long prose + code + table + callout)
      rendered in dark and light at 1440 and 390.
- [x] `prefers-reduced-motion: reduce` pass — verified in a `reducedMotion:
      'reduce'` context: bloom and terminal-cursor animations resolve to
      `animation-name: none`, reveals render immediately, the walkthrough
      serves its stacked fallback.
- [x] Keyboard traversal — all **57** focusable elements on the landing page
      show a visible focus indicator (outline or ring), measured by focusing
      each in turn and reading computed style.
- [x] Colour contrast at WCAG AA — **0** text nodes below threshold on the
      landing page (dark and light) and on a docs page, measured by flattening
      each element's colour over its resolved background.
- [x] No horizontal overflow at 390 / 768 / 1024 on landing **and** docs;
      no code block scrolls horizontally on either.
- [x] Gutters consistent across every section and the header at
      108 / 34 / 26 (1440 / 1024 / 390).
- [x] No hardcoded hex outside the sanctioned terminal-dot exception —
      `pnpm check:tokens` passes.
- [x] Every homepage code sample traced to a real repo file —
      `pnpm check:samples` reports 10/10.

Still genuinely outstanding, and not agent-checkable: whether the result
*reads* well to a human on a real device. Everything above is a measurement,
not a judgement.

## Explicitly out of scope

- Any change to Rust crates, the CLI, or its help text.
- Rewriting docs page content or restructuring the sidebar's information
  architecture.
- Visual regression test infrastructure.
- Blog layout (`public/src/layouts/BlogLayout.astro`) beyond whatever it
  inherits from the token changes.
