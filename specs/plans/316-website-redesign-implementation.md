# Website and Docs Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Design spec:** `specs/plans/316-website-redesign.md` — read it first.

**Goal:** Rebuild the mvm homepage on a small shared primitives layer with
scroll-driven motion, a scroll-synced code walkthrough, and an SDK/CLI tab
block; restyle the Starlight docs chrome and prose to match; keep both light
and dark palettes working.

**Architecture:** Extend the existing two-layer token system in
`public/tailwind.css` (base palette varies per scheme, role tokens are
scheme-invariant and reference it). Add five motion/layout primitives under
`public/src/components/landing/primitives/`. Rebuild the six existing landing
components on those primitives. Restyle docs via `public/src/styles/custom.css`
and the three Starlight overrides. Two real automated gates — a hardcoded-hex
gate and a code-sample provenance gate — run in CI-able Node scripts.

**Tech Stack:** Astro 5.18, Starlight 0.37.6, Tailwind 4, React 19 islands,
prism-react-renderer, pnpm 10, Node 22.

## Global Constraints

- **Work in the worktree** `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-website-redesign` on branch `feat/website-redesign`. Do not `cd` to the main checkout.
- **Package manager is pnpm.** `pnpm-workspace.yaml` exists; a stale `public/package-lock.json` also exists and is deleted in Task 1. All commands: `cd public && pnpm …`.
- **No hardcoded hex in components.** Every colour is a role token (`var(--color-…)` or a Tailwind `bg-…`/`text-…` bound to one). Sole sanctioned exception: the terminal-dot tokens `--color-dot-close|minimize|expand`, which are macOS Aqua product-affordance colours and are theme-independent. Gate: Task 3.
- **Both palettes stay working.** Every base-palette token added under `@theme` must get a matching value in *both* the `[data-theme="light"]` block and the `@media (prefers-color-scheme: light)` block in `public/tailwind.css`. Those two blocks are duplicates of each other by design — keep them in sync.
- **`prefers-reduced-motion: reduce` is a specified path, not a fallback.** Blooms static, no reveal transitions, no cursor tracking, walkthrough degraded to a stacked list. Verified in Task 20.
- **Every homepage code sample must be real** — traced to a file under `examples/` or to real `mvmctl --help` output. Gate: Task 2.
- **Do not edit any `.md` or `.mdx` file under `public/src/content/`.** Docs content is out of scope; only chrome and prose *styling* change.
- **Do not name the reference sites** in any file, commit message, or code comment. Refer to them as "the reference" if needed. Standing project rule.
- **No plan/PR/ADR references in code comments** — CI-gated by `xtask check-no-spec-refs`. Comments explain *why*, not which plan asked for it.
- **Correct backend facts** (the current homepage is wrong — see Task 12/15): HVF is the macOS 26+ Apple Silicon default; libkrun is the default on macOS 13–25 and on Linux is an explicit opt-in; Firecracker is the Linux KVM workload path; QEMU is a Linux dev/test builder default. **Apple Virtualization was removed and must not be mentioned.** There is no Docker on any runtime path.
- **The three SDK surfaces** are: Python (`crates/mvm-sdk/sdks/python`), TypeScript/Node (`crates/mvm-sdk/sdks/typescript`), and Rust (the `mvm-sdk` crate itself — there is no `sdks/rust` directory). Plus the `mvmctl` CLI.
- **Commit after every task.** Pre-commit hooks must not be bypassed.

---

### Task 1: Baseline — pin the toolchain and get a clean build

**Files:**
- Delete: `public/package-lock.json`
- Modify: `public/package.json`

- [ ] **Step 1: Confirm the site builds before you touch anything**

```bash
cd public && pnpm install --frozen-lockfile && pnpm build
```

Expected: completes, writes `public/dist/`. If it fails, stop and report —
you are not fixing a pre-existing break as part of this plan.

- [ ] **Step 2: Remove the stale npm lockfile**

Two lockfiles disagree about the dependency tree; `pnpm-workspace.yaml`
settles which is authoritative.

```bash
cd public && rm package-lock.json
```

- [ ] **Step 3: Add the verification scripts entry**

In `public/package.json`, add to `"scripts"`:

```json
"check:tokens": "node scripts/check-no-hardcoded-hex.mjs",
"check:samples": "node scripts/check-sample-provenance.mjs",
"check": "pnpm check:tokens && pnpm check:samples && pnpm build"
```

- [ ] **Step 4: Rebuild to confirm nothing regressed**

```bash
cd public && pnpm build
```

Expected: same clean result as Step 1.

- [ ] **Step 5: Commit**

```bash
git add public/package.json && git rm --cached public/package-lock.json
git commit -m "chore(site): pin pnpm as the site package manager"
```

---

### Task 2: Code-sample provenance gate

The homepage will carry code the reader is invited to trust. Samples rot
silently because nothing checks them. This gate is what makes the "samples must
be real" constraint enforceable rather than aspirational.

**Files:**
- Create: `public/scripts/check-sample-provenance.mjs`
- Create: `public/src/components/landing/samples.ts`

**Interfaces:**
- Produces: `samples.ts` exports `SAMPLES: Sample[]` where
  `type Sample = { id: string; label: string; language: string; source: string; code: string }`.
  `source` is a repo-relative path (e.g. `examples/python/hello-app/app.py`) or
  the literal string `"cli-help"`. Every later task that renders code imports
  from this module — no component contains an inline code string.

- [ ] **Step 1: Write the failing gate**

Create `public/scripts/check-sample-provenance.mjs`:

```js
// Every homepage code sample must be a verbatim slice of a real repo file.
// A sample that drifts from its source is worse than no sample: it teaches
// the reader something that does not run.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..", "..");
const samplesPath = join(import.meta.dirname, "..", "src/components/landing/samples.ts");
const src = readFileSync(samplesPath, "utf8");

// samples.ts is plain data; evaluate it as a module to read SAMPLES.
const { SAMPLES } = await import(samplesPath);

const failures = [];
for (const s of SAMPLES) {
  if (s.source === "cli-help") continue; // checked by Task 14's help-text step
  let fileText;
  try {
    fileText = readFileSync(join(repoRoot, s.source), "utf8");
  } catch {
    failures.push(`${s.id}: source not found: ${s.source}`);
    continue;
  }
  const normalize = (t) => t.replace(/\r\n/g, "\n").trim();
  if (!normalize(fileText).includes(normalize(s.code))) {
    failures.push(`${s.id}: code is not a verbatim slice of ${s.source}`);
  }
}

if (failures.length) {
  console.error("Sample provenance failures:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log(`sample provenance OK (${SAMPLES.length} samples)`);
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd public && node scripts/check-sample-provenance.mjs
```

Expected: FAIL — `samples.ts` does not exist yet (module resolution error).

- [ ] **Step 3: Create samples.ts with one real sample**

First read the real file so you copy it verbatim:

```bash
cat examples/python/hello-app/app.py
```

Then create `public/src/components/landing/samples.ts` exporting `SAMPLES`
with a single entry whose `code` is an exact slice of that file, `source` is
`"examples/python/hello-app/app.py"`, `language` is `"python"`, `id` is
`"python-hello"`, `label` is `"Python"`. Do not retype the file — copy it.

- [ ] **Step 4: Run the gate to verify it passes**

```bash
cd public && node scripts/check-sample-provenance.mjs
```

Expected: PASS — `sample provenance OK (1 samples)`.

- [ ] **Step 5: Prove the gate actually bites**

Change one character inside the `code` string, re-run, confirm it FAILS,
then revert. A gate you have not seen go red is not a gate.

- [ ] **Step 6: Commit**

```bash
git add public/scripts/check-sample-provenance.mjs public/src/components/landing/samples.ts
git commit -m "test(site): gate homepage code samples against their source files"
```

---

### Task 3: Hardcoded-hex gate

**Files:**
- Create: `public/scripts/check-no-hardcoded-hex.mjs`

- [ ] **Step 1: Write the failing gate**

Create `public/scripts/check-no-hardcoded-hex.mjs`:

```js
// Components consume role tokens, never raw colour. This keeps light mode
// working: a hex in a component is a value light mode cannot override.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "src");
// The terminal-dot row is deliberately theme-independent: those are macOS
// window-control colours, a product affordance rather than a theme choice.
const ALLOWED = /--color-dot-(close|minimize|expand)/;
const HEX = /#[0-9a-fA-F]{3,8}\b/;

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const failures = [];
for (const file of walk(root)) {
  if (!/\.(tsx|ts|astro|css)$/.test(file)) continue;
  if (file.endsWith("code-block.tsx")) continue; // token-valued Prism theme
  readFileSync(file, "utf8").split("\n").forEach((line, i) => {
    if (HEX.test(line) && !ALLOWED.test(line)) {
      failures.push(`${file.slice(root.length + 1)}:${i + 1}: ${line.trim()}`);
    }
  });
}

if (failures.length) {
  console.error("Hardcoded colour outside the token system:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log("no hardcoded hex in components");
```

- [ ] **Step 2: Run it — expect failures from existing code**

```bash
cd public && node scripts/check-no-hardcoded-hex.mjs
```

Expected: FAIL, listing any current offenders. Record the list.

- [ ] **Step 3: Fix each offender by routing it through a role token**

For each line reported, replace the hex with the nearest existing role token
(`text-title`, `text-body`, `border-edge`, `bg-canvas`, `bg-raised`, …). If no
token fits, that is a signal Task 4 needs to add one — note it and move on;
Task 4 will revisit.

- [ ] **Step 4: Run the gate to verify it passes**

```bash
cd public && node scripts/check-no-hardcoded-hex.mjs
```

Expected: PASS.

- [ ] **Step 5: Rebuild**

```bash
cd public && pnpm build
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add public/scripts/check-no-hardcoded-hex.mjs public/src
git commit -m "test(site): gate components against hardcoded colour values"
```

---

### Task 4: Extend the token palette

**Files:**
- Modify: `public/tailwind.css`

**Interfaces:**
- Produces, consumed by every later task: base tokens `--color-surface-2`,
  `--color-accent-2`, `--color-accent-3`; role tokens `--color-glow-1`,
  `--color-glow-2`, `--color-glow-3`, `--color-glass-border`,
  `--color-raised-2`, and `--font-display`.

- [ ] **Step 1: Add the new base tokens to the dark `@theme` block**

In the `@theme` block, after `--color-surface`, add `--color-surface-2` (one
step lighter than `--color-surface`). After `--color-accent-hover`, add
`--color-accent-2` (cyan) and `--color-accent-3` (violet). Deepen
`--color-page` toward near-black and raise `--color-surface` to preserve the
contrast step between them.

- [ ] **Step 2: Mirror them into both light blocks**

Add light-mode values for `--color-surface-2`, `--color-accent-2`,
`--color-accent-3` in **both** `[data-theme="light"]` **and**
`@media (prefers-color-scheme: light) :root:not([data-theme="dark"])`.
Missing either one produces a mode that silently falls back to dark values.

- [ ] **Step 3: Add the role tokens to `@theme inline`**

```css
  --color-raised-2: var(--color-surface-2);
  --color-glass-border: color-mix(in oklab, var(--color-border) 70%, var(--color-heading));
  --color-glow-1: color-mix(in oklab, var(--color-accent) var(--glow-strength), transparent);
  --color-glow-2: color-mix(in oklab, var(--color-accent-2) var(--glow-strength), transparent);
  --color-glow-3: color-mix(in oklab, var(--color-accent-3) var(--glow-strength), transparent);
```

- [ ] **Step 4: Define `--glow-strength` per scheme**

In the dark `@theme` block set `--glow-strength: 22%`. In **both** light
blocks set `--glow-strength: 7%`. This single knob is what lets one `Bloom`
component read as a glow in dark and a faint tint in light, with no
branching in component code.

- [ ] **Step 5: Verify both schemes resolve**

```bash
cd public && pnpm build && pnpm dev
```

Open the site, toggle the theme picker through Light / Dark / Auto. Confirm
no element loses its background or goes unreadable in either mode.

- [ ] **Step 6: Commit**

```bash
git add public/tailwind.css
git commit -m "feat(site): add second surface, two accents, and scheme-aware glow tokens"
```

---

### Task 5: Self-hosted display font

The current `custom.css` fetches JetBrains Mono from a third-party CDN at
render time. That is a render-blocking third-party request and a privacy leak
on every page load. Self-host both faces.

**Files:**
- Modify: `public/package.json`, `public/src/styles/custom.css`, `public/tailwind.css`

- [ ] **Step 1: Add the font packages**

```bash
cd public && pnpm add @fontsource-variable/inter @fontsource-variable/jetbrains-mono
```

- [ ] **Step 2: Replace the CDN import**

In `public/src/styles/custom.css`, delete the
`@import url('https://fonts.googleapis.com/...')` line at the top and replace
with:

```css
@import "@fontsource-variable/inter";
@import "@fontsource-variable/jetbrains-mono";
```

- [ ] **Step 3: Bind the display token**

In `public/tailwind.css` `@theme`, add:

```css
  --font-display: "Inter Variable", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "JetBrains Mono Variable", ui-monospace, monospace;
```

In `custom.css`, update `--sl-font-system-mono` to lead with
`"JetBrains Mono Variable"`, and set `--sl-font` to `var(--font-display)`.

- [ ] **Step 4: Verify no network font request remains**

```bash
cd public && pnpm build && grep -rn "fonts.googleapis" src/ dist/ | head
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add public/package.json public/pnpm-lock.yaml public/src/styles/custom.css public/tailwind.css
git commit -m "feat(site): self-host the display and mono typefaces"
```

---

### Task 6: `Section` and `Eyebrow` primitives

**Files:**
- Create: `public/src/components/landing/primitives/Section.tsx`
- Create: `public/src/components/landing/primitives/Eyebrow.tsx`

**Interfaces:**
- Produces: `<Section id? className? rule?>` — `rule` (boolean) draws a
  hairline top border. `<Eyebrow n? >label</Eyebrow>` — `n` is a
  zero-padded index string like `"01"`.

- [ ] **Step 1: Write `Section.tsx`**

```tsx
import { cn } from "@/lib/utils";

export function Section({
  id,
  rule = false,
  className,
  children,
}: {
  id?: string;
  rule?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section
      id={id}
      className={cn(
        "relative w-full px-6 py-24 sm:px-8 lg:py-32",
        rule && "border-t border-edge/60",
        className,
      )}
    >
      <div className="relative mx-auto max-w-6xl">{children}</div>
    </section>
  );
}
```

- [ ] **Step 2: Write `Eyebrow.tsx`**

```tsx
import { cn } from "@/lib/utils";

export function Eyebrow({
  n,
  className,
  children,
}: {
  n?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <p className={cn("mb-3 font-mono text-xs tracking-[0.2em] uppercase text-label", className)}>
      {n && <span className="text-accent">{n}</span>}
      {n && <span className="mx-2 text-dim">—</span>}
      {children}
    </p>
  );
}
```

- [ ] **Step 3: Build**

```bash
cd public && pnpm build
```

Expected: clean (nothing imports them yet — this only proves they compile).

- [ ] **Step 4: Commit**

```bash
git add public/src/components/landing/primitives
git commit -m "feat(site): add Section and Eyebrow layout primitives"
```

---

### Task 7: `Bloom` primitive with reduced-motion path

**Files:**
- Create: `public/src/components/landing/primitives/Bloom.tsx`
- Modify: `public/src/styles/custom.css`

**Interfaces:**
- Produces: `<Bloom accents={[1,2,3]} />` — renders an absolutely-positioned,
  pointer-events-none backdrop. Parent must be `relative overflow-hidden`.

- [ ] **Step 1: Write `Bloom.tsx`**

```tsx
import { cn } from "@/lib/utils";

export function Bloom({
  accents = [1, 2],
  className,
}: {
  accents?: Array<1 | 2 | 3>;
  className?: string;
}) {
  return (
    <div className={cn("pointer-events-none absolute inset-0 overflow-hidden", className)} aria-hidden="true">
      {accents.map((a, i) => (
        <div
          key={a}
          className={cn(
            "site-bloom absolute rounded-full blur-[120px]",
            i === 0 ? "left-1/2 top-0 h-[36rem] w-[52rem] -translate-x-1/2 -translate-y-1/4" : "right-0 top-1/3 h-[26rem] w-[26rem]",
          )}
          style={{ background: `var(--color-glow-${a})`, animationDelay: `${i * -8}s` }}
        />
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Add the drift animation and the reduced-motion stop**

Append to `public/src/styles/custom.css`:

```css
/* Background blooms drift slowly. Under reduced-motion they hold still —
   the tint is decorative, the movement is what triggers discomfort. */
@keyframes site-bloom-drift {
  from { transform: translate3d(0, 0, 0) scale(1); }
  to   { transform: translate3d(4rem, -2rem, 0) scale(1.12); }
}

.site-bloom {
  animation: site-bloom-drift 28s ease-in-out infinite alternate;
}

@media (prefers-reduced-motion: reduce) {
  .site-bloom { animation: none; }
}
```

Note the `-translate-x-1/2` utility on the first bloom and the animation's
`transform` both target `transform`; the animation wins. Position the first
bloom with `left`/`margin` instead of a translate utility so the centring
survives the animation.

- [ ] **Step 3: Verify both motion paths**

```bash
cd public && pnpm dev
```

In DevTools, Rendering → "Emulate CSS prefers-reduced-motion: reduce".
Confirm the blooms stop moving and remain visible.

- [ ] **Step 4: Commit**

```bash
git add public/src/components/landing/primitives/Bloom.tsx public/src/styles/custom.css
git commit -m "feat(site): add drifting background bloom primitive"
```

---

### Task 8: `GlowCard` primitive

**Files:**
- Create: `public/src/components/landing/primitives/GlowCard.tsx`

**Interfaces:**
- Produces: `<GlowCard accent={1|2|3}>` — bordered card with a
  cursor-tracked radial highlight and an accent-tinted border on hover.

- [ ] **Step 1: Write `GlowCard.tsx`**

```tsx
import { useRef } from "react";
import { cn } from "@/lib/utils";

export function GlowCard({
  accent = 1,
  className,
  children,
}: {
  accent?: 1 | 2 | 3;
  className?: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);

  // Cursor tracking is pure decoration, so it is skipped entirely rather
  // than merely shortened when the user asks for reduced motion.
  function onPointerMove(e: React.PointerEvent<HTMLDivElement>) {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  }

  return (
    <div
      ref={ref}
      onPointerMove={onPointerMove}
      className={cn("site-glow-card group relative overflow-hidden rounded-xl border border-glass-border/60 bg-raised p-6 transition-colors", className)}
      style={{ "--glow": `var(--color-glow-${accent})` } as React.CSSProperties}
    >
      <div className="site-glow-card__sheen pointer-events-none absolute inset-0 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden="true" />
      <div className="relative">{children}</div>
    </div>
  );
}
```

- [ ] **Step 2: Add the sheen and hover-border CSS**

Append to `public/src/styles/custom.css`:

```css
.site-glow-card__sheen {
  background: radial-gradient(16rem circle at var(--mx, 50%) var(--my, 0%), var(--glow), transparent 65%);
}

.site-glow-card:hover {
  border-color: color-mix(in oklab, var(--glow) 55%, var(--color-glass-border));
}

@media (prefers-reduced-motion: reduce) {
  .site-glow-card__sheen { display: none; }
}
```

- [ ] **Step 3: Verify in both schemes**

Run `pnpm dev`, hover a card in dark mode and light mode. In light mode the
sheen should be barely-there and the border should carry the card — that is
the intended difference, not a bug.

- [ ] **Step 4: Commit**

```bash
git add public/src/components/landing/primitives/GlowCard.tsx public/src/styles/custom.css
git commit -m "feat(site): add cursor-tracked glow card primitive"
```

---

### Task 9: `Reveal` primitive

**Files:**
- Create: `public/src/components/landing/primitives/Reveal.tsx`

**Interfaces:**
- Produces: `<Reveal delay={0}>` — fades and rises children once on first
  intersection, then disconnects.

- [ ] **Step 1: Write `Reveal.tsx`**

```tsx
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

export function Reveal({
  delay = 0,
  className,
  children,
}: {
  delay?: number;
  className?: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  // Start visible when motion is reduced, and when JS has not run yet the
  // CSS below keeps content visible — the page must never depend on the
  // observer firing to be readable.
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setShown(true);
      return;
    }
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown(true);
          io.disconnect();
        }
      },
      { rootMargin: "0px 0px -10% 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={cn("site-reveal", shown && "is-shown", className)}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {children}
    </div>
  );
}
```

- [ ] **Step 2: Add the CSS, defaulting to visible**

Append to `public/src/styles/custom.css`:

```css
/* Default to visible: if scripting or the observer fails, the page still
   reads. The hidden state is only applied once JS has taken over. */
.site-reveal {
  opacity: 1;
}

@media (prefers-reduced-motion: no-preference) {
  html.js .site-reveal {
    opacity: 0;
    transform: translateY(0.75rem);
    transition: opacity 600ms ease, transform 600ms ease;
  }
  html.js .site-reveal.is-shown {
    opacity: 1;
    transform: none;
  }
}
```

- [ ] **Step 3: Add the `js` class**

In `public/src/overrides/Header.astro`, add an inline script that sets
`document.documentElement.classList.add("js")` before paint.

- [ ] **Step 4: Verify the no-JS path**

Disable JavaScript in DevTools, reload. Confirm all homepage content is
visible. This is the failure mode that matters — a reveal animation that
hides content permanently when the observer does not fire.

- [ ] **Step 5: Commit**

```bash
git add public/src/components/landing/primitives/Reveal.tsx public/src/styles/custom.css public/src/overrides/Header.astro
git commit -m "feat(site): add reveal-on-scroll primitive that fails visible"
```

---

### Task 10: Rebuild the Hero

**Files:**
- Modify: `public/src/components/landing/Hero.tsx`

- [ ] **Step 1: Swap the hand-rolled glow for `Bloom`**

Replace the two hardcoded `bg-accent/7 blur-[120px]` divs with
`<Bloom accents={[1, 2]} />`. Keep the outer
`relative overflow-hidden` on the section.

- [ ] **Step 2: Apply the display font to the headline**

Add `font-display` to the `h1`, raise the size step, and keep the existing
gradient-text treatment on the second line — retarget it from
`from-accent via-nix to-accent` to `from-accent via-accent-2 to-accent-3`.

- [ ] **Step 3: Wrap the copy column in `Reveal`**

Wrap the headline, subhead, install row, CTA row, and stats row in
`<Reveal>` with staggered `delay` values of `0, 80, 160, 240, 320`.

- [ ] **Step 4: Keep the terminal animation as-is**

`TerminalAnimation` stays. Retarget its wrapper glow to `--color-glow-1` /
`--color-glow-3` via tokens rather than the current `bg-accent/10` /
`bg-nix/10`.

- [ ] **Step 5: Verify**

```bash
cd public && pnpm check
```

Expected: token gate PASS, sample gate PASS, build clean.

- [ ] **Step 6: Commit**

```bash
git add public/src/components/landing/Hero.tsx
git commit -m "feat(site): rebuild the hero on the bloom and reveal primitives"
```

---

### Task 11: Install section

**Files:**
- Create: `public/src/components/landing/Install.tsx`
- Modify: `public/src/components/landing/Landing.tsx`

- [ ] **Step 1: Read the real install commands**

```bash
sed -n '1,40p' public/src/content/docs/install/macos.md
sed -n '1,40p' public/src/content/docs/install/linux.md
sed -n '1,40p' public/src/content/docs/install/windows.md
```

Use the commands exactly as documented. Do not invent a variant.

- [ ] **Step 2: Build the section**

`Install.tsx` renders a `Section` with `rule`, an `Eyebrow n="01"` reading
`Install`, and a `Tabs` block (from `../ui/tabs`) with three triggers —
`macOS`, `Linux`, `Windows (WSL2)` — each content pane showing the real
command in a copy-to-clipboard row matching the Hero's install row styling.

- [ ] **Step 3: Mount it**

In `Landing.tsx`, insert `<Install />` between `<Hero />` and `<Features />`.

- [ ] **Step 4: Verify**

```bash
cd public && pnpm check
```

- [ ] **Step 5: Commit**

```bash
git add public/src/components/landing/Install.tsx public/src/components/landing/Landing.tsx
git commit -m "feat(site): add a per-platform install section"
```

---

### Task 12: Numbered feature walk — and fix two false claims

**The current `Features.tsx` advertises things that do not exist.** Fix them
here; do not carry them forward.

- `"Apple Virtualization on macOS 26+"` — that backend was **removed**. The
  macOS 26+ Apple Silicon default is HVF. `xtask check-no-vz` fails the build
  if the name returns to the codebase.
- `"mkPythonService, mkNodeService, mkStaticSite"` — `grep -rl mkPythonService nix/`
  returns nothing. These helpers do not exist. Delete the card or replace it
  with a capability that does.

**Files:**
- Modify: `public/src/components/landing/Features.tsx`

- [ ] **Step 1: Verify the claims yourself before rewriting**

```bash
grep -rln "mkPythonService\|mkNodeService\|mkStaticSite" nix/ ; echo "exit=$?"
grep -rn "Apple Virtualization" public/src/components/
```

Expected: no nix matches; two component matches to remove.

- [ ] **Step 2: Correct the backend card**

Rewrite the Multi-Backend description to: HVF on macOS 26+ Apple Silicon,
libkrun on macOS 13–25, Firecracker on Linux KVM. No shared-kernel fallback.
No mention of Apple Virtualization or Docker.

- [ ] **Step 3: Replace the Service Builders card**

Substitute a claim you can point at in the repo. `mvmctl doctor`,
`mvmctl cache prune`, the signed-`ExecutionPlan` admission path, and the
chain-signed audit log are all real and all documented under
`public/src/content/docs/`.

- [ ] **Step 4: Restyle onto the primitives**

Replace `Card`/`CardHeader` with `GlowCard`, add `Eyebrow n="02"` reading
`Capabilities`, wrap each card in `Reveal` with an 80ms-per-index stagger,
rotate `accent` across `1, 2, 3`, and drop the hand-rolled grid-background div
in favour of `Bloom`.

- [ ] **Step 5: Verify**

```bash
cd public && pnpm check && grep -rn "Apple Virtualization\|mkPythonService" src/components/ ; echo "expect no matches"
```

- [ ] **Step 6: Commit**

```bash
git add public/src/components/landing/Features.tsx
git commit -m "fix(site): correct the backend and tooling claims on the homepage"
```

---

### Task 13: Scroll-synced code walkthrough

The centrepiece. Steps scroll on the left; a code panel sticks on the right
and swaps as each step enters view. Native scrolling only — no scroll
hijacking, no pinning library.

**Files:**
- Create: `public/src/components/landing/Walkthrough.tsx`
- Modify: `public/src/components/landing/samples.ts`, `public/src/components/landing/Landing.tsx`

**Interfaces:**
- Consumes: `SAMPLES` from `./samples` (Task 2), `Section`/`Eyebrow` (Task 6),
  `CodeBlock` from `../ui/code-block`.

- [ ] **Step 1: Add the four walkthrough samples**

Add four entries to `SAMPLES` with ids `walk-define`, `walk-build`,
`walk-run`, `walk-result`, each a verbatim slice of a real file under
`examples/`. Read the files first:

```bash
cat examples/python/hello-app/app.py
cat examples/python/hello-app/README.md
cat examples/typescript/hello-app/*
```

- [ ] **Step 2: Run the provenance gate — it must pass**

```bash
cd public && node scripts/check-sample-provenance.mjs
```

Expected: PASS with 5 samples. If it fails, your slice is not verbatim.

- [ ] **Step 3: Write the component**

```tsx
import { useEffect, useRef, useState } from "react";
import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { CodeBlock } from "../ui/code-block";
import { SAMPLES } from "./samples";

const STEPS = [
  { id: "walk-define", title: "Define the workload", body: "A decorator marks the entrypoint. Nothing runs on your host — the file is parsed statically." },
  { id: "walk-build", title: "Build the image", body: "Nix builds the rootfs inside the builder VM. Cached, so rebuilds are near-instant." },
  { id: "walk-run", title: "Run it", body: "A real microVM with its own kernel. Network is deny-all unless policy admits it." },
  { id: "walk-result", title: "Read the result", body: "Output streams back over vsock. The run is recorded in the chain-signed audit log." },
];

export function Walkthrough() {
  const [active, setActive] = useState(0);
  const refs = useRef<Array<HTMLDivElement | null>>([]);

  useEffect(() => {
    // Reduced motion gets the stacked fallback rendered below instead, so
    // there is no observer to run at all.
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i));
        }
      },
      { rootMargin: "-45% 0px -45% 0px" },
    );
    refs.current.forEach((el) => el && io.observe(el));
    return () => io.disconnect();
  }, []);

  const sample = (id: string) => SAMPLES.find((s) => s.id === id)!;

  return (
    <Section rule>
      <Eyebrow n="03">How it works</Eyebrow>
      <h2 className="mb-16 font-display text-3xl font-bold text-title sm:text-4xl">
        From a file to a running microVM
      </h2>

      {/* Scroll-synced layout, hidden when motion is reduced. */}
      <div className="site-walk grid gap-12 lg:grid-cols-2">
        <div className="flex flex-col gap-[40vh]">
          {STEPS.map((s, i) => (
            <div
              key={s.id}
              data-i={i}
              ref={(el) => { refs.current[i] = el; }}
              className={`transition-opacity duration-500 ${active === i ? "opacity-100" : "opacity-40"}`}
            >
              <Eyebrow n={String(i + 1).padStart(2, "0")}>{s.title}</Eyebrow>
              <p className="max-w-md text-lg leading-relaxed text-body">{s.body}</p>
            </div>
          ))}
        </div>
        <div className="hidden lg:block">
          <div className="sticky top-32">
            <CodeBlock code={sample(STEPS[active].id).code} language={sample(STEPS[active].id).language} />
          </div>
        </div>
      </div>

      {/* Stacked fallback: reduced motion, and every viewport below lg. */}
      <div className="site-walk-static flex flex-col gap-12 lg:hidden">
        {STEPS.map((s, i) => (
          <div key={s.id}>
            <Eyebrow n={String(i + 1).padStart(2, "0")}>{s.title}</Eyebrow>
            <p className="mb-4 max-w-md text-lg leading-relaxed text-body">{s.body}</p>
            <CodeBlock code={sample(s.id).code} language={sample(s.id).language} />
          </div>
        ))}
      </div>
    </Section>
  );
}
```

- [ ] **Step 4: Wire the reduced-motion swap in CSS**

Append to `public/src/styles/custom.css`:

```css
@media (prefers-reduced-motion: reduce) {
  .site-walk { display: none; }
  .site-walk-static { display: flex; }
}
```

- [ ] **Step 5: Mount it**

In `Landing.tsx`, insert `<Walkthrough />` after `<Features />`.

- [ ] **Step 6: Verify all three paths**

```bash
cd public && pnpm check && pnpm dev
```

Confirm: (a) desktop — code panel sticks and swaps as you scroll;
(b) narrow viewport — stacked list, every step has its own code block;
(c) reduced-motion emulation at desktop width — stacked list, no swapping.

- [ ] **Step 7: Commit**

```bash
git add public/src/components/landing/Walkthrough.tsx public/src/components/landing/samples.ts public/src/components/landing/Landing.tsx public/src/styles/custom.css
git commit -m "feat(site): add a scroll-synced code walkthrough"
```

---

### Task 14: SDK and CLI tab block

**Files:**
- Create: `public/src/components/landing/Surfaces.tsx`
- Modify: `public/src/components/landing/samples.ts`, `public/src/components/landing/Landing.tsx`, `public/scripts/check-sample-provenance.mjs`

- [ ] **Step 1: Capture the real CLI help output**

```bash
cargo run -q -- machine run --help > /tmp/mvmctl-run-help.txt && cat /tmp/mvmctl-run-help.txt
```

Save a verbatim slice into `SAMPLES` with `id: "cli-run"`,
`source: "cli-help"`, `language: "bash"`.

- [ ] **Step 2: Teach the gate to check CLI samples too**

Replace the `if (s.source === "cli-help") continue;` line in
`check-sample-provenance.mjs` with a check that shells out to the real
command and asserts the sample is a slice of its output:

```js
  if (s.source === "cli-help") {
    const { execFileSync } = await import("node:child_process");
    let out = "";
    try {
      out = execFileSync("cargo", ["run", "-q", "--", ...s.helpArgs], {
        cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      failures.push(`${s.id}: could not run 'mvmctl ${s.helpArgs.join(" ")}'`);
      continue;
    }
    if (!out.replace(/\r\n/g, "\n").includes(s.code.trim())) {
      failures.push(`${s.id}: does not match real 'mvmctl ${s.helpArgs.join(" ")}' output`);
    }
    continue;
  }
```

Add `helpArgs: ["machine", "run", "--help"]` to the `cli-run` sample.

- [ ] **Step 3: Prove the extended gate bites**

Edit one character of the `cli-run` sample, run
`node scripts/check-sample-provenance.mjs`, confirm FAIL, revert, confirm PASS.

- [ ] **Step 4: Add the three SDK samples**

Read the real SDK surfaces and take verbatim slices:

```bash
cat crates/mvm-sdk/sdks/python/README.md
cat crates/mvm-sdk/sdks/typescript/README.md
cat crates/mvm-sdk/README.md
```

Add `sdk-python`, `sdk-node`, `sdk-rust` to `SAMPLES` with sources pointing at
those README paths. **Note there is no `sdks/rust` directory** — the Rust
surface is the `mvm-sdk` crate itself.

- [ ] **Step 5: Write the component**

`Surfaces.tsx` renders a `Section` with `Eyebrow n="04"` reading
`SDKs and CLI`, a headline making the point that the same task is expressible
four ways, and a `Tabs` block with four triggers — `Python`, `Node.js`,
`Rust`, `CLI` — each pane a `CodeBlock` fed from `SAMPLES`. Below the tabs,
four links into the docs: `sdk/python/`, `sdk/nodejs/`, `sdk/rust/`,
`reference/cli-commands/`.

- [ ] **Step 6: Mount it and verify keyboard access**

Insert `<Surfaces />` after `<Walkthrough />` in `Landing.tsx`. Then tab
through the trigger row: each trigger must be reachable and activate on
Enter and Space. `ui/tabs.tsx` renders real `<button>` elements, so this
should hold — confirm it rather than assume it.

- [ ] **Step 7: Verify**

```bash
cd public && pnpm check
```

- [ ] **Step 8: Commit**

```bash
git add public/src/components/landing/Surfaces.tsx public/src/components/landing/samples.ts public/src/components/landing/Landing.tsx public/scripts/check-sample-provenance.mjs
git commit -m "feat(site): show the same task across the three SDKs and the CLI"
```

---

### Task 15: Architecture section — and fix two more false claims

`Architecture.tsx` currently says mvmctl detects "Apple Virtualization, and
Docker". Both are wrong: the Apple Virtualization backend was removed, and
there is no Docker on any runtime path — that is a core project invariant.

**Files:**
- Modify: `public/src/components/landing/Architecture.tsx`

- [ ] **Step 1: Confirm the offending lines**

```bash
grep -n "Apple Virtualization\|Docker" public/src/components/landing/Architecture.tsx
```

- [ ] **Step 2: Correct the detection copy**

Rewrite to the real selection rule: mvmctl detects the platform and picks
HVF on macOS 26+ Apple Silicon, libkrun on macOS 13–25, and Firecracker on
Linux KVM. Remove every mention of Docker and Apple Virtualization.

- [ ] **Step 3: Restyle onto the primitives**

`Section` + `Eyebrow n="05"` + `Bloom accents={[2]}`, diagram nodes as
`GlowCard`, whole block wrapped in `Reveal`.

- [ ] **Step 4: Verify**

```bash
cd public && pnpm check && grep -rn "Apple Virtualization\|Docker" src/components/ ; echo "expect no matches"
```

- [ ] **Step 5: Commit**

```bash
git add public/src/components/landing/Architecture.tsx
git commit -m "fix(site): correct the backend-detection description in the architecture section"
```

---

### Task 16: Security section

**Files:**
- Create: `public/src/components/landing/Security.tsx`
- Modify: `public/src/components/landing/Landing.tsx`

- [ ] **Step 1: Take the claims from the real ledger**

The authoritative source is the claims table in
`specs/adrs/001-microvm-security-posture.md`. Pick four claims that are
**numbered and enforced** — not the two `Preview` claims (16 and 17), which
carry limits that a homepage card cannot fairly summarise. Good candidates:
claim 3 (a tampered rootfs fails to boot), claim 10 (default-deny egress),
claim 13 (no raw secret crosses the broker channel), claim 15 (a sealed
production microVM has no shell, no DevOnly verbs, no PTY).

- [ ] **Step 2: Write the section**

`Section rule` + `Eyebrow n="06"` reading `Security`, four `GlowCard`s each
with the claim in plain language and a link into the matching page under
`public/src/content/docs/security/`. Wrap in `Reveal` with stagger.

- [ ] **Step 3: State the posture honestly**

Add one line under the headline noting these are CI-enforced claims with named
witnesses, and link to `security/claim-ledger/`. Do not write "unhackable",
"provably secure", or any absolute — the ADR names what is out of scope
(a malicious host, multi-tenant guests, hardware-backed key attestation) and
the homepage must not contradict it.

- [ ] **Step 4: Mount and verify**

```bash
cd public && pnpm check
```

- [ ] **Step 5: Commit**

```bash
git add public/src/components/landing/Security.tsx public/src/components/landing/Landing.tsx
git commit -m "feat(site): add a security-claims section linked to the ledger"
```

---

### Task 17: CTA and Footer

**Files:**
- Modify: `public/src/components/landing/CTABanner.tsx`, `public/src/components/landing/Footer.tsx`

- [ ] **Step 1: Restyle the CTA**

Replace the hand-rolled `bg-accent/5 blur-[120px]` div with
`<Bloom accents={[1, 3]} />`, switch the section wrapper to `Section`, apply
`font-display` to the `h2`, and wrap the contents in `Reveal`.

- [ ] **Step 2: Fix the CTA copy**

It currently promises "a running Firecracker VM in minutes" — wrong on macOS,
where the backend is HVF or libkrun. Reword to be backend-neutral.

- [ ] **Step 3: Restyle the footer**

Column headings in mono uppercase to match `Eyebrow`; hairline top border
using `border-glass-border/60`.

- [ ] **Step 4: Verify**

```bash
cd public && pnpm check
```

- [ ] **Step 5: Commit**

```bash
git add public/src/components/landing/CTABanner.tsx public/src/components/landing/Footer.tsx
git commit -m "feat(site): restyle the closing CTA and footer"
```

---

### Task 18: Docs chrome — header, sidebar, TOC

**Files:**
- Modify: `public/src/overrides/Header.astro`, `public/src/styles/custom.css`

- [ ] **Step 1: Make the header sticky with a hairline**

In `Header.astro`, apply a `position: sticky; top: 0` bar with
`backdrop-filter: blur(12px)`, a background of
`color-mix(in oklab, var(--color-page) 80%, transparent)`, and a
`border-bottom: 1px solid var(--color-glass-border)` in place of the current
solid treatment.

- [ ] **Step 2: Restyle the sidebar group labels**

In `custom.css`, target Starlight's sidebar group headings and set
`font-family: var(--font-mono)`, uppercase, `letter-spacing: 0.16em`,
`font-size: 0.7rem`, `color: var(--color-label)`. Add a
`border-left: 1px solid var(--color-edge)` indent rail on nested lists.

- [ ] **Step 3: Match the right-hand TOC**

Apply the same label treatment to the "On this page" heading and route the
active-item marker through `var(--color-accent)`.

- [ ] **Step 4: Verify in both schemes at two widths**

Run `pnpm dev`, open a docs page, check the header blur and sidebar rail in
light and dark, at desktop and at a width where the sidebar collapses to the
mobile menu. The blurred header must not swallow the mobile nav toggle.

- [ ] **Step 5: Commit**

```bash
git add public/src/overrides/Header.astro public/src/styles/custom.css
git commit -m "feat(site): restyle the docs header, sidebar, and table of contents"
```

---

### Task 19: Docs prose and code frames

**Files:**
- Modify: `public/src/styles/custom.css`, `public/src/overrides/MarkdownContent.astro`

- [ ] **Step 1: Retune the prose scale**

Update the existing "Typography", "Docs content headings", and "Docs
paragraphs" blocks in `custom.css` against `--font-display`. Set the content
measure to `68ch`. Headings get `font-family: var(--font-display)` and tighter
tracking; body keeps its current generous line-height.

- [ ] **Step 2: Match code frames to the card treatment**

Update the `expressiveCode.styleOverrides` in `public/astro.config.mjs` —
`borderRadius: "0.75rem"` already matches `GlowCard`; change `borderColor` to
reference the token rather than the hardcoded `#30363d` it currently carries.
The existing inline comment already admits it is overridden by `custom.css`;
remove the duplication rather than leave two sources of truth.

- [ ] **Step 3: Restyle tables and callouts**

Give tables the same `border-glass-border` hairline and `0.75rem` radius;
leave Starlight's per-type aside tints alone — `custom.css` already explains
why they are deliberately not pinned, and they work in both schemes.

- [ ] **Step 4: Verify against a heavy page**

Open `getting-started/quickstart/` and `reference/cli-commands/` — long prose,
many code blocks, tables, and callouts — in both schemes.

- [ ] **Step 5: Verify**

```bash
cd public && pnpm check
```

- [ ] **Step 6: Commit**

```bash
git add public/src/styles/custom.css public/src/overrides/MarkdownContent.astro public/astro.config.mjs
git commit -m "feat(site): retune docs prose, tables, and code frames"
```

---

### Task 20: Final verification and screenshot matrix

**Files:**
- Create: `/tmp/mvm-site-shots/` (scratch — **never** inside the repo tree)

- [ ] **Step 1: Full gate run**

```bash
cd public && pnpm check
```

Expected: token gate PASS, sample gate PASS, build clean.

- [ ] **Step 2: Confirm no stale claim survived anywhere in the site source**

```bash
grep -rn "Apple Virtualization\|mkPythonService\|mkNodeService\|mkStaticSite" public/src/components/ ; echo "expect no matches"
grep -rn "fonts.googleapis" public/src/ ; echo "expect no matches"
```

- [ ] **Step 3: Screenshot matrix**

Serve the built site and capture, into `/tmp/mvm-site-shots/`:

| Page | Scheme | Width |
| --- | --- | --- |
| `/` | dark | 1440 |
| `/` | light | 1440 |
| `/` | dark | 390 |
| `/` | dark, reduced-motion | 1440 |
| `/getting-started/quickstart/` | dark | 1440 |
| `/getting-started/quickstart/` | light | 1440 |

```bash
cd public && pnpm preview
```

- [ ] **Step 4: Check the reduced-motion shot specifically**

In that screenshot the walkthrough must be the stacked list with a code block
per step, and all content must be visible. If anything is missing, `Reveal`
is hiding content — that is a release blocker, not a polish item.

- [ ] **Step 5: Keyboard pass**

Tab from the top of the homepage to the footer. Every link, button, and tab
trigger must show a visible focus ring against both schemes.

- [ ] **Step 6: Update the plan docs**

Tick the verification checklist in `specs/plans/316-website-redesign.md`,
mark it `Status: COMPLETE`, and add a line to `specs/REFACTOR-STATUS.md` with
today's date. Project rule: the plan doc, the sprint spec, and the rollup move
in the same change as the work.

- [ ] **Step 7: Commit**

```bash
git add specs/plans/316-website-redesign.md specs/REFACTOR-STATUS.md
git commit -m "docs(plan 316): mark the website redesign complete"
```

---

## Self-review notes

**Spec coverage.** Tokens → Task 4/5. Primitives → Tasks 6–9. Homepage
sections 1–8 → Tasks 10–17. Docs chrome + prose → Tasks 18–19. Verification →
Tasks 2, 3, 20. Light+dark → Global Constraints plus explicit steps in Tasks
4, 8, 18, 19. Reduced motion → Tasks 7, 8, 9, 13, 20. Real code samples →
Tasks 2, 13, 14.

**Added beyond the spec, with cause.** Tasks 12 and 15 fix four factual errors
found in the existing components while reading them for this plan: the
homepage advertises the removed Apple Virtualization backend, Docker detection
that contradicts a core invariant, and three Nix service builders that do not
exist in the tree. Task 5 also removes a third-party CDN font fetch. These are
in scope because this plan rewrites the exact components carrying them;
shipping a redesign that preserves false claims would be worse than not
redesigning.

**Known gap, accepted.** No visual regression testing. Verification is a build,
two real gates, and a human-reviewed screenshot matrix. Adding VRT
infrastructure is a larger piece of work than this redesign and belongs in its
own plan.
