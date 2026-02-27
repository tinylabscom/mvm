# OpenClaw Setup Kit — Changelog

## v4.0.0 - Feb 17, 2026

**Shipping version focused on "it just works" for complete beginners.**

### What Changed

- Rebuilt `Setup.command` for a single reliable flow on both macOS and Linux/VPS.
- Removed manual Node.js dead-end steps. The script now uses the official OpenClaw installer (which handles Node.js as needed).
- Replaced fragile onboarding flags with documented non-interactive defaults, with an automatic fallback to guided quickstart.
- Added proper headless/VPS handling:
  - no browser assumptions on SSH sessions
  - prints an SSH tunnel command to open the dashboard safely from local machine
- Added `Setup-VPS.sh` as a clear Linux/VPS entrypoint.
- Added `START HERE.txt` for plain-text onboarding and marketplace compatibility.
- Updated `START HERE.md` with separate Mac and VPS instructions.

### Why

Previous versions still had avoidable failure modes (manual Node install loop, outdated references, and local-browser assumptions on VPS). This release optimizes for the actual buyer: non-technical users who need a working install without touching advanced setup options.

---

## v3.0.0 - Feb 17, 2026

**Rebuilt for complete beginners.** The product now assumes zero terminal experience.

### What Changed

- **START HERE.md** replaced the original brief text onboarding file with a more detailed beginner guide.
- **Setup.command** replaced older platform-specific and legacy setup scripts.
- Setup flow shifted to `openclaw onboard` for config generation instead of manual `openclaw.json` templates.
- **Removed `Day 1/Before You Start.md`** — absorbed into START HERE.md
- **Removed `Day 1/openclaw.json`** — openclaw onboard generates config now, reference file no longer needed
- **Updated `Day 1/Your First Conversation.md`** — refreshed for new flow
- **Going Deeper/** and **Bump/** — unchanged

### Why

The v2 product had a chicken-and-egg problem: `setup.sh` generated an incomplete `openclaw.json` that conflicted with what `openclaw onboard` creates (missing auth profiles, model definitions, meta tracking). The fix: let OpenClaw's own wizard handle all plumbing, and let the kit handle what OpenClaw doesn't — personality, guidance, and hand-holding for beginners.

---

## v2.0.0 - Feb 16, 2026

**Complete product restructure.** Replaced documentation dump with guided beginner experience.

### Problem
The v1 product was 38 files across 7 folders with 30+ placeholder fields, 3 platform-specific scripts requiring manual editing, and security/cost/workflow content all presented on Day 1.

### Solution
Single interactive script (setup.sh) asks 6 questions and generates everything. Zero placeholders.

---

## v1.0.0 - Initial Release

Original product with platform-specific scripts, template files, and comprehensive documentation.
