# The Handoff Structure

A simple system for working with your AI agent. Six folders, clear roles.

---

## The Concept

Without structure, working with an AI agent becomes chaos. Files get lost, you can't tell what's in progress vs done, and your agent doesn't know where to look for work.

The Handoff Structure fixes this with six folders:

```
~/handoff/
├── inbox/        Drop tasks here. Agent checks this first.
├── research/     Agent's working notes and findings.
├── drafts/       Work in progress. Agent puts drafts here for your review.
├── ready/        Completed deliverables, ready to use.
├── playground/   Experimental space. Agent builds prototypes here.
└── archive/      Completed projects moved here after use.
```

---

## Quick Setup

```bash
mkdir -p ~/handoff/{inbox,research,drafts,ready,playground,archive}
```

Add this to your SOUL.md:

```markdown
## Handoff Protocol
1. Check inbox/ for new tasks first
2. Store research notes in research/
3. Put drafts in drafts/ and notify me
4. Move final work to ready/ after my approval
5. Use playground/ for experiments and prototypes
6. Don't touch archive/ (I manage that)
```

---

## How It Works

### You drop a task in inbox/

Create a file like `inbox/write-blog-post.txt`:
```
Write a blog post about OpenClaw security best practices.
1,000 words. Practical tone.
Output to: drafts/blog-openclaw-security.md
```

### Agent processes it

1. Reads the task
2. Does research (notes go in `research/`)
3. Writes a draft (goes in `drafts/`)
4. Notifies you: "Draft ready for review"

### You review and approve

1. Open the draft, add feedback
2. Agent revises based on your notes
3. Final version moves to `ready/`
4. After you use it, move to `archive/`

---

## Daily Workflow

**Morning:** Check `ready/` for overnight work. Review `drafts/` for things needing feedback.

**During the day:** Drop tasks in `inbox/` as they come up. Review drafts when notified.

**Evening:** Drop overnight tasks in `inbox/`. Clean up `ready/` by archiving finished work. Check `playground/` to see what the agent experimented with.

---

## Tips

- **Keep tasks specific.** "Write a blog post about X, 1000 words, practical tone" beats "write something."
- **One task per file.** Don't put 5 requests in one file.
- **Let MEMORY.md build naturally.** Don't edit it. Your agent learns your preferences over time.
- **Check playground/ occasionally.** Your agent sometimes builds useful tools there on its own.

---

## For Multi-Machine Setups

If you run OpenClaw on a separate machine and want to sync your handoff folder, see `Going Deeper/Security/tailscale-setup.md` for secure remote access. A simple rsync over Tailscale keeps both machines in sync:

```bash
rsync -avz ~/handoff/ user@100.x.x.x:~/handoff/
```
