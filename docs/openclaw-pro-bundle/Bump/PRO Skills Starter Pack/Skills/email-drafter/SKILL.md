---
name: email-drafter
description: |
  Drafts emails and sequences based on USER.md tone and style.
  Reads inbox/, outputs drafts to ~/handoff/drafts/ for review before sending.
  Never sends automatically without explicit approval.
---

# Email Drafter Skill

Drafts emails matching your voice, reads thread context, and prepares sequences. Always drafts first, never auto-sends.

## Quick Start

1. Add your email style to `USER.md` (tone, sign-off preferences, examples)
2. Tell your agent: `Draft a reply to John's project update email`
3. Review the draft at `~/handoff/drafts/`, then send manually

## When to Use

- Replying to emails (reads thread context first)
- Cold outreach sequences (3-7 emails with delays)
- Newsletter drafts
- Onboarding email flows
- Templating common replies (support, sales, partnerships)

## Configuration

```json
{
  "skills": {
    "email-drafter": {
      "enabled": true,
      "config": {
        "inboxDir": "~/inbox/email-to-reply/",
        "outputDir": "~/handoff/drafts/",
        "templatesDir": "~/templates/",
        "toneMatching": true,
        "maxThreadDepth": 5,
        "signatures": {
          "default": "Best,\n[Your Name]",
          "formal": "Regards,\n[Your Name]\n[Title]",
          "casual": "Thanks,\n[Your Name]"
        },
        "sequenceDefaults": {
          "onboarding": { "emails": 5, "delays": [0, 2, 5, 10, 20] },
          "outreach": { "emails": 3, "delays": [0, 3, 7] }
        }
      }
    }
  }
}
```

### Gmail Integration (Advanced)

Connect directly to Gmail via MCP:

```json
{
  "mcp": {
    "gmail": { "command": "npx", "args": ["-y", "composio-mcp-server-gmail"] }
  }
}
```

With Gmail MCP connected, the email drafter can:
- Read your inbox directly (no manual .eml export needed)
- Access full thread history for better reply context
- Draft replies that match your actual email voice (learned from sent folder)

Note: This requires OAuth authentication. Run `openclaw mcp setup gmail` and follow the browser auth flow.

## How It Works

### Four Drafting Modes

**Reply**: Drop `.eml` file in `~/inbox/email-to-reply/`. Skill reads thread, extracts context, drafts reply matching the sender's tone.

**New Email**: Provide recipient, subject, key points. Skill drafts in your style from USER.md.

**Sequence**: Specify goal (onboarding, outreach, nurture). Skill drafts 3-7 emails with delays between each.

**Template**: Request a reusable template with `{placeholders}`. Save to `~/templates/` for future use.

### Output Format

Every draft includes metadata and drafting notes:

```markdown
---
to: john@acmecorp.com
subject: Re: VSL feedback - iteration 3
drafted: 2026-02-03
tone: professional-warm
---

Hi John,

Thanks for the detailed feedback on iteration 3...

---
DRAFTING NOTES:
- Used professional-warm tone to match his style
- Offered 3 options (his preference from previous emails)
- Specific timeline (he values concrete commitments)
```

## Example Usage

### Reply to Email

```
You: [Forward email to ~/inbox/email-to-reply/]
     Draft a reply

Agent: Thread: 4 messages | Tone: Professional, detail-oriented
       Key: He likes intro, section 2 needs work, wants alternatives
       Draft ready: ~/handoff/drafts/reply-vsl-feedback-2026-02-03.md
```

### Email Sequence

```
You: Create cold outreach sequence for SaaS founders
     Product: OpenClaw | Goal: Book demo calls | Emails: 3

Agent: Email 1 (Day 0): Introduction + value prop
       Email 2 (Day 3): Case study + social proof
       Email 3 (Day 7): Final attempt + alternative resource
       Sequence ready: ~/handoff/drafts/sequence-saas-outreach-2026-02-03.md
```

### Via Command

```bash
openclaw skill email-drafter reply ~/inbox/email.eml
openclaw skill email-drafter new --to sarah@example.com --subject "Q1 priorities" --brief "Confirm feature X, hiring update, ask for timeline"
openclaw skill email-drafter sequence --type outreach --audience "SaaS founders" --goal "book demos"
```

## Safety

- **Never auto-sends.** Every email is a draft. You review and send manually.
- **Flags sensitive content.** Pricing, legal terms, and personal info get warning labels.
- **Templates require all placeholders filled.** Can't accidentally send `{customer_name}`.

## Tips

- **Maintain USER.md.** Include tone per recipient type (clients = professional-warm, team = casual-direct).
- **Provide context in briefs.** "Reply to John's VSL feedback, offer 3 alternatives, 48hr timeline" beats "reply to John."
- **Build a template library.** Common replies (feature declined, demo follow-up, partnership intro) save hours over time.
- **Use budget models for routine emails.** MiniMax for internal, Claude for client-facing.
