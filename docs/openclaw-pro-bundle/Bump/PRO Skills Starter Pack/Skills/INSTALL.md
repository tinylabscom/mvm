# Install All 5 Skills

## One-Command Install

```bash
cp -r content-writer web-researcher calendar-manager email-drafter file-organizer ~/.openclaw/skills/
openclaw skills list
openclaw skills check
```

## Verify

```bash
openclaw skills list
```

You should see all five: `content-writer`, `web-researcher`, `calendar-manager`, `email-drafter`, `file-organizer`.

## Install a Single Skill

```bash
cp -r content-writer ~/.openclaw/skills/
openclaw skills list
openclaw skills check
```

## Enable in Config

Each skill must be enabled in `~/.openclaw/openclaw.json`:

```json
{
  "skills": {
    "content-writer": { "enabled": true },
    "web-researcher": { "enabled": true },
    "calendar-manager": { "enabled": true },
    "email-drafter": { "enabled": true },
    "file-organizer": { "enabled": true }
  }
}
```

## Troubleshooting

**Skills not showing up?** Check `ls ~/.openclaw/skills/` -- each folder needs a `SKILL.md` file. Then run `openclaw gateway restart` and re-check with `openclaw skills list`.

**Permission denied?** Run `chmod -R 755 ~/.openclaw/skills/`

## Want More Skills?

The OpenClaw community has built hundreds of additional skills:

- **awesome-claude-skills** repos on GitHub (ComposioHQ, travisvn collections)
- **bestclaudecodeskills.com** -- curated directory of community skills
- **MCP integrations** -- connect to Gmail, GitHub, Slack, HubSpot, and 50+ services via Model Context Protocol servers

The 5 skills in this pack are the most-requested daily drivers. But the ecosystem is massive and growing.

To install community skills:

```bash
cp -r /path/to/community-skill ~/.openclaw/skills/
openclaw skills list
openclaw skills check
```
