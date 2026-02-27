---
name: content-writer
description: |
  Writes polished content for multiple platforms (blog posts, social media, emails).
  Matches tone and style from USER.md preferences.
  Outputs drafts to ~/handoff/drafts/ for review.
---

# Content Writer Skill

Transforms briefs into platform-specific content that matches your voice.

## Quick Start

1. Add your writing style to `USER.md` (tone, vocabulary, examples of your writing)
2. Tell your agent what to write: `Write a LinkedIn post about local AI agents`
3. Review the draft at `~/handoff/drafts/`

## When to Use

- Blog posts and articles
- Social media (tweets, LinkedIn posts, threads)
- Email newsletters
- Repurposing content across formats
- First drafts that need light editing, not full rewrites

## Configuration

```json
{
  "skills": {
    "content-writer": {
      "enabled": true,
      "config": {
        "outputDir": "~/handoff/drafts/",
        "defaultStyle": "professional-casual",
        "platforms": {
          "twitter": { "maxLength": 280, "threadMaxTweets": 15 },
          "linkedin": { "maxLength": 3000, "preferredLength": 1200 },
          "blog": { "minLength": 800, "maxLength": 2500 },
          "email": { "preferredLength": 500 }
        },
        "includeAlternatives": true
      }
    }
  }
}
```

## How It Works

1. **Reads USER.md** for your writing style, tone, vocabulary, platform preferences
2. **Parses your brief** -- accepts natural language or structured format
3. **Generates content** structured for the target platform with CTAs and metadata
4. **Saves draft** to `~/handoff/drafts/{format}-{slug}-{date}.md` with revision notes

## Brief Formats

Natural language:

```
Write a LinkedIn post about the security benefits of local-first AI agents.
Keep it under 300 words, professional but approachable.
```

Structured:

```
Format: blog
Topic: Why OpenClaw beats traditional automation
Target: Technical founders who use Claude
Length: 1200 words
CTA: Link to setup guide
```

## Example Usage

### Via Chat

```
You: Write a blog post about the file-organizer skill, 1000 words

Agent: Draft complete: ~/handoff/drafts/blog-file-organizer-skill-2026-02-03.md
       Word count: 1,047 | Reading time: 4 min
       Want me to create a Twitter thread version?
```

### Via Command

```bash
openclaw skill content-writer run \
  --format twitter \
  --topic "OpenClaw + Tailscale for remote access" \
  --length thread \
  --style technical-casual
```

### Batch Mode

Create `~/inbox/content-briefs/batch.txt` with multiple briefs separated by `---`, then:

```bash
openclaw skill content-writer batch ~/inbox/content-briefs/batch.txt
```

## Output

Each draft includes:
- The content itself
- Metadata (platform, word count, reading time, tags)
- Revision notes (what to check before publishing)
- Alternative headlines

## Tips

- **Better USER.md = better output.** Include 3-5 writing samples that capture your voice.
- **Specific briefs win.** Include angle, target audience, and CTA -- not just "write about X."
- **Combine with web-researcher.** "Research X, then write a blog post about it."
- **Use budget models for drafts.** MiniMax for first drafts, Claude for final polish.
