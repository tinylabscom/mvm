---
name: web-researcher
description: |
  Autonomous web research that searches, synthesizes, and saves structured reports.
  Runs in background for overnight batch research.
  Outputs to ~/handoff/research/ with full source citations.
---

# Web Researcher Skill

Conducts autonomous research, synthesizes findings, and produces structured reports with citations.

## Quick Start

1. Configure search provider in `openclaw.json` (Perplexity, Exa, or Brave Search)
2. Ask: `Research what VSL frameworks top marketers are using in 2026`
3. Review plan, approve cost, and get your report at `~/handoff/research/`

## When to Use

- Competitive analysis
- Market research
- Technical investigation
- Trend analysis
- Due diligence on companies or tools

## Configuration

```json
{
  "skills": {
    "web-researcher": {
      "enabled": true,
      "config": {
        "outputDir": "~/handoff/research/",
        "searchProvider": "perplexity",
        "searchAPIKey": "env:PERPLEXITY_API_KEY",
        "maxSourcesPerQuery": 20,
        "saveRawData": true,
        "credibilityScoring": true,
        "costLimit": {
          "perQuery": 1.00,
          "requireApproval": true
        }
      }
    }
  }
}
```

### MCP-Powered Search (Advanced)

For deeper research, connect MCP search servers:

```json
{
  "mcp": {
    "exa": { "command": "npx", "args": ["-y", "@anthropic/mcp-server-exa"] },
    "brave-search": { "command": "npx", "args": ["-y", "@anthropic/mcp-server-brave-search"] }
  }
}
```

MCP search servers give the researcher direct access to search APIs without going through a wrapper. Results are more structured and often higher quality than browser-based searching.

## How It Works

1. **Parses your question** and builds a search plan (queries, source types, estimated cost)
2. **Shows you the plan** before spending anything -- you approve or adjust
3. **Runs searches** via configured API, extracts key information per source
4. **Synthesizes findings** -- identifies patterns, flags contradictions, ranks credibility
5. **Generates report** at `~/handoff/research/{topic}/report-{date}.md`

## Report Structure

```
~/handoff/research/{topic}/
  report-{date}.md        # Executive summary + key findings + source analysis
  raw/                    # Raw extraction from each source
  search-log.json         # What was searched and when
```

Each report includes:
- Executive summary (2-3 paragraphs)
- Key findings with evidence and citations
- Source credibility ranking (High/Medium/Low)
- Gaps and limitations
- Full source list with URLs

## Example Usage

### Via Chat

```
You: Research VSL frameworks used by top marketers in 2026

Agent: Plan: 8 search queries, ~24 sources expected
       Estimated cost: $0.35 | Time: 10 minutes
       Approve? (yes/no/adjust)

You: yes

Agent: Report ready: ~/handoff/research/vsl-frameworks-2026/report-2026-02-03.md
       Key finding: Story-first frameworks dominating, PAS declining
```

### Via Command

```bash
openclaw skill web-researcher run \
  --query "Best practices for securing AI agents in 2026" \
  --depth comprehensive \
  --output ~/handoff/research/ai-security/
```

### Overnight Batch

Create `~/inbox/research-queue/batch.txt` with queries separated by `---`, then:

```bash
openclaw skill web-researcher batch ~/inbox/research-queue/batch.txt --schedule 2am
```

Wake up to finished reports.

## Cost Control

- Every query shows estimated cost before execution
- Set per-query limits in config (`costLimit.perQuery`)
- Use budget models for non-critical research (MiniMax at 1/5 the cost)
- Quick scans (5-10 sources): $0.10-0.25
- Detailed research (15-25 sources): $0.30-0.60

## Tips

- **Specific queries get better results.** "AI agent frameworks with local-first architecture comparing security and cost" beats "AI tools."
- **Define success criteria.** Tell it how many sources you need and what questions must be answered.
- **Chain with content-writer.** Research first, then write a blog post using the findings.
- **Review raw data.** If synthesis feels off, check `raw/` folder for source material.
