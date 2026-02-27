# Full Cost Control Guide

Everything you need to keep your agent costs predictable. For quick basics, see `Day 1/Cost Basics.md`.

---

## Model Pricing (Current)

| Model | Input (per 1M tokens) | Output (per 1M tokens) | Typical task cost |
|-------|----------------------|------------------------|-------------------|
| Claude Haiku 3.5 | $0.80 | $4.00 | $0.02-0.05 |
| Claude Sonnet 4 | $3.00 | $15.00 | $0.10-0.30 |
| Claude Opus 4.5 | $15.00 | $75.00 | $1.00-3.00 |
| GPT-4o mini | $0.15 | $0.60 | $0.01-0.03 |
| GPT-4o | $2.50 | $10.00 | $0.08-0.25 |
| MiniMax (subscription) | ~$0.14 | ~$0.70 | $14/month flat |

**1 million tokens** is roughly 750,000 words. A typical task uses 5,000-20,000 input tokens and 2,000-10,000 output.

---

## Monthly Cost Scenarios

### Light Use: $15-25/month
- 5-10 tasks per day
- Mostly Haiku for file ops, some Sonnet for writing
- Hardware: your existing computer (no server cost)

### Moderate Use: $40-75/month (recommended sweet spot)
- 20-30 tasks per day
- Sonnet as default, Haiku for file ops, rare Opus
- Hardware: Mac Mini or existing machine

### Heavy Use: $100-200/month
- 50+ tasks per day
- Frequent Sonnet and occasional Opus
- With optimization (caching, batching): can be reduced 30-40%

### Budget Option: $14/month
- MiniMax subscription for unlimited calls
- Lower quality than Claude but workable for learning
- Or: Haiku-only on existing hardware (~$15/month)

---

## Cost Control Strategies

### 1. Model Selection Rules

Use the cheapest model that can handle the task:

| Task type | Use this model | Why |
|-----------|---------------|-----|
| Reading/writing files | Haiku | No reasoning needed, 3x cheaper |
| Simple edits, formatting | Haiku | Mechanical work |
| Quick factual answers | Haiku | Speed matters more than depth |
| Research and analysis | Sonnet | Best quality/cost ratio |
| Writing (blogs, emails, copy) | Sonnet | Publication-quality output |
| Code generation | Sonnet | Strong at code, good balance |
| Complex multi-step reasoning | Opus | Only when Sonnet falls short |
| High-stakes decisions | Opus | When accuracy justifies 5x cost |

Configure in `~/.openclaw/openclaw.json`:

```json
{
  "models": {
    "default": "claude-sonnet-4-20250514",
    "fast": "claude-haiku-3-5-20241022",
    "powerful": "claude-opus-4-5-20251101"
  },
  "auto_model_selection": true
}
```

### 2. Add Cost Awareness to SOUL.md

Add this section to your agent's SOUL.md:

```markdown
## Cost Management
- Daily budget: $5 (adjust to your comfort)
- At 50% of budget: switch to Haiku for non-critical tasks
- At 80% of budget: notify me before proceeding
- At 100%: pause and wait for my approval
- Never process more than 50 files without asking first
- Summarize findings between tool calls to reduce context size
```

### 3. Cache Research

Create a knowledge base so your agent doesn't re-research the same topics:

Add to SOUL.md:
```markdown
Before researching a topic, check MEMORY.md for existing findings.
If information exists and is less than a week old, use it.
```

Savings: 20-40% reduction on research-heavy workflows.

### 4. Batch Processing

Instead of 10 separate tasks (10 separate API calls with 10x context overhead), batch related work:

```
Process all 5 files in inbox/ together:
- Read all files first
- Analyze as a group
- Generate outputs in one pass
```

Savings: 40-60% on multi-file operations.

### 5. API Dashboard Alerts

**Anthropic (console.anthropic.com/settings/billing):**
- Set alert at $25 (early warning)
- Set alert at $50 (review usage)
- Set hard cap at your monthly limit

**OpenAI (platform.openai.com/settings/organization/billing/limits):**
- Set monthly budget
- Enable email alerts at 50%, 75%, 90%

---

## Red Flags: You're Burning Money

**High Opus usage (>20% of calls):** Review each Opus call. Could Sonnet handle it?

**$5+/day on file operations:** You're using the wrong model. Set Haiku for file tasks.

**Redundant research:** Same topics researched multiple times. Implement the caching strategy above.

**Context bloat:** After 10 tool calls, you're passing 100k+ tokens of context. Add to SOUL.md: "Summarize findings every 3-5 tool calls."

---

## Emergency Cost Reduction

If your bill is out of control:

1. **Right now:** Switch to Haiku-only in your config
2. **Today:** Set a $2/day budget in SOUL.md, review API dashboard for runaway loops
3. **This week:** Audit which tasks cost the most, implement caching, optimize model selection
4. **This month:** Build cost awareness into your agent's behavior permanently

---

## Cost Per Common Task

| Task | Haiku | Sonnet | Opus |
|------|-------|--------|------|
| Read 10 files | $0.01 | $0.04 | $0.18 |
| Organize 100 files | $0.05 | $0.18 | $0.85 |
| Write 1,000-word blog post | $0.08 | $0.25 | $1.20 |
| Generate 3,000-word VSL | $0.35 | $0.75 | $3.50 |
| Research 20 sources | $0.40 | $0.90 | $4.20 |
| Generate 500 lines of code | $0.15 | $0.40 | $1.90 |

**Key insight:** Sonnet is only 2-3x more expensive than Haiku for writing tasks but delivers 5-10x better quality. Use Haiku for mechanical work, Sonnet for everything creative.

---

For model-by-model task recommendations, see `model-selection-matrix.md` in this folder.
