# Model Selection Matrix

Quick reference for choosing the right model for each task type.

---

## Quick Decision Table

| Task Type | Recommended Model | Cost (per 1M tokens) | Why |
|-----------|------------------|---------------------|-----|
| **File Operations** | Haiku | $0.80 / $4.00 | Fast, cheap, good enough for reading/writing files |
| **Simple Edits** | Haiku | $0.80 / $4.00 | Find and replace, rename, basic formatting |
| **Quick Answers** | Haiku | $0.80 / $4.00 | Factual queries, status checks, simple questions |
| **Research** | Sonnet 4 | $3.00 / $15.00 | Best quality/cost ratio for analysis |
| **Writing** | Sonnet 4 | $3.00 / $15.00 | Blog posts, reports, emails, copy |
| **Code Generation** | Sonnet 4 | $3.00 / $15.00 | Strong at code, good balance |
| **Debugging** | Sonnet 4 | $3.00 / $15.00 | Can trace logic and identify issues |
| **Complex Reasoning** | Opus 4.5 | $15.00 / $75.00 | Only when you need deep multi-step thinking |
| **Critical Decisions** | Opus 4.5 | $15.00 / $75.00 | High-stakes choices, business strategy |
| **Data Analysis** | Sonnet 4 | $3.00 / $15.00 | Structured analysis, pattern recognition |
| **Email Sequences** | Sonnet 4 | $3.00 / $15.00 | Drafting, personalization, follow-ups |
| **Long-Form Writing** | Sonnet 4 or Opus | $3.00 / $15.00 or $15 / $75 | Sonnet for drafts, Opus for final polish |

---

## Detailed Task Breakdown

### File Operations

**Tasks:**
- Reading files
- Writing files
- Copying, moving, renaming files
- Listing directory contents
- Checking file sizes/permissions
- Simple grep/find operations

**Recommended:** Haiku

**Why:** These tasks require no reasoning. Haiku is 3-4x cheaper than Sonnet and just as fast.

**Example config:**
```json
{
  "model_selection": {
    "file_read": "claude-haiku-3-5-20241022",
    "file_write": "claude-haiku-3-5-20241022",
    "file_list": "claude-haiku-3-5-20241022"
  }
}
```

**Cost comparison (reading 10 files):**
- Haiku: $0.01
- Sonnet: $0.04
- Opus: $0.18

### Simple Edits

**Tasks:**
- Find and replace
- Basic formatting (add line breaks, indent)
- Comment/uncomment code
- Change variable names
- Add/remove boilerplate

**Recommended:** Haiku

**Why:** These are mechanical tasks. Haiku can handle regex and simple transformations.

**When to upgrade to Sonnet:**
- If the edit requires understanding code logic
- If you need to preserve semantic meaning
- If the edit is part of a larger refactor

### Research and Analysis

**Tasks:**
- Web research
- Document analysis
- Competitive research
- Market research
- Synthesizing multiple sources
- Extracting insights

**Recommended:** Sonnet 4

**Why:** Research requires comprehension, pattern recognition, and synthesis. Sonnet excels at this. Haiku will miss nuance. Opus is overkill (and 5x more expensive).

**Cost comparison (analyzing 20 sources):**
- Haiku: $0.40 (but lower quality)
- Sonnet: $0.90 (best value)
- Opus: $4.20 (marginal improvement over Sonnet)

**When to upgrade to Opus:**
- If the research informs a critical business decision
- If you need to catch subtle contradictions across sources
- If Sonnet's analysis feels shallow after review

### Writing (Content, Copy, Reports)

**Tasks:**
- Blog posts
- Reports
- Documentation
- Email sequences
- Social media content
- Ad copy
- Landing page copy

**Recommended:** Sonnet 4

**Why:** Sonnet produces human-like, engaging writing. Haiku's writing feels flat and generic. Opus is marginally better but 5x more expensive.

**Cost comparison (1,000-word blog post):**
- Haiku: $0.08 (but noticeably worse quality)
- Sonnet: $0.25 (publication-ready)
- Opus: $1.20 (slightly better, not worth 5x cost)

**When to upgrade to Opus:**
- High-stakes sales pages (VSLs, landing pages)
- When the writing directly drives revenue
- When you've iterated with Sonnet and need the extra polish

### Code Generation

**Tasks:**
- Writing functions
- Building scripts
- Creating APIs
- Refactoring code
- Adding features
- Writing tests

**Recommended:** Sonnet 4

**Why:** Sonnet is strong at code. It handles multiple languages, understands patterns, generates clean code. Haiku can write simple functions but struggles with multi-file refactors.

**Cost comparison (500 lines of code):**
- Haiku: $0.15 (basic functions only)
- Sonnet: $0.40 (production-quality)
- Opus: $1.90 (marginal improvement)

**When to upgrade to Opus:**
- Complex algorithms requiring deep reasoning
- Security-critical code
- When Sonnet produces buggy output after multiple attempts

### Debugging

**Tasks:**
- Finding bugs
- Tracing logic errors
- Understanding error messages
- Suggesting fixes
- Explaining why code fails

**Recommended:** Sonnet 4

**Why:** Debugging requires understanding code flow, tracing state, and identifying edge cases. Sonnet handles this well. Haiku misses subtle bugs.

**When to upgrade to Opus:**
- Multi-file bugs with complex interactions
- Race conditions and concurrency issues
- When Sonnet can't isolate the root cause

### Complex Reasoning

**Tasks:**
- Multi-variable decision making
- Architectural planning
- System design
- Strategy development
- Evaluating trade-offs with 5+ variables
- Long-chain logical deductions

**Recommended:** Opus 4.5

**Why:** This is what Opus was built for. It can hold more context, reason through more steps, catch edge cases Sonnet misses.

**Cost comparison (complex decision analysis):**
- Sonnet: $0.60 (may miss edge cases)
- Opus: $2.80 (more thorough)

**When to downgrade to Sonnet:**
- If the decision is reversible
- If you're just exploring options (not finalizing)
- If budget is tight and "good enough" works

### Data Analysis

**Tasks:**
- Spreadsheet analysis
- Pattern recognition across datasets
- Categorization and tagging
- Summarizing survey responses
- Extracting insights from transcripts

**Recommended:** Sonnet 4

**Why:** The work is structured. Sonnet can follow rubrics, score consistently, extract patterns. Opus is overkill for most analysis tasks.

**Cost comparison (analyzing 50 records):**
- Sonnet: $1.20
- Opus: $5.50

**When to upgrade to Opus:**
- High-stakes analysis informing major decisions
- Complex datasets with subtle patterns
- When Sonnet's analysis feels shallow

### Long-Form Writing

**Tasks:**
- Sales pages and landing pages
- Video scripts
- Whitepapers and guides
- Newsletter sequences
- Polishing final copy

**Recommended:** Sonnet 4 for drafts, optional Opus for final polish

**Why:** Sonnet produces strong first drafts. Opus adds nuance and polish for high-stakes pieces.

**Workflow:**
1. **Draft:** Sonnet ($0.75 for 3,000 words)
2. **Review:** Human feedback
3. **Refine:** Sonnet ($0.40 for revisions)
4. **Optional final polish:** Opus ($1.80 for refinement)

**Total cost:**
- Sonnet-only: $1.15
- Sonnet + Opus polish: $2.95

**When to use Opus:**
- The writing directly drives revenue
- High-stakes client deliverables
- When you've iterated with Sonnet and need the extra polish

---

## Model Switching: When to Change

### Start with Sonnet, Downgrade to Haiku If:

- The task turns out to be simpler than expected
- You're doing the same operation 50+ times (batch processing)
- Budget is tight and quality is acceptable

### Start with Sonnet, Upgrade to Opus If:

- Sonnet's output feels shallow or misses key insights
- The task has high stakes (revenue impact >$1k)
- You've iterated 3+ times with Sonnet and it's not quite right

### Never Use Opus For:

- File operations
- Simple queries
- Routine tasks
- Anything you'd normally use Haiku for

---

## Configuring Model Selection in OpenClaw

### Option 1: Manual Selection (Per Task)

In your prompt to OpenClaw:
```
[Use Haiku] Organize the files in my inbox folder
[Use Sonnet] Write a blog post about OpenClaw security
[Use Opus] Analyze the trade-offs for these 3 architecture options
```

### Option 2: Automatic Selection (Config File)

In `~/.openclaw/openclaw.json`:

```json
{
  "models": {
    "default": "claude-sonnet-4-20250514",
    "fast": "claude-haiku-3-5-20241022",
    "powerful": "claude-opus-4-5-20251101"
  },
  "auto_model_selection": true,
  "model_selection_rules": {
    "file_read": "fast",
    "file_write": "fast",
    "file_edit": "fast",
    "file_list": "fast",
    "simple_query": "fast",
    "research": "default",
    "writing": "default",
    "code_generation": "default",
    "debugging": "default",
    "complex_reasoning": "powerful",
    "decision_making": "powerful"
  }
}
```

### Option 3: Budget-Based Switching

In your `SOUL.md`:

```markdown
## Model Selection Based on Budget

If daily spending < $2:
- Use Sonnet as default
- Use Opus when justified

If daily spending $2-4:
- Use Sonnet for critical tasks only
- Use Haiku for everything else
- No Opus without approval

If daily spending > $4:
- Switch to Haiku-only mode
- Notify owner
- Wait for budget reset or approval
```

---

## Cost Impact of Model Selection

### Scenario 1: Everything on Opus (Don't Do This)

```
Tasks per day: 30
Model: Opus for everything
Cost per task: $2.00 average
Daily: $60
Monthly: $1,800

🚨 This is insane for most users
```

### Scenario 2: Everything on Sonnet

```
Tasks per day: 30
Model: Sonnet for everything
Cost per task: $0.20 average
Daily: $6
Monthly: $180

⚠️ Better, but still wasteful on file ops
```

### Scenario 3: Optimized (Do This)

```
Tasks per day: 30
Breakdown:
- 10 file ops on Haiku: $0.30
- 18 tasks on Sonnet: $3.60
- 2 complex tasks on Opus: $4.00
Daily: $7.90
Monthly: $237

Still high, but getting better
```

### Scenario 4: Aggressive Optimization (Best)

```
Tasks per day: 30
Breakdown:
- 15 file ops on Haiku: $0.45
- 14 tasks on Sonnet: $2.80
- 1 complex task on Opus: $2.00
Daily: $5.25
Monthly: $157.50

But with caching and batch processing:
Reduce redundant research: -$30/month
Batch file operations: -$20/month
Smarter Opus usage: -$40/month

Optimized monthly: $67.50

✅ This is the sweet spot
```

---

## Quick Reference: Cost Per Common Task

| Task | Haiku | Sonnet | Opus | Recommended |
|------|-------|--------|------|-------------|
| Read 1 file | $0.001 | $0.003 | $0.015 | Haiku |
| Write 1 file | $0.001 | $0.003 | $0.015 | Haiku |
| Organize 20 files | $0.02 | $0.06 | $0.30 | Haiku |
| Blog post (1k words) | $0.08 | $0.25 | $1.20 | Sonnet |
| Research (10 sources) | $0.20 | $0.45 | $2.10 | Sonnet |
| Code function (50 lines) | $0.03 | $0.08 | $0.38 | Sonnet |
| VSL (3k words) | $0.35 | $0.75 | $3.50 | Sonnet + Opus polish |
| Offer audit | $0.60 | $1.20 | $5.50 | Sonnet |
| Complex decision | $0.50 | $1.00 | $2.80 | Opus |

---

## Summary

**Default to Sonnet** for most tasks. It's the best balance of quality and cost.

**Use Haiku** for file operations and simple queries. It's 3-4x cheaper and just as fast.

**Reserve Opus** for <5% of tasks where deep reasoning justifies the 5x cost premium.

**Review your usage weekly** and adjust based on actual spending patterns.
