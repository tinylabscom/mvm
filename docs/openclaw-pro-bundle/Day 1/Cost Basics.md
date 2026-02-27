# Cost Basics

What your agent costs to run and how to control it.

---

## How Pricing Works

Your agent uses AI models through an API. You pay per task based on which model runs it.

| Model | Cost per typical task | Best for |
|-------|----------------------|----------|
| **Haiku** | ~$0.02 | File operations, quick answers, simple edits |
| **Sonnet** | ~$0.20 | Writing, research, code, most daily work |
| **Opus** | ~$2.00 | Complex reasoning, high-stakes decisions |

Most people use Sonnet for 90% of tasks. Normal monthly cost: **$15-75** depending on usage.

---

## 3 Settings to Configure Now

### 1. Set a daily spending limit

Go to console.anthropic.com > Settings > Billing.
Set a monthly limit you're comfortable with. Start with $25 if you're unsure.

### 2. Set up email alerts

Same page. Turn on alerts at 50% and 80% of your limit.
You'll get an email before you hit your cap.

### 3. Pick your default model

In your agent config, Sonnet is the default. This is the right choice for most people. Only switch to Opus when Sonnet's output isn't good enough for a specific task.

---

## Where to Check Spending

- **Anthropic dashboard:** console.anthropic.com/settings/billing
- **OpenClaw stats:** `openclaw stats --last-24h` (shows model usage and token counts)

---

## Rules of Thumb

- Haiku for anything mechanical (moving files, formatting, quick lookups)
- Sonnet for anything creative or analytical (writing, research, debugging)
- Opus only when the stakes justify it (<5% of tasks)

For detailed cost optimization strategies and model selection, see `Going Deeper/Cost Optimization/`.
