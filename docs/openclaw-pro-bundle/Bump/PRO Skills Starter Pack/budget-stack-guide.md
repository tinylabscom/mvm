# The $0-14/Month OpenClaw Stack

Run a production AI agent for less than a Netflix subscription. Or run it for free.

## Three Tiers

### Tier 1: $0/Month (Free)

| Component | Provider | Cost |
|-----------|----------|------|
| **Server** | Oracle Cloud Free Tier | $0 |
| **Models** | DeepSeek R1/V3 + free APIs | $0 |
| **Networking** | Tailscale Free | $0 |
| **Total** | | **$0/month** |

Oracle Cloud Free Tier gives you 4 ARM CPUs, 24GB RAM, and 200GB storage. Permanently free, not a trial. That's more power than most paid VPS plans.

DeepSeek R1 and V3 are 671-billion parameter models, MIT licensed, free for commercial use. Quality rivals GPT-4 on most tasks. Run via API through providers like Kilo Gateway, or self-host on your Oracle instance.

Additional free model options:
- **MiniMax** via Puter.js (free API, developer pays nothing)
- **Z.AI GLM 4.5 Air** via Kilo Gateway (free tier)
- **MoonshotAI Kimi K2** via Kilo Gateway (free tier)
- **Kimi K2.5** via Novita (free tier)
- **Groq** free inference (fast, limited)
- **Google Gemini** via AI Studio (free tier, generous limits)

Good enough for: content drafts, research, file organization, email drafting, calendar management. Covers 80%+ of daily tasks.

### Tier 2: $4/Month (Better Stability)

| Component | Provider | Cost |
|-----------|----------|------|
| **Server** | Hetzner CX21 | ~$4 |
| **Models** | DeepSeek/free APIs | $0 |
| **Networking** | Tailscale Free | $0 |
| **Total** | | **~$4/month** |

Hetzner CX21: 2 vCPU, 4GB RAM, 40GB SSD, 20TB traffic. Located in Germany, Finland, or USA. Hourly billing so you can test before committing.

Why pay $4 when Oracle is free? Hetzner gives you faster provisioning, simpler setup, better support, and you're not dependent on Oracle's free tier conditions. Peace of mind for a production agent.

Contabo offers one-click OpenClaw deployment at ~€4.50/month (~$4.75 USD). Create account, click deploy, done. Zero manual setup. Alternative to Hetzner if you value automatic provisioning.

### Tier 3: $14/Month (Best Quality)

| Component | Provider | Cost |
|-----------|----------|------|
| **Server** | Hetzner CX21 | ~$4 |
| **Models** | MiniMax Coding Plan | $10 |
| **Networking** | Tailscale Free | $0 |
| **Total** | | **~$14/month** |

MiniMax Coding Plan: 300M tokens/month for $10. That's roughly 15M input + 5M output tokens. Enough for heavy daily use.

Add Claude Haiku as fallback for critical tasks (pay-per-use, typically $5-20/month depending on usage).

Hybrid strategy: MiniMax for 90% of tasks, Claude for the 10% that needs top-tier reasoning.

## Free API Credits (Hidden Gold)

Sites like getaiperks.com aggregate free API credits from dozens of providers. At time of writing, you can collect $3,000-$176,000 in free credits across:
- Anthropic (free tier)
- Google AI Studio (free Gemini access)
- Mistral (free tier)
- Groq (free inference)
- Together.ai (free credits)
- And 20+ more

These change frequently. Check monthly.

## Prompt Caching: The Biggest Hidden Savings

Real numbers from X/Twitter:
- Users reporting $200/day → $40/day after enabling caching alone
- Anthropic's official documentation confirms 90% savings on cached input tokens
- If you're sending the same SOUL.md on every request, you're paying 10x too much

Enable it:

```bash
openclaw config set enablePromptCaching true
```

The cache has a 5-minute TTL, refreshed on each use. As long as you're actively using your agent, cached prompts stay hot.

## The 97% Cost Reduction Case Study

Real documented case: $1,200/month cloud AI automation stack replaced with self-hosted OpenClaw setup. New cost: $36/month. That's a 97% reduction.

Before: $1,200/month (GPT-4 for everything, no caching, bloated context)
After: $36/month (model routing + prompt caching + context trimming + free models for simple tasks)

The three levers:
- **Model selection** (60% savings) -- use DeepSeek/MiniMax for routine tasks, Claude only when necessary
- **Prompt caching** (additional 20%) -- enable caching for context files that repeat across requests
- **Context management** (additional 10%) -- trim unnecessary files, use focused queries

The key: most AI tasks don't need GPT-4 or Claude Opus. They need a decent model running on hardware you control.

## Setup Walkthrough (Tier 2: Hetzner)

### Step 1: Provision Server

1. Sign up at hetzner.com
2. Create server: Ubuntu 24.04, CX21, add your SSH key
3. Note the server IP

### Step 2: Server Setup

```bash
ssh root@YOUR_SERVER_IP
apt update && apt upgrade -y
adduser openclaw
usermod -aG sudo openclaw
su - openclaw
```

### Step 3: Install Dependencies

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs git build-essential
```

### Step 4: Install OpenClaw

```bash
curl -fsSL https://openclaw.ai/install.sh | bash
openclaw --version
```

### Step 5: Configure

Your `~/.openclaw/openclaw.json` is created during onboarding (`Setup.command` runs this for you). Edit it to add: model provider (MiniMax primary, Claude Haiku fallback), channel config (Telegram recommended), and skills. See `Going Deeper/Channels/` for channel setup guides.

Set environment variables:

```bash
echo 'export MINIMAX_API_KEY="your-key"' >> ~/.bashrc
echo 'export ANTHROPIC_API_KEY="your-key"' >> ~/.bashrc
echo 'export TELEGRAM_BOT_TOKEN="your-token"' >> ~/.bashrc
source ~/.bashrc
```

### Step 6: Install Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Follow the auth link. Note your Tailscale IP (100.x.x.x).

Install Tailscale on your local machine too. Now you can reach your VPS securely from anywhere without port forwarding.

### Step 7: Make It Persistent

Create a systemd service so OpenClaw starts on boot:

```bash
# Create service file at /etc/systemd/system/openclaw.service
# Set User=openclaw, ExecStart=/usr/bin/openclaw start, Restart=always
# EnvironmentFile=/home/openclaw/.openclaw/.env
sudo systemctl enable openclaw && sudo systemctl start openclaw
```

### Step 8: Connect a Channel

See `Going Deeper/Channels/` for Telegram or Discord setup.

## Oracle Cloud Free Tier Setup (Tier 1)

1. Create free account at cloud.oracle.com (select closest region)
2. Compute > Instances > Create Instance
3. Image: Ubuntu 24.04 | Shape: VM.Standard.A1.Flex (ARM) | 4 OCPUs, 24 GB RAM, 200 GB boot volume
4. Add SSH key, create instance
5. Follow Steps 2-8 from Hetzner walkthrough above (use `arm64` packages where needed)

## Model Quality Comparison

| Model | Quality | Cost | Best For |
|-------|---------|------|----------|
| Claude Opus 4 | 10/10 | $$$$ | Client-facing content, complex reasoning |
| Claude Haiku 4 | 8/10 | $$ | Critical tasks on a budget |
| MiniMax Coding | 7/10 | $ | Routine tasks, first drafts |
| DeepSeek R1/V3 | 7/10 | Free | Everything when budget is zero |
| Ollama (local 8B) | 6/10 | Free | Experimentation, simple tasks |

**Strategy:** Use the cheapest model that gets the job done. Upgrade per-task, not globally.

## Cost Projection

| Usage Level | Tier 1 | Tier 2 | Tier 3 |
|-------------|--------|--------|--------|
| Light (50 queries/day) | $0 | $4 | $14 |
| Moderate (100/day + some Claude) | $0-5 | $9-15 | $20-35 |
| Heavy (300+/day, regular Claude) | $10-30 | $15-40 | $50-150 |

All three tiers are cheaper than hiring an assistant ($2,000+/month) or using Zapier Premium ($29-99/month with task limits).

## When to Upgrade

**VPS too slow?** `htop` shows RAM > 90% consistently. Upgrade to CX31 (8GB RAM, ~$8/month).

**Model quality not enough?** Add Claude Haiku as fallback for critical tasks. Budget $10-20/month extra.

**Need team access?** Upgrade VPS to CX41 (4 vCPU, 16GB, ~$16/month). Supports 5-10 users.

## Troubleshooting

**VPS unresponsive:** Check `htop`. If maxed, reduce concurrent skills in config or upgrade.

**API quota exceeded:** Check `openclaw usage --this-month`. Reduce non-critical usage or add pay-as-you-go funds.

**Tailscale drops:** `sudo systemctl restart tailscaled && tailscale status`

**OpenClaw won't start:** `journalctl -u openclaw -n 50` for logs. Common: missing env vars, port conflict, invalid JSON.
