# Telegram Channel Setup

Control your OpenClaw agent from Telegram. Easiest channel to set up, best API, completely free.

**Time to complete: 10 minutes.**

## Prerequisites

- OpenClaw installed and running
- Telegram account
- 10 minutes

## Quick Start (Recommended)

If you want guided setup instead of manual configuration:

```bash
openclaw onboard
```

This walks you through channel setup step-by-step, including Telegram. It handles token configuration, security settings, and verification automatically.

If you prefer manual setup, continue below.

## Setup

### Step 1: Create Your Bot

1. Open Telegram, search for `@BotFather`
2. Send `/newbot`
3. Choose a display name (e.g., "My OpenClaw Agent")
4. Choose a username ending in "bot" (e.g., `myopenclaw_bot`)
5. BotFather gives you a token: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`
6. Copy this token

### Step 2: Store the Token

```bash
# Add to your shell profile
echo 'export TELEGRAM_BOT_TOKEN="YOUR_TOKEN_HERE"' >> ~/.bashrc
source ~/.bashrc
```

Or add to `~/.openclaw/.env`:

```
TELEGRAM_BOT_TOKEN=YOUR_TOKEN_HERE
```

### Step 3: Configure OpenClaw

Edit `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "telegram": {
      "enabled": true,
      "token": "env:TELEGRAM_BOT_TOKEN",
      "dmPolicy": "allowlist",
      "allowFrom": ["your-telegram-username"]
    }
  }
}
```

Replace `your-telegram-username` with your actual Telegram username (no @ symbol).

### Step 4: Restart and Test

```bash
openclaw gateway restart
```

Check it connected:

```bash
openclaw logs | grep telegram
# Should show: [INFO] Telegram channel initialized
```

In Telegram, find your bot by username and send `/start`. You should get a welcome message.

### Step 5: Verify Security

From a different Telegram account, try messaging your bot. It should respond with "Access denied." If it doesn't, double-check your `dmPolicy` and `allowFrom` settings, then restart.

## Configuration Options

### Allow Multiple Users

```json
{
  "allowFrom": ["your-username", "partner-username", "assistant-username"]
}
```

### Notification Settings

```json
{
  "notifications": {
    "enabled": true,
    "sendOn": ["error", "completion", "approval-required"],
    "quiet": { "enabled": true, "start": "22:00", "end": "07:00" }
  }
}
```

### Group Chat Integration

1. Add your bot to a Telegram group
2. Send a message mentioning the bot to get the group chat ID from logs
3. Configure:

```json
{
  "groupChats": {
    "enabled": true,
    "allowedGroups": ["-1001234567890"],
    "requireMention": true
  }
}
```

### Custom Commands

Map Telegram commands to skills:

```json
{
  "customCommands": {
    "/daily": "openclaw skill calendar-manager today",
    "/write": "openclaw skill content-writer run --format",
    "/research": "openclaw skill web-researcher run --query"
  }
}
```

## Security

1. **Always use allowlist.** Never set `dmPolicy` to `"open"` without additional auth.
2. **Never commit your bot token to git.** Use environment variables or `.env` files.
3. **Rotate token if compromised.** BotFather > `/mybots` > select bot > API Token > Revoke.
4. **Enable Telegram 2FA.** Settings > Privacy and Security > Two-Step Verification.
5. **Monitor access logs.** `openclaw logs --filter telegram --last 24h`

**Real threat data:** Security researchers found 42,000+ exposed OpenClaw instances on the internet, with 93% having no authentication. Always use Tailscale or a VPN to access your gateway. Never expose port 18789 directly to the internet.

## Troubleshooting

**Bot doesn't respond:**
1. Is OpenClaw running? `openclaw status`
2. Is token valid? `curl https://api.telegram.org/botYOUR_TOKEN/getMe`
3. Is your username in the allowlist (without @)?
4. Did you restart after config changes?

**"Access Denied" for your own account:**
- Check spelling of username in `allowFrom` (case-sensitive, no @ symbol)
- Your Telegram username is in Settings > @username, not your display name

**Bot stops responding after server restart:**
- Check env var loaded: `echo $TELEGRAM_BOT_TOKEN`
- If empty: `source ~/.bashrc`

## Integration Examples

**Daily calendar briefing at 7 AM:**

```json
{
  "skills": {
    "calendar-manager": {
      "config": {
        "dailyBriefing": { "enabled": true, "time": "07:00", "channel": "telegram" }
      }
    }
  }
}
```

**Approval requests via Telegram:**

When a skill needs your OK (e.g., file organizer wants to move 847 files), it sends a message. Reply with your choice.

**Cost: $0.** Telegram Bot API is free. You only pay for agent processing.
