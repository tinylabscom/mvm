# Discord Channel Setup

Control your OpenClaw agent from Discord. Best for teams, thread support, and rich formatting.

**Time to complete: 15 minutes.**

## Prerequisites

- OpenClaw installed and running
- Discord account
- A server where you have admin permissions (or create one)

## Quick Start (Recommended)

If you want guided setup instead of manual configuration:

```bash
openclaw onboard
```

This walks you through channel setup step-by-step, including Discord. It handles token configuration, security settings, and verification automatically.

If you prefer manual setup, continue below.

## Setup

### Step 1: Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application"
3. Name it (e.g., "OpenClaw Agent")
4. Click "Create"

### Step 2: Create Bot and Get Token

1. In your application, go to "Bot" tab (left sidebar)
2. Click "Add Bot" > "Yes, do it!"
3. Click "Reset Token" > "Copy"
4. Save this token securely

### Step 3: Enable Required Intents

Still in the "Bot" tab, scroll to "Privileged Gateway Intents" and enable:

- **Message Content Intent** (required -- bot can't read messages without this)
- **Server Members Intent**
- **Presence Intent**

Click "Save Changes."

### Step 4: Store Token and Configure

```bash
echo 'export DISCORD_BOT_TOKEN="YOUR_TOKEN_HERE"' >> ~/.bashrc
source ~/.bashrc
```

Edit `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "token": "env:DISCORD_BOT_TOKEN",
      "dmPolicy": "allowlist",
      "allowFrom": ["your-discord-username"],
      "commandPrefix": "!",
      "serverSettings": {
        "allowedServers": ["YOUR_SERVER_ID"],
        "allowedChannels": ["YOUR_CHANNEL_ID"]
      }
    }
  }
}
```

### Step 5: Get Server and Channel IDs

1. In Discord: User Settings > Advanced > toggle "Developer Mode" ON
2. Right-click your server name > "Copy Server ID"
3. Right-click the channel you want > "Copy Channel ID"
4. Paste into config above

### Step 6: Invite Bot to Server

1. Developer Portal > your app > "OAuth2" > "URL Generator"
2. Under Scopes: check `bot` and `applications.commands`
3. Under Bot Permissions: check Send Messages, Embed Links, Attach Files, Read Message History, Add Reactions, Use Slash Commands
4. Copy the generated URL, open in browser
5. Select your server, click "Authorize"

### Step 7: Start and Test

```bash
openclaw gateway restart
openclaw logs | grep discord
# Should show: [INFO] Discord channel initialized
```

In your Discord channel, send `!help`. Bot should respond with available commands.

## Configuration Options

### DM vs Server

**DMs only:**
```json
{ "dmPolicy": "allowlist", "serverSettings": { "allowServers": false } }
```

**Server only:**
```json
{ "dmPolicy": "closed", "serverSettings": { "allowedServers": ["id"], "allowedChannels": ["id"] } }
```

**Both (default):** Set both `allowFrom` and `serverSettings`.

### Role-Based Access

Restrict to users with a specific Discord role:

```json
{
  "serverSettings": { "requireRole": "OpenClaw User" }
}
```

Create the role in Server Settings > Roles, assign to trusted users.

### Thread Support

Keep long conversations in threads instead of cluttering the channel:

```json
{
  "threads": {
    "enabled": true,
    "autoCreate": true,
    "namingPattern": "{skill} - {user} - {date}"
  }
}
```

### Response Formatting

```json
{
  "responseSettings": {
    "useEmbeds": true,
    "streamResponses": true,
    "maxMessageLength": 2000,
    "splitLongMessages": true,
    "reactions": { "working": "hourglass", "complete": "white_check_mark", "error": "x" }
  }
}
```

## Security

1. **Private server only.** Don't add your bot to public servers.
2. **Use allowlists.** Even in your server, restrict who can use the bot.
3. **Channel restrictions.** Bot responds only in `#bot-commands`, not everywhere.
4. **Never commit bot token.** Environment variables or `.env` only.
5. **Rotate if compromised.** Developer Portal > Bot > Reset Token.
6. **Monitor logs.** `openclaw logs --filter discord --last 24h`

**Real threat data:** Security researchers found 42,000+ exposed OpenClaw instances on the internet, with 93% having no authentication. Always use Tailscale or a VPN to access your gateway. Never expose port 18789 directly to the internet.

## Troubleshooting

**Bot appears offline:**
1. Is OpenClaw running? `openclaw status`
2. Is token valid? Check logs for auth errors.
3. Is "Message Content Intent" enabled in Developer Portal?

**Bot online but doesn't respond:**
1. Message Content Intent is the #1 cause. Enable it in Developer Portal > Bot > Privileged Gateway Intents.
2. Check bot has permissions in the channel (View Channel, Send Messages).
3. Is the channel ID in `allowedChannels`?
4. Are you using the right prefix? (`!help` not `/help` if prefix is `!`)

**"Missing Access" error:**
- Server Settings > Roles > find bot role > enable required permissions
- Or: right-click channel > Edit > Permissions > add bot role

**Slash commands don't appear:**
- Re-invite with `applications.commands` scope
- Run: `openclaw channel discord register-commands`
- May take up to 1 hour. Restart Discord to force refresh.

## Cost

**Free.** Discord Bot API has no costs. You only pay for agent processing.
