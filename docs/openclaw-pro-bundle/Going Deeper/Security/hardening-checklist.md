# Security Hardening Checklist

> **When to do this:** After you've used your agent for a few days and are comfortable with the basics. This is not required for Day 1 setup.

## The Context You Need to Know

In early 2025, security researcher Jamieson O'Reilly found 780+ OpenClaw servers exposed on Shodan. The Register called it a "security dumpster fire."

**The problem:** Default OpenClaw configurations bind the gateway to `0.0.0.0`, exposing your entire system to the internet. Your API keys, your conversations, your file system—all accessible to anyone who finds your IP.

**This checklist prevents you from being on that list.**

---

## 5-Step Hardening Process

### Step 1: Bind Gateway to Loopback Only

**What this does:** Prevents external access. Your gateway only accepts connections from your local machine.

**Configuration:**

Edit the `gateway` section in `~/.openclaw/openclaw.json`:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789
  }
}
```

**Not** `0.0.0.0`. **Not** your public IP. Only loopback/`127.0.0.1`.

**Verify:**
```bash
curl http://127.0.0.1:18789/health
# Should work

curl http://YOUR_PUBLIC_IP:18789/health
# Should timeout (correct behavior)
```

### Step 2: Set Up Gateway Authentication Token

**What this does:** Requires authentication even for local connections. Defense in depth.

**Generate token:**
```bash
openssl rand -hex 32
```

**Add to the `gateway.auth` section in `~/.openclaw/openclaw.json`:**
```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "YOUR_GENERATED_TOKEN_HERE"
    }
  }
}
```

**Restart gateway:**
```bash
pkill -f "openclaw.*gateway"
openclaw gateway start
```

### Step 3: Install Tailscale VPN for Remote Access

**What this does:** Lets you access your OpenClaw dashboard remotely without exposing ports.

You no longer need port forwarding. You no longer need to expose 18789 to the internet. Tailscale creates a secure mesh network between your devices.

**See:** `tailscale-setup.md` for complete installation guide.

**Quick version:**
```bash
# macOS
brew install --cask tailscale

# Ubuntu
curl -fsSL https://tailscale.com/install.sh | sh
```

Connect to your Tailnet, then access your dashboard via your Tailscale IP:
```
http://100.x.x.x:18789
```

### Step 4: Set File Permissions

**What this does:** Prevents other users on your system from reading your config files (which contain API keys).

```bash
# Lock down the entire OpenClaw directory
chmod 700 ~/.openclaw

# Extra protection for config and identity files
chmod 600 ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/workspace/SOUL.md
chmod 600 ~/.openclaw/workspace/USER.md

# Verify
ls -la ~/.openclaw/
# Should show -rw------- (read/write for you only)
```

### Step 5: Enable Sensitive Data Redaction in Logs

**What this does:** Prevents API keys and tokens from appearing in plain text in your logs.

**Add to `~/.openclaw/openclaw.json`:**
```json
{
  "logging": {
    "redact_sensitive": true,
    "redact_patterns": [
      "sk-[a-zA-Z0-9-]+",
      "Bearer [a-zA-Z0-9-_\\.]+",
      "api[_-]?key[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9-_]+",
      "token[\"']?\\s*[:=]\\s*[\"']?[a-zA-Z0-9-_\\.]+"
    ]
  }
}
```

**Test:**
```bash
tail -f ~/.openclaw/logs/gateway.log
# Make a request with your API key
# Verify the key shows as [REDACTED] in logs
```

---

## Verification Checklist

Before considering your setup hardened:

- [ ] Gateway bound to 127.0.0.1 (not 0.0.0.0)
- [ ] Authentication token set and working
- [ ] Tailscale installed and connected
- [ ] Can access dashboard via Tailscale IP from another device
- [ ] Cannot access dashboard from public IP
- [ ] File permissions set to 600/700
- [ ] Log redaction working
- [ ] No ports exposed in firewall (see `firewall-rules.md`)

---

## What If I Already Exposed My Setup?

1. **Rotate all API keys immediately.** Anthropic dashboard, OpenAI dashboard, any provider you used.
2. **Check your API usage logs** for suspicious activity.
3. **Apply all hardening steps above.**
4. **Consider your conversations compromised.** Anything you discussed with your agent may have been read.

This is not theoretical. Exposed OpenClaw instances have been exploited in the wild.

---

## Additional Resources

- `tailscale-setup.md` - Complete VPN setup guide
- `firewall-rules.md` - UFW configuration for Ubuntu VPS
- `Going Deeper/Cost Optimization/full-cost-control-guide.md` - Prevent runaway API spending

(PRO Skills Pack includes a security-audit skill that runs this checklist monthly and alerts you to configuration drift.)
