# Tailscale VPN Setup for OpenClaw

## What Tailscale Does

Tailscale creates a secure mesh VPN between your devices. No port forwarding. No exposed SSH. No public IP addresses in your config files.

**What this means for OpenClaw:**
- Access your dashboard from your phone while traveling
- SSH into your VPS without exposing port 22 to the internet
- Sync your handoff folder between machines using rsync
- Run multiple OpenClaw instances (Mac Mini + VPS) on the same private network

**The magic:** Tailscale IPs are stable. Your Mac Mini is always `100.101.102.103`. Your VPS is always `100.104.105.106`. You can hardcode these in your configs.

---

## Installation

### macOS

```bash
brew install --cask tailscale
```

Launch Tailscale from Applications, or:
```bash
open /Applications/Tailscale.app
```

### Ubuntu VPS

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

### iOS/Android

Download from App Store or Google Play. Sign in with the same account you'll use on desktop.

---

## Connecting to Your Tailnet

### First Connection

```bash
# Start Tailscale and authenticate
sudo tailscale up
```

This opens a browser window for authentication. Sign in with:
- Google
- Microsoft
- GitHub
- Or create a Tailscale account

**You now have a Tailscale IP.** Find it with:
```bash
tailscale ip -4
# Example output: 100.101.102.103
```

### Verify Connection

From any device on your Tailnet:
```bash
ping 100.101.102.103
# Should respond
```

---

## Accessing Your OpenClaw Dashboard Remotely

### Step 1: Find Your Tailscale IP

On the machine running OpenClaw gateway:
```bash
tailscale ip -4
```

Let's say it returns `100.101.102.103`.

### Step 2: Access from Another Device

From your laptop, phone, or any device on your Tailnet:
```
http://100.101.102.103:18789
```

**That's it.** No port forwarding. No firewall rules. No nginx reverse proxy.

### Step 3: Bookmark It

Add to your browser bookmarks or home screen:
- **Mac Mini OpenClaw:** `http://100.101.102.103:18789`
- **VPS OpenClaw:** `http://100.104.105.106:18789`

---

## SSH Access via Tailscale

### The Old Way (Don't Do This)

```bash
# Expose SSH to the internet
ufw allow 22

# SSH from anywhere
ssh user@your.public.ip.address
# Now you're in Shodan and getting brute-force attempts
```

### The Tailscale Way (Do This)

```bash
# On VPS: Close public SSH
ufw delete allow 22

# SSH via Tailscale IP
ssh user@100.104.105.106
# Only accessible to devices on your Tailnet
```

**No brute-force attempts.** No fail2ban needed. No port scanning. Your SSH port isn't visible to the internet.

---

## Syncing Handoff Folder Between Machines

### The Use Case

You have:
- A Mac Mini running OpenClaw 24/7
- A MacBook Pro for work on the go

You want:
- Tasks you drop in `~/handoff/inbox/` on your MacBook to sync to your Mac Mini
- Completed work in `~/handoff/ready/` on your Mac Mini to sync to your MacBook

### The Setup

**On Mac Mini (Tailscale IP: 100.101.102.103):**
```bash
# Enable SSH (only accessible via Tailscale)
sudo systemsetup -setremotelogin on
```

**On MacBook Pro:**
```bash
# Sync inbox TO Mac Mini
rsync -avz ~/handoff/inbox/ user@100.101.102.103:~/handoff/inbox/

# Sync ready FROM Mac Mini
rsync -avz user@100.101.102.103:~/handoff/ready/ ~/handoff/ready/
```

### Automate with a Script

Create `~/scripts/sync-handoff.sh`:
```bash
#!/bin/bash
REMOTE="user@100.101.102.103"

# Push inbox
rsync -avz --delete ~/handoff/inbox/ $REMOTE:~/handoff/inbox/

# Pull ready
rsync -avz --delete $REMOTE:~/handoff/ready/ ~/handoff/ready/

# Pull archive (optional)
rsync -avz --delete $REMOTE:~/handoff/archive/ ~/handoff/archive/

echo "Handoff sync complete"
```

Make executable:
```bash
chmod +x ~/scripts/sync-handoff.sh
```

Run before you leave for the day:
```bash
~/scripts/sync-handoff.sh
```

---

## Multi-Instance Setup

### The Scenario

You run two OpenClaw instances:
1. **Mac Mini:** Always on, handles overnight tasks
2. **Ubuntu VPS:** Cheaper API costs, handles batch work

Both accessible via Tailscale.

### Configuration

**Mac Mini OpenClaw:**
```json
{
  "gateway": {
    "host": "100.101.102.103",
    "port": 18789
  }
}
```

**VPS OpenClaw:**
```json
{
  "gateway": {
    "host": "100.104.105.106",
    "port": 18789
  }
}
```

**Access both from one browser:**
- Mac Mini: `http://100.101.102.103:18789`
- VPS: `http://100.104.105.106:18789`

Bookmark both. Switch based on which agent you want to use.

---

## Mobile Access

### iOS/Android App

Install Tailscale app. Connect to your Tailnet. Open Safari/Chrome:
```
http://100.101.102.103:18789
```

You can now:
- Check your agent's work while traveling
- Read completed drafts from `~/handoff/ready/`
- Drop new tasks in `~/handoff/inbox/` via web interface
- Monitor costs and activity

### Add to Home Screen

iOS: Safari > Share > Add to Home Screen
Android: Chrome > Menu > Add to Home Screen

Icon appears next to your other apps. Tap it, instant access to your OpenClaw dashboard.

---

## Security Notes

### Is Tailscale Secure?

Yes. Tailscale uses WireGuard (modern, audited VPN protocol) with your own cryptographic keys. Tailscale's coordination servers never see your traffic.

**Your traffic:** Encrypted end-to-end between your devices.
**Tailscale sees:** Only connection metadata (which devices want to talk to each other).

### Can Others on My Tailnet Access My OpenClaw?

Only if you share your Tailnet. By default, your Tailnet is private to you.

If you share your Tailnet with teammates:
- Use gateway authentication (see `hardening-checklist.md`)
- Or use Tailscale ACLs to restrict access by device

### What If I Lose My Laptop?

Remotely disable the device:
1. Go to https://login.tailscale.com/admin/machines
2. Find the device
3. Click "Disable"

The device can no longer access your Tailnet.

---

## Troubleshooting

### "Cannot connect to 100.x.x.x:18789"

**Check Tailscale is running:**
```bash
tailscale status
```

**Check gateway is running on the host:**
```bash
# On the machine running OpenClaw
ps aux | grep "openclaw.*gateway"
```

**Check gateway is bound correctly:**
```bash
# Should show 127.0.0.1:18789 OR 0.0.0.0:18789
# NOT 127.0.0.1:18789 if you want remote access
sudo lsof -i :18789
```

**If gateway is bound to 127.0.0.1 only:**
You can't access it remotely. Either:
1. Bind to `0.0.0.0` (but only with Tailscale, never exposed publicly)
2. Or use SSH tunnel: `ssh -L 18789:localhost:18789 user@100.101.102.103`

### "Tailscale IPs keep changing"

They shouldn't. Tailscale IPs are stable. If yours are changing:
- Check you're not accidentally creating new devices
- Verify you're logged into the same Tailnet on all devices

### "rsync is slow"

Tailscale uses direct connections when possible, but sometimes routes through DERP relays.

**Force direct connection:**
```bash
tailscale ping 100.101.102.103
```

This helps Tailscale find the fastest path.

---

## Next Steps

- [ ] Install Tailscale on all your devices
- [ ] Find Tailscale IPs with `tailscale ip -4`
- [ ] Bookmark your OpenClaw dashboard URL
- [ ] Test remote access from another device
- [ ] Set up handoff folder sync script
- [ ] Add to mobile home screen
- [ ] Close public SSH port if using VPS (see `firewall-rules.md`)

You now have secure remote access without exposing a single port to the internet.
