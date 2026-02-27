# Firewall Configuration for OpenClaw

## The Goal

Lock down your system so nothing is exposed to the internet except what you explicitly allow. If you're using Tailscale (recommended), you don't need to expose ANY ports publicly.

---

## Ubuntu VPS Setup (UFW)

### Step 1: Install UFW

```bash
sudo apt update
sudo apt install ufw
```

### Step 2: Default Deny

```bash
# Deny all incoming by default
sudo ufw default deny incoming

# Allow all outgoing (your agent needs to call APIs)
sudo ufw default allow outgoing
```

### Step 3: Allow SSH (Temporarily)

```bash
# Allow SSH so you don't lock yourself out
sudo ufw allow 22/tcp
```

**Important:** If you're connected via SSH right now, enabling UFW will maintain your current session but new connections must pass through UFW rules.

### Step 4: Enable UFW

```bash
sudo ufw enable
```

Confirm with `y` when prompted.

### Step 5: Verify

```bash
sudo ufw status verbose
```

You should see:
```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
```

### Step 6: Secure SSH with Tailscale

Once you have Tailscale installed (see `tailscale-setup.md`):

```bash
# Remove public SSH access
sudo ufw delete allow 22/tcp

# Verify
sudo ufw status
# SSH should no longer be listed
```

Now SSH only works via Tailscale IP:
```bash
ssh user@100.x.x.x
```

### Step 7: Rate Limit SSH (Optional, for Public SSH)

If you MUST keep SSH public (not recommended), rate-limit it:

```bash
sudo ufw limit 22/tcp
```

This allows only 6 connection attempts per 30 seconds from a single IP. Slows down brute-force attacks.

### Step 8: Verify Nothing Else Is Open

```bash
sudo ufw status numbered
```

You should see ZERO open ports after removing SSH. Your OpenClaw gateway runs on 18789, but it's NOT open to the internet. It's only accessible via Tailscale or localhost.

**Test from another machine (not on your Tailnet):**
```bash
curl http://YOUR_PUBLIC_IP:18789
# Should timeout (correct)
```

**Test via Tailscale:**
```bash
curl http://100.x.x.x:18789
# Should work (correct)
```

---

## Advanced: Fail2Ban (Optional)

If you're keeping SSH exposed publicly (again, not recommended), add fail2ban.

### Install

```bash
sudo apt install fail2ban
```

### Configure

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

Find the `[sshd]` section and ensure:
```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

This bans IPs after 3 failed login attempts for 1 hour.

### Start Fail2Ban

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Check Status

```bash
sudo fail2ban-client status sshd
```

---

## macOS Setup

macOS has a built-in firewall, but it's application-based (not port-based like UFW).

### Enable Firewall

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

### Block All Incoming Connections

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
```

**Warning:** This blocks all incoming connections except those explicitly allowed. You'll need to allow specific apps.

### Allow OpenClaw Gateway (If Needed)

If you want to access your OpenClaw dashboard from other devices on your local network (not over the internet):

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/openclaw/gateway
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblock /path/to/openclaw/gateway
```

**Better approach:** Use Tailscale. Then you don't need to allow anything through macOS firewall.

### Stealth Mode

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

This makes your Mac invisible to port scans. Ping requests are ignored. Your Mac won't respond to ICMP.

### Verify

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
# Should show: Firewall is enabled. (State = 1)
```

---

## iptables (For Advanced Users)

If you prefer iptables over UFW (Ubuntu):

### Flush Existing Rules

```bash
sudo iptables -F
sudo iptables -X
```

### Default Policies

```bash
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
```

### Allow Loopback

```bash
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

### Allow Established Connections

```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

### Allow SSH (Temporarily)

```bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

### Save Rules

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### Remove SSH After Tailscale Setup

```bash
sudo iptables -D INPUT -p tcp --dport 22 -j ACCEPT
sudo netfilter-persistent save
```

---

## Verifying Your Setup Is Locked Down

### From Outside Your Network

Use a tool like Shodan or nmap from a different IP:

```bash
nmap -p 1-65535 YOUR_PUBLIC_IP
```

You should see:
```
All 65535 scanned ports on YOUR_PUBLIC_IP are filtered
```

Or:
```
Not shown: 65535 filtered ports
```

**You should NOT see:**
- Port 18789 open
- Port 22 open (if using Tailscale)
- Any other ports open

### From Your Tailnet

```bash
nmap -p 18789 100.x.x.x
```

You should see:
```
PORT      STATE SERVICE
18789/tcp open  unknown
```

This confirms Tailscale access works but public access doesn't.

---

## Common Mistakes

### Mistake 1: Binding to 0.0.0.0 Without Firewall

```json
{
  "gateway": {
    "host": "0.0.0.0",
    "port": 18789
  }
}
```

**With no firewall:** Your dashboard is now publicly accessible. Anyone can find it via Shodan.

**Fix:** Either bind to 127.0.0.1 (local only) or use 0.0.0.0 with UFW blocking port 18789 publicly.

### Mistake 2: Forgetting to Remove SSH After Tailscale Setup

You set up Tailscale, but port 22 is still open publicly.

**Check:**
```bash
sudo ufw status
```

**If you see 22/tcp ALLOW, remove it:**
```bash
sudo ufw delete allow 22/tcp
```

### Mistake 3: Testing from the Same Network

You test `curl http://YOUR_PUBLIC_IP:18789` from your laptop on the same network. It works. You think it's secure.

**Wrong.** You're testing from inside your network. Test from a VPS or mobile data to verify external access is blocked.

---

## Shodan Check (How Exposed Are You?)

Shodan is a search engine for internet-connected devices. If your OpenClaw shows up there, you're exposed.

### Check Your IP

```bash
# Find your public IP
curl ifconfig.me

# Search Shodan (requires account)
# Go to https://www.shodan.io/
# Search: YOUR_PUBLIC_IP
```

**If you see port 18789 listed:** You're exposed. Fix immediately.

**If you see nothing or only expected services:** You're good.

---

## Emergency: I Think I'm Exposed

### Step 1: Check What's Open

```bash
sudo netstat -tulnp | grep LISTEN
```

Look for:
- `0.0.0.0:18789` or `*:18789` = Bad (exposed to internet)
- `127.0.0.1:18789` = Good (local only)
- `100.x.x.x:18789` = Good (Tailscale only)

### Step 2: Block the Port Immediately

```bash
sudo ufw deny 18789/tcp
```

### Step 3: Reconfigure Gateway

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

Restart gateway:
```bash
pkill -f "openclaw.*gateway"
openclaw gateway start
```

### Step 4: Rotate API Keys

If your gateway was exposed with no authentication:
1. Assume your API keys are compromised
2. Go to Anthropic/OpenAI dashboard
3. Generate new keys
4. Update your OpenClaw config
5. Revoke old keys

### Step 5: Check API Usage Logs

Look for suspicious activity:
- API calls you didn't make
- High token usage during hours you weren't active
- Unusual queries or prompts

If you find evidence of unauthorized access, consider your conversations compromised.

---

## Firewall Checklist

Before considering your setup secure:

- [ ] UFW enabled (Ubuntu) or macOS firewall on
- [ ] Default deny incoming
- [ ] SSH not exposed publicly (or rate-limited if must be public)
- [ ] Tailscale installed and working
- [ ] Port 18789 not open publicly (test from external IP)
- [ ] Gateway bound to 127.0.0.1 or Tailscale IP
- [ ] nmap scan from external IP shows no open ports
- [ ] Shodan search shows no unexpected services

---

## Next Steps

- See `hardening-checklist.md` for complete security setup
- See `tailscale-setup.md` for VPN configuration
- See `Going Deeper/Cost Optimization/full-cost-control-guide.md` to prevent API cost blowouts

Your firewall protects the perimeter. Gateway binding protects the service. Authentication protects access. Use all three layers.
