# OpenClaw Setup Kit

This kit is built for complete beginners.

Goal: get OpenClaw running quickly on your own machine, with your own API key, without sharing private keys with anyone.

## Before You Start

- You need an Anthropic API key from `https://console.anthropic.com/settings/keys`
- Your key stays on your machine/server. It is not sent to SkillStack.
- Expected time:
  - Mac: 5-10 minutes
  - VPS: 10-20 minutes

## Option A: Mac Setup (recommended if you are non-technical)

1. Open this folder.
2. Double-click `Setup.command`.
3. If macOS warns about security, right-click `Setup.command` > **Open**.
4. Follow prompts.
5. When setup finishes, your dashboard opens in browser.

## Optional Advanced Path: Linux VPS Setup

This path is not recommended for complete beginners.
If this is your first OpenClaw setup, use Mac first and get one successful run before moving to VPS.

1. Upload this folder to your VPS and SSH in.
2. `cd` into this folder.
3. Run:
   ```bash
   bash Setup-VPS.sh
   ```
4. Follow prompts.
5. At the end, the script prints one SSH tunnel command.
6. Run that command from your local computer, then open `http://127.0.0.1:18789`.

## What the setup script does

- Installs OpenClaw (and Node.js if needed) using the official OpenClaw installer
- Runs onboarding with safe defaults (no advanced wizard decisions)
- Creates `SOUL.md`, `USER.md`, and `MEMORY.md`
- Starts the OpenClaw gateway

## Included files

- `Setup.command` - main setup wizard (Mac + Linux)
- `Setup-VPS.sh` - Linux/VPS entrypoint
- `Day 1/` - first prompts + cost basics
- `Going Deeper/` - security, cost, channels, workflows
- `Bump/` - bonus packs

## If something goes wrong

1. Re-run the setup script (`Setup.command` or `Setup-VPS.sh`).
2. Run diagnostics from `Bump/OpenClaw Rescue Kit/02-diagnostic.sh`.
3. Check official docs: `https://docs.openclaw.ai`.
