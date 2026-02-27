---
name: file-organizer
description: |
  Scans directories for clutter, proposes organization plan WITH cost estimate.
  Gets explicit approval before moving files.
  Includes safeguards to prevent the "$200 Downloads folder" problem.
---

# File Organizer Skill

Organizes files intelligently. Shows you the plan and cost before touching anything.

## Quick Start

1. Tell your agent: `Organize my Downloads folder`
2. Review the proposed plan and cost estimate
3. Approve (full organization or simple rules), and it handles the rest

## When to Use

- Cleaning up Downloads folder
- Organizing project directories
- Sorting photos/screenshots by date or content
- Grouping documents by topic or client
- Archiving old files

## The Problem This Solves

You have 847 files in `~/Downloads/`. You ask an AI agent to organize them.

**Without safeguards**: Agent analyzes every file. You wake up to a $200 API bill.

**With this skill**: Agent scans (cheap), shows plan, estimates cost, waits for your approval. Total: $0.50-3.00.

## Configuration

```json
{
  "skills": {
    "file-organizer": {
      "enabled": true,
      "config": {
        "requireApproval": true,
        "costLimits": {
          "scanMax": 0.50,
          "executionMax": 5.00
        },
        "rules": {
          "archiveOlderThan": 180,
          "detectDuplicates": true,
          "groupByType": true
        },
        "safetyChecks": {
          "noDeleteWithoutBackup": true,
          "quarantineDuplicates": true,
          "maxFilesPerRun": 1000,
          "skipSystemFolders": true
        }
      }
    }
  }
}
```

## How It Works

### Step 1: Scan (Cheap)

Agent reads file metadata only -- names, extensions, sizes, dates. No AI analysis yet.

Cost: $0.05-0.20

### Step 2: Propose Plan

```
ORGANIZATION PLAN: ~/Downloads/
Files: 847 | Size: 12.4 GB | Duplicates: 23

Proposed:
  Archive/     612 files (>6 months old, sorted by year)
  Documents/   67 files (PDFs, spreadsheets, text)
  Images/      120 files (screenshots, photos)
  Videos/      6 files
  Other/       28 files

COST ESTIMATE:
A. Full organization (AI content grouping): $2-3
B. Simple rules only (by extension + date): $0.50
C. Cancel
```

### Step 3: You Decide

Nothing happens until you pick A, B, or C.

### Step 4: Execute + Log

Creates activity log at `~/Downloads/organization-log-{date}.md` showing every file moved.

## Two Strategies

**Simple (cheap)**: Groups by file extension and date. PDFs to Documents/, screenshots to Images/, old files to Archive/. No AI needed. $0.30-0.80.

**Smart (AI-powered)**: Opens files, reads content, groups by topic (e.g., all Acme Corp files together). Smart renaming (IMG_1234.jpg becomes product-screenshot-feb-3.jpg). $1.50-5.00.

## Example Usage

```
You: Organize my Downloads folder

Agent: Scanning 847 files...
       Options:
       A. Full ($2-3)  B. Simple ($0.50)  C. Cancel

You: B

Agent: Done. 847 files organized. 23 duplicates quarantined.
       Log: ~/Downloads/organization-log-2026-02-03.md
```

### Via Command

```bash
openclaw skill file-organizer scan ~/Downloads/
openclaw skill file-organizer scan ~/Downloads/ --dry-run     # Preview only, free
openclaw skill file-organizer scan ~/Documents/ --strategy smart
openclaw skill file-organizer scan ~/Downloads/ --filter images
```

## Safety Features

- **Never deletes files.** Moves only. Duplicates go to `Duplicates/` for your review.
- **Approval required.** Nothing executes without your yes.
- **Cost limits.** Auto-aborts if scan or execution exceeds your configured max.
- **File count limits.** 1000+ files triggers batch mode with separate approval per batch.
- **Skips system folders.** Won't touch `/System/`, `/Applications/`, `.git/`, `.env`.
- **Activity log.** Every run logs what moved where. If something goes wrong, you can undo.

## Tips

- **Start with dry run.** `--dry-run` shows the plan without executing. Free.
- **Simple strategy first.** It covers 90% of use cases at 1/5 the cost.
- **Organize regularly.** Monthly cleanup keeps costs low. Don't let 5000 files pile up.
- **Review duplicates manually.** The skill quarantines them but won't delete. That's your call.
