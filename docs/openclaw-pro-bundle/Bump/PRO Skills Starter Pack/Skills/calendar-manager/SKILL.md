---
name: calendar-manager
description: |
  Manages calendar via Google Calendar API or iCal.
  Creates meeting prep briefs, suggests schedule optimizations, sends reminders.
  Integrates with configured messaging channels.
---

# Calendar Manager Skill

Reads your calendar, prepares you for meetings, optimizes your schedule, and sends contextual reminders.

## Quick Start

1. Connect your calendar: `openclaw skill calendar-manager setup --provider google`
2. Set your daily briefing time in config
3. Wake up to your schedule delivered via Telegram/WhatsApp/Discord

## When to Use

- Morning schedule briefings with focus blocks identified
- Auto-generated meeting prep (attendees, context, suggested agenda)
- Schedule optimization (reduce context switching, protect deep work)
- Contextual reminders (not just "meeting in 15 min" but actual prep notes)

## Configuration

```json
{
  "skills": {
    "calendar-manager": {
      "enabled": true,
      "config": {
        "provider": "google",
        "credentials": "env:GOOGLE_CALENDAR_CREDENTIALS",
        "calendarId": "primary",
        "dailyBriefing": {
          "enabled": true,
          "time": "07:00",
          "channel": "telegram",
          "includeFocusBlocks": true
        },
        "meetingPrep": {
          "enabled": true,
          "autoPrepBefore": 2,
          "searchDirectories": [
            "~/handoff/meetings/",
            "~/handoff/clients/"
          ]
        },
        "reminders": {
          "beforeMeeting": [30, 10],
          "afterMeeting": 15
        },
        "optimization": {
          "minimumFocusBlock": 90,
          "preferredMeetingTimes": ["10:00-12:00", "14:00-16:00"],
          "noMeetingDays": ["Friday afternoon"]
        }
      }
    }
  }
}
```

## How It Works

### Daily Briefing

Every morning at your configured time, your agent sends:

```
Today (Tuesday, Feb 3):

FOCUS BLOCKS
08:00-10:00  Clear (2 hours - deep work)
14:00-16:00  Clear (2 hours)

MEETINGS
10:00  1:1 with Sarah (Zoom) - last met 3 weeks ago
11:00  Client call - Acme Corp - VSL review iteration 3
16:30  Team standup

NOTES
- Tight: Only 15 min between client call and lunch
- Suggestion: Move standup to Thursday for afternoon focus block
```

### Meeting Prep

Auto-generated 2 hours before each meeting:
- Who's attending and when you last met
- Previous meeting notes and open items
- Suggested agenda
- Relevant files to reference

### Schedule Optimization

Weekly suggestions to improve your calendar:
- Batch meetings to create focus blocks
- Flag days with too much context switching
- Protect deep work time

## Example Usage

### Via Chat

```
You: What's on my calendar today?

Agent: 3 meetings, 4 hours of focus time
       Next: 1:1 with Sarah at 10:00
       Want meeting prep for Acme call?
```

### Via Command

```bash
openclaw skill calendar-manager today
openclaw skill calendar-manager week
openclaw skill calendar-manager prep "Client call - Acme Corp"
openclaw skill calendar-manager optimize --week
```

## Tips

- **Use consistent meeting titles.** "Client call - Acme Corp" beats "Call with John" -- better context search.
- **Add notes to calendar events.** The skill includes them in prep briefs.
- **Block focus time on your calendar.** The skill recognizes protected blocks and won't suggest moving them.
- **After meetings, send voice memo or text notes.** The skill saves them for next time's prep.
