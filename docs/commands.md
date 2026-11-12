# Using stack-guard

[← back to the README](../README.md)

Open Claude Code in your project folder (or the folder that holds your projects) and type:

```
/stack-guard
```

That is the whole thing. (If another plugin also has a `/stack-guard`, use `/stack-guard:stack-guard`.) Optional:

- `/stack-guard ~/Projects/my-bot` checks one folder
- `/stack-guard --audit-only` reports and changes none of your code or packages (it only writes its report into a `.stack-guard/` folder, which ignores itself in git; your own `.gitignore` is never edited)
- `/stack-guard --yes` reports, then applies the safe package updates without asking again. Node/Python upgrades, service restarts, deploys and commits still get their own question.

You can also just say: *"check my stack for security problems"*.

**Two more commands:**

- `/stack-guard:inventory` runs the script to write `STACK-INVENTORY.md`: a plain list of every project, where it's deployed, its runtime, package counts and MCP servers, with anything it couldn't place flagged at the top. Keep it (it describes your setup, so review it before committing it anywhere public). When the next security alert lands, you'll know in seconds whether it touches you.
- `/stack-guard:watch` sets up a **daily routine on your own computer** (launchd on Mac, cron on Linux, Task Scheduler on Windows). It shows you the exact entry and asks before adding it. Each morning the script checks everything on the list, a **news scout agent** reads the last 14 days of security news for your versions, and an **explainer agent** writes what's new in plain words. You get **only what changed since yesterday**: a desktop notification, a report in `.stack-guard/reports/`, and optionally a Discord or Slack webhook. On Mac and Linux, a check missed because the computer was off or asleep runs at the next start, login or wake (on Linux within the hour; the cron entry starts every hour and stops at once unless a check is due). On Windows, a check missed while the computer was off is not caught up yet. `/stack-guard:watch --off` removes it.

## In Codex

Start a new Codex conversation, then type `$stack-guard:run-stack-guard audit this folder`, or just ask: *"run stack-guard on this folder"* (add *"audit only"* to change none of your code or packages). Codex has no slash commands for plugins, so the `run-stack-guard` skill is the entry point; it does the same audit, news check and safe fixes.
